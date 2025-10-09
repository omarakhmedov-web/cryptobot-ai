import os
import json
import logging
import requests
from flask import Flask, request, abort, jsonify
from dotenv import load_dotenv
import structlog

from common import classify_input, chain_from_hint, build_scan_link, getenv_bool
from dex_client import fetch_market
from chain_client import fetch_onchain_factors
from webintel import analyze_website
from risk_engine import Factors, compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp
from buttons import keyboard_main
from limits import can_scan, register_scan, try_activate_judge_pass, is_judge_active
from state import store_bundle, load_bundle

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN","")
WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET","")
DEFAULT_LANG = os.getenv("DEFAULT_LANG","en")

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL","")
DEBUG = getenv_bool("DEBUG", False)

logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"))
log = structlog.get_logger()

app = Flask(__name__)

def tg_api(method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        r = requests.post(url, json=payload, timeout=8)
        if r.status_code == 200:
            return r.json()
        return {"ok": False, "status": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_message(chat_id: int, text: str, reply_markup: dict | None = None, parse_mode: str | None = None) -> dict:
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return tg_api("sendMessage", payload)

def answer_callback_query(cb_id: str, text: str, show_alert: bool = True) -> dict:
    return tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": text, "show_alert": show_alert})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "version": "mvp-plus-1.0"})

@app.post(f"/webhook/{WEBHOOK_SECRET}")
def webhook():
    upd = request.get_json(force=True, silent=True) or {}
    if "message" in upd:
        return handle_message(upd["message"])
    if "callback_query" in upd:
        return handle_callback(upd["callback_query"])
    return jsonify({"ok": True})

def _build_all(verdict, market, webintel, factors, links, lang):
    # single consistent bundle used across all views
    quick = render_quick(verdict, market, links, lang)
    details = render_details(verdict, market, webintel, lang)
    why = render_why(verdict, lang)
    whypp = render_whypp(verdict, factors.__dict__, lang)
    lp = render_lp(None, lang)  # enrich later
    return {"quick": quick, "details": details, "why": why, "whypp": whypp, "lp": lp}

def process_input(text: str, chat_id: int, lang: str = "en") -> dict:
    kind, value = classify_input(text)
    market = fetch_market(value)
    chain = market.get("chain") or chain_from_hint(value)
    token_addr = market.get("tokenAddress")
    links = {
        "site": market.get("links",{}).get("site"),
        "dex": market.get("links",{}).get("dex"),
        "scan": build_scan_link(chain, token_addr) if token_addr else None,
    }
    onchain = fetch_onchain_factors(token_addr, chain)
    webintel = analyze_website(links.get("site"))

    factors = Factors(
        honeypot=bool(onchain.get("honeypot")),
        blacklist=bool(onchain.get("blacklist")),
        pausable=bool(onchain.get("pausable")),
        upgradeable=bool(onchain.get("upgradeable")),
        mint=bool(onchain.get("mint")),
        maxTx=onchain.get("maxTx"),
        maxWallet=onchain.get("maxWallet"),
        taxes=onchain.get("taxes") or {"buy":0.0,"sell":0.0},
        liq_usd=market.get("liq"),
        fdv=market.get("fdv"),
        vol24h=market.get("vol24h"),
        delta24h=market.get("delta24h"),
        whois_created=webintel.get("whois",{}).get("created"),
        ssl_ok=webintel.get("ssl",{}).get("ok"),
        wayback_first=webintel.get("wayback",{}).get("first"),
    )
    verdict = compute_verdict(factors)
    bundle = _build_all(verdict, market, webintel, factors, links, lang)
    return {"bundle": bundle, "links": links, "market": market, "verdict": verdict}

def handle_message(msg: dict):
    chat = msg.get("chat",{})
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()
    lang = DEFAULT_LANG

    # commands
    if text.startswith("/start"):
        send_message(chat_id, "Welcome to Metridex.\nSend a token address, TX hash, or a link — I'll run a QuickScan.\nCommands: /quickscan, /upgrade, /pass <code>, /limits")
        return jsonify({"ok": True})

    if text.startswith("/limits"):
        active = "yes" if is_judge_active(chat_id) else "no"
        send_message(chat_id, f"Free daily limit: 2\nJudge-Pass active: {active}")
        return jsonify({"ok": True})

    if text.startswith("/pass"):
        parts = text.split(maxsplit=1)
        code = parts[1].strip() if len(parts) > 1 else ""
        ok, status = try_activate_judge_pass(chat_id, code)
        send_message(chat_id, f"Judge-Pass: {status}")
        return jsonify({"ok": True})

    if text.startswith("/quickscan"):
        send_message(chat_id, "Send a token address, TX hash, or URL.")
        return jsonify({"ok": True})

    # limits check
    allowed, mode = can_scan(chat_id)
    if not allowed:
        send_message(chat_id, "Free tier limit reached. Tap Upgrade.")
        return jsonify({"ok": True})

    try:
        res = process_input(text, chat_id, lang)
        bundle = res["bundle"]
        links = res["links"]
        # First send the QuickScan, capturing message_id
        resp = send_message(chat_id, bundle["quick"])
        msg_id = None
        if resp.get("ok") and resp.get("result"):
            msg_id = resp["result"]["message_id"]
        # store bundle per (chat_id,msg_id) for stable popups
        if msg_id is not None:
            store_bundle(chat_id, msg_id, bundle)
        km = keyboard_main("v1", msg_id or 0, chat_id, links)
        if msg_id:
            # edit to attach keyboard for stability (2-step avoids some bots mixing)
            tg_api("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": msg_id, "reply_markup": km})
        else:
            send_message(chat_id, "(control) — failed to capture message_id; re-sending with keyboard.", reply_markup=km)

        register_scan(chat_id)
        return jsonify({"ok": True})
    except Exception as e:
        log.error("process_error", error=str(e))
        send_message(chat_id, f"Error: {e}")
        return jsonify({"ok": True})

def handle_callback(cb: dict):
    data = cb.get("data","")
    cb_id = cb.get("id")
    msg = cb.get("message",{})
    chat_id = msg.get("chat",{}).get("id")
    msg_id = msg.get("message_id")

    try:
        version, action, mid_s, cid_s = data.split(":", 3)
        if version != "v1":
            answer_callback_query(cb_id, "Outdated action.", True); return jsonify({"ok": True})
        try:
            mid = int(mid_s); cid = int(cid_s)
        except ValueError:
            answer_callback_query(cb_id, "Bad callback data.", True); return jsonify({"ok": True})
        if cid != chat_id or mid != msg_id:
            answer_callback_query(cb_id, "Stale/foreign message.", False); return jsonify({"ok": True})
    except Exception:
        answer_callback_query(cb_id, "Malformed callback.", True); return jsonify({"ok": True})

    bundle = load_bundle(chat_id, msg_id)
    if not bundle:
        answer_callback_query(cb_id, "This scan has expired. Resubmit the token/URL for fresh data.", True)
        return jsonify({"ok": True})

    try:
        if action == "DETAILS":
            answer_callback_query(cb_id, "More details sent.", False)
            send_message(chat_id, bundle.get("details","(no details)"))
            return jsonify({"ok": True})
        elif action == "WHY":
            answer_callback_query(cb_id, bundle.get("why","Why? n/a"), True); return jsonify({"ok": True})
        elif action == "WHYPP":
            answer_callback_query(cb_id, bundle.get("whypp","Why++ n/a"), True); return jsonify({"ok": True})
        elif action == "LP":
            answer_callback_query(cb_id, bundle.get("lp","LP n/a"), True); return jsonify({"ok": True})
        elif action == "UPGRADE":
            answer_callback_query(cb_id, "Upgrade: Visit metridex.com/pricing", True); return jsonify({"ok": True})
        else:
            answer_callback_query(cb_id, "Unknown action.", True); return jsonify({"ok": True})
    except Exception as e:
        answer_callback_query(cb_id, f"Handler error: {e}", True)
        return jsonify({"ok": True})
