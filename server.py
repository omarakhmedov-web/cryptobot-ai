import os, json, requests
from flask import Flask, request, jsonify

from limits import can_scan, register_scan, try_activate_judge_pass, is_judge_active
from state import store_bundle, load_bundle
from buttons import build_keyboard
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en")




# === OMEGA FIXES BLOCK START (METRIDEX-OMEGA) ================================
# Provides: stable button order, EN-only sanitize, webhook hardening.
import re, json, time, sys, traceback

class OMEGA:
    BUTTONS_ORDER = [
        "More details",
        "Why?",
        "Why++",
        "LP lock",
        "Open in DEX",
        "Open in Scan",
        "Upgrade",
    ]
    _ALIASES = {
        "more": "More details", "details": "More details",
        "why": "Why?", "why?": "Why?",
        "why++": "Why++",
        "lp": "LP lock", "lp lock": "LP lock",
        "open in dex": "Open in DEX", "open dex": "Open in DEX",
        "open in scan": "Open in Scan", "open scan": "Open in Scan",
        "upgrade": "Upgrade",
    }
    @staticmethod
    def _normalize_label(text: str) -> str:
        if not text: return ""
        t = re.sub(r"\s+", " ", str(text)).strip().lower()
        return OMEGA._ALIASES.get(t, t.title() if t in OMEGA.BUTTONS_ORDER else t)

    @staticmethod
    def enforce_button_order(markup):
        if not isinstance(markup, dict): return markup
        ik = markup.get("inline_keyboard")
        if not isinstance(ik, list): return markup
        # Flatten
        flat = []
        for row in ik:
            if isinstance(row, (list, tuple)):
                for btn in row:
                    if isinstance(btn, dict):
                        flat.append(btn)
        buckets = {k: [] for k in OMEGA.BUTTONS_ORDER}
        for btn in flat:
            text = btn.get("text") or btn.get("label") or ""
            cb = btn.get("callback_data") or btn.get("url") or ""
            key = OMEGA._normalize_label(text) or OMEGA._normalize_label(cb)
            key = re.sub(r"[^\w\s\+\?]", "", key).strip()
            if key.lower() == "lp": key = "LP lock"
            if key.lower() == "why": key = "Why?"
            if key in buckets: buckets[key].append(btn)
        ordered = []; row = []
        for name in OMEGA.BUTTONS_ORDER:
            for btn in buckets.get(name, []):
                row.append(btn)
                if len(row) == 2:
                    ordered.append(row); row = []
        if row: ordered.append(row)
        if ordered:
            markup["inline_keyboard"] = ordered
        return markup

    _RU_SNIPPETS = {
        "Почему?": "Why?",
        "Почему++": "Why++",
        "Заблокировать LP": "LP lock",
        "Подробнее": "More details",
        "Открыть в DEX": "Open in DEX",
        "Открыть в Scan": "Open in Scan",
        "Обновить": "Upgrade",
    }
    @staticmethod
    def force_english(text: str) -> str:
        if not text: return text
        s = str(text)
        for ru, en in OMEGA._RU_SNIPPETS.items():
            s = s.replace(ru, en)
        s = re.sub(r"[\u0400-\u04FF]+", "", s)  # strip Cyrillic
        s = re.sub(r"[ \t]{2,}", " ", s).strip()
        return s

    @staticmethod
    def safe_endpoint(name="endpoint"):
        def deco(fn):
            def wrapper(*args, **kwargs):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    tb = traceback.format_exc()
                    sys.stderr.write(f"[OMEGA][{name}] ERROR: {e}\n{tb}\n")
                    payload = {"ok": True, "status": "degraded", "endpoint": name}
                    try:
                        if "flask" in sys.modules:
                            from flask import jsonify
                            return jsonify(payload), 200
                    except Exception:
                        pass
                    import json as _json
                    return _json.dumps(payload), 200, {"Content-Type": "application/json"}
            return wrapper
        return deco
# === OMEGA FIXES BLOCK END ====================================================


app = Flask(__name__)

def _tg_api(method: str, payload: dict):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_message(chat_id: int, text: str, reply_markup=None, parse_mode: str | None = None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup: payload["reply_markup"] = reply_markup
    if parse_mode: payload["parse_mode"] = parse_mode
    return _tg_api("sendMessage", payload)

def answer_callback_query(cb_id: str, text: str, alert: bool = False):
    return _tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": text, "show_alert": alert})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "version": "superbot-1.0.1"})

@OMEGA.safe_endpoint("webhook")
@app.post(f"/webhook/{BOT_WEBHOOK_SECRET}")
def webhook():
    upd = request.get_json(force=True, silent=True) or {}
    if "message" in upd: return handle_message(upd["message"])
    if "callback_query" in upd: return handle_callback(upd["callback_query"])
    return jsonify({"ok": True})

def handle_message(msg: dict):
    chat_id = msg.get("chat",{}).get("id"); text = (msg.get("text") or "").strip()
    if not chat_id: return jsonify({"ok": True})

    if text.startswith("/start"):
        send_message(chat_id, "Send a token address / txhash / URL for a quick scan.")
        return jsonify({"ok": True})
    if text.startswith("/limits"):
        free = os.getenv("FREE_DAILY_LIMIT", "2")
        send_message(chat_id, f"Free daily limit: {free}\nJudge-pass active: {'yes' if is_judge_active(chat_id) else 'no'}")
        return jsonify({"ok": True})
    if text.startswith("/pass"):
        parts = text.split(maxsplit=1); code = parts[1].strip() if len(parts)>1 else ""
        ok, msgp = try_activate_judge_pass(chat_id, code)
        send_message(chat_id, msgp or ("Activated" if ok else "Invalid code"))
        return jsonify({"ok": True})

    if not can_scan(chat_id):
        send_message(chat_id, "Free limit reached. Tap Upgrade.")
        return jsonify({"ok": True})

    token = text
    market = fetch_market(token)
    # FIX: compute_verdict expects a single argument (market)
    verdict = compute_verdict(market)
    links = market.get("links") or {}

    quick = render_quick(verdict, market, links, DEFAULT_LANG)
    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = render_why(verdict, DEFAULT_LANG)
    whypp = render_whypp(verdict, {}, DEFAULT_LANG)
    lp = render_lp({}, DEFAULT_LANG)
    # Enforce EN-only texts
    quick = OMEGA.force_english(quick)
    details = OMEGA.force_english(details)
    why = OMEGA.force_english(why)
    whypp = OMEGA.force_english(whypp)
    lp = OMEGA.force_english(lp)

    resp = send_message(chat_id, quick, parse_mode="Markdown")
    msg_id = None
    if resp.get("ok") and resp.get("result"): msg_id = resp["result"]["message_id"]

    try:
        kb = build_keyboard(chat_id, msg_id, links)
        # Enforce stable button order
        try:
            kb = OMEGA.enforce_button_order(kb)
        except Exception:
            pass
        _ = _tg_api("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": msg_id, "reply_markup": kb})
    except Exception:
        pass

    bundle = {"quick": quick, "details": details, "why": why, "whypp": whypp, "lp": lp}
    if msg_id is not None: store_bundle(chat_id, msg_id, bundle)

    register_scan(chat_id)
    return jsonify({"ok": True})

def handle_callback(cb: dict):
    data = cb.get("data",""); cb_id = cb.get("id")
    msg = cb.get("message",{}); chat_id = msg.get("chat",{}).get("id"); msg_id = msg.get("message_id")

    try:
        version, action, mid_s, cid_s = data.split(":", 3)
        if version != "v1": answer_callback_query(cb_id, "Outdated action.", True); return jsonify({"ok": True})
        try: mid = int(mid_s); cid = int(cid_s)
        except ValueError: answer_callback_query(cb_id, "Bad callback data.", True); return jsonify({"ok": True})
        if cid != chat_id or mid != msg_id: answer_callback_query(cb_id, "Stale/foreign message.", False); return jsonify({"ok": True})
    except Exception:
        answer_callback_query(cb_id, "Malformed callback.", True); return jsonify({"ok": True})

    bundle = load_bundle(chat_id, msg_id)
    if not bundle:
        answer_callback_query(cb_id, "This scan has expired. Resubmit the token/URL for fresh data.", True)
        return jsonify({"ok": True})

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details","(no details)"), parse_mode="Markdown")
    elif action == "WHY":
        answer_callback_query(cb_id, bundle.get("why","Why? n/a"), True)
    elif action == "WHYPP":
        answer_callback_query(cb_id, bundle.get("whypp","Why++ n/a"), True)
    elif action == "LP":
        answer_callback_query(cb_id, bundle.get("lp","LP n/a"), True)
    elif action == "UPGRADE":
        answer_callback_query(cb_id, "Upgrade: Visit metridex.com/pricing", True)
    else:
        answer_callback_query(cb_id, "Unknown action.", True)
    return jsonify({"ok": True})
