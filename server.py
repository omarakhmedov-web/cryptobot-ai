import os, json, re, time, traceback, requests
from flask import Flask, request, jsonify

from limits import can_scan, register_scan, try_activate_judge_pass
from state import store_bundle, load_bundle
from buttons import build_keyboard  # classic UI
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp
from chain_client import fetch_onchain_factors

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"
DEBUG_TG = os.getenv("DEBUG_TG", "0") == "1"

# Pricing/Help URLs (override via ENV if нужно)
HELP_URL = os.getenv("HELP_URL", "https://metridex.com/help")
DEEP_REPORT_URL = os.getenv("DEEP_REPORT_URL", "https://metridex.com/upgrade/deep-report")
DAY_PASS_URL = os.getenv("DAY_PASS_URL", "https://metridex.com/upgrade/day-pass")
PRO_URL = os.getenv("PRO_URL", "https://metridex.com/upgrade/pro")
TEAMS_URL = os.getenv("TEAMS_URL", "https://metridex.com/upgrade/teams")

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

# --- MarkdownV2 escape ---
_MD2_SPECIALS = r'_*[]()~`>#+-=|{}.!'
_MD2_PATTERN = re.compile('[' + re.escape(_MD2_SPECIALS) + ']')
def mdv2_escape(text: str) -> str:
    if text is None: return ""
    return _MD2_PATTERN.sub(lambda m: '\\\\' + m.group(0), str(text))

def tg(method, payload=None, files=None, timeout=12):
    payload = payload or {}
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        try: j = r.json()
        except Exception: j = {"ok": False, "status_code": r.status_code, "text": r.text}
        if DEBUG_TG and not j.get("ok", False):
            print("TG API ERR:", method, r.status_code, r.text[:300])
        return j
    except Exception as e:
        if DEBUG_TG: print("TG EXC:", method, e)
        return {"ok": False, "error": str(e)}

def send_message(chat_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    res = tg("sendMessage", data)
    if not res.get("ok"):
        data2 = {"chat_id": chat_id, "text": str(text)}
        if reply_markup: data2["reply_markup"] = json.dumps(reply_markup)
        res = tg("sendMessage", data2)
    return res

def answer_callback_query(cb_id, text, show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

def send_document(chat_id: int, filename: str, content_bytes: bytes, caption: str | None = None, content_type: str = "text/html"):
    files = { "document": (filename, content_bytes, content_type) }
    payload = {"chat_id": chat_id}
    if caption: payload["caption"] = caption
    return tg("sendDocument", payload, files=files)

# --- Extra keyboards (Upgrade / How it works?) ---
def build_upgrade_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [
                {"text": "🔍 Deep report — $3", "url": DEEP_REPORT_URL},
                {"text": "⏱ Day Pass — $9", "url": DAY_PASS_URL},
            ],
            [
                {"text": "⚙️ Pro — $29", "url": PRO_URL},
                {"text": "👥 Teams — from $99", "url": TEAMS_URL},
            ],
            [
                {"text": "ℹ️ How it works?", "url": HELP_URL}
            ]
        ]
    }

def build_info_keyboard() -> dict:
    return {"inline_keyboard": [[{"text": "ℹ️ How it works?", "url": HELP_URL}]]}

# --- Callback parsing ---
def parse_cb(data: str):
    m = re.match(r"^v1:(\\w+):(\\-?\\d+):(\\-?\\d+)$", data or "")
    if not m: return None
    return m.group(1), int(m.group(2)), int(m.group(3))

# --- On-chain formatter (lite) ---
def format_onchain(addr: str, chain: str, factors: dict) -> str:
    taxes = factors.get("taxes") or {}
    def pct(x):
        try: return f"{float(x):.1f}%"
        except Exception: return "—"
    return (\
        "*On-chain*\\n"
        f"Contract code: present\\n"
        f"Token: {addr or '—'} on {chain}\\n"
        f"Honeypot: {'YES' if factors.get('honeypot') else 'no'} | Blacklist: {'YES' if factors.get('blacklist') else 'no'}\\n"
        f"Pausable: {'YES' if factors.get('pausable') else 'no'} | Upgradeable: {'YES' if factors.get('upgradeable') else 'no'}\\n"
        f"Mint: {'YES' if factors.get('mint') else 'no'} | Taxes: buy {pct(taxes.get('buy'))}, sell {pct(taxes.get('sell'))}"
    )

# --- Webhook ---
@app.post(f"/webhook/{BOT_WEBHOOK_SECRET}")
def webhook():
    try:
        upd = request.get_json(force=True, silent=True) or {}
        if "message" in upd: return on_message(upd["message"])
        if "edited_message" in upd: return on_message(upd["edited_message"])
        if "callback_query" in upd: return on_callback(upd["callback_query"])
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True})

# --- Handlers ---
def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if text.lower().startswith("/start"):
        welcome = ("*Welcome to Metridex*\\n"
                   "Send a token address, TX hash, or a link — I\\'ll run a QuickScan.\\n\\n"
                   "*Commands:* /quickscan, /upgrade, /limits\\n"
                   f"Help: {HELP_URL}")
        send_message(chat_id, welcome, reply_markup=build_info_keyboard())
        return jsonify({"ok": True})

    if text.lower().startswith("/upgrade"):
        msg_txt = ("**Metridex Pro** — full QuickScan access\\n"
                   "• Pro $29/mo — fast lane, Deep reports, export\\n"
                   "• Teams $99/mo — for teams/channels\\n"
                   "• Day‑Pass $9 — 24h of Pro\\n"
                   "• Deep Report $3 — one detailed report\\n\\n"
                   "Choose your access below. How it works: " + HELP_URL)
        send_message(chat_id, msg_txt, reply_markup=build_upgrade_keyboard())
        return jsonify({"ok": True})

    if text.upper().startswith("PASS "):
        code = text.split(" ",1)[1].strip()
        ok, msg_txt = try_activate_judge_pass(chat_id, code)
        send_message(chat_id, msg_txt)
        return jsonify({"ok": True})

    # scanning flow
    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted\\. Use /upgrade or enter your Judge Pass\\.")
        return jsonify({"ok": True})

    token = text
    market = fetch_market(token)
    verdict = compute_verdict(market)
    links = (market or {}).get("links") or {}

    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    quick = re.sub(r"\\[.*?\\]\\(.*?\\)", "", quick).strip()  # drop inline links to keep MarkdownV2 safe

    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = render_why(verdict, DEFAULT_LANG)
    whypp = render_whypp(verdict, {}, DEFAULT_LANG)
    lp = render_lp({}, DEFAULT_LANG)

    bundle = {
        "verdict": {"level": getattr(verdict, "level", None), "score": getattr(verdict, "score", None)},
        "reasons": list(getattr(verdict, "reasons", []) or []),
        "market": {
            "pairSymbol": market.get("pairSymbol"), "chain": market.get("chain"),
            "price": market.get("price"), "fdv": market.get("fdv"), "mc": market.get("mc"),
            "liq": market.get("liq"), "vol24h": market.get("vol24h"),
            "priceChanges": market.get("priceChanges") or {},
            "tokenAddress": market.get("tokenAddress"), "pairAddress": market.get("pairAddress")
        },
        "links": {"dex": links.get("dex"), "scan": links.get("scan"), "site": links.get("site")},
        "details": details, "why": why, "whypp": whypp, "lp": lp
    }

    sent = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, None, links))
    msg_id = sent.get("result", {}).get("message_id") if sent.get("ok") else None
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
    return jsonify({"ok": True})

def on_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat",{}).get("id")
    msg_id = msg.get("message_id")

    m = parse_cb(data)
    if not m:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})
    action, _, _ = m

    bundle = load_bundle(chat_id, msg_id) or {}

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details","(no details)"))

    elif action == "WHY":
        answer_callback_query(cb_id, bundle.get("why","Why? n/a"), True)

    elif action == "WHYPP":
        text = bundle.get("whypp","Why++ n/a")
        if len(text) <= 190: answer_callback_query(cb_id, text, True)
        else:
            answer_callback_query(cb_id, "Sent extended rationale.", False)
            send_message(chat_id, text)

    elif action == "LP":
        text = bundle.get("lp","LP n/a")
        if len(text) <= 190: answer_callback_query(cb_id, text, True)
        else:
            answer_callback_query(cb_id, "LP lock info sent.", False)
            send_message(chat_id, text)

    elif action == "REPORT":
        answer_callback_query(cb_id, "Report sent.", False)
        html = ("<!doctype html><html><body><pre>" + json.dumps(bundle, ensure_ascii=False, indent=2) + "</pre></body></html>").encode("utf-8")
        send_document(chat_id, f"Metridex_Report_{int(time.time())}.html", html, caption="Metridex QuickScan report")

    elif action == "ONCHAIN":
        mkt = bundle.get("market") or {}
        addr = mkt.get("tokenAddress")
        chain = mkt.get("chain","ethereum")
        try:
            f = fetch_onchain_factors(addr, chain)
            txt = format_onchain(addr, chain, f)
        except Exception:
            txt = "On-chain: temporary unavailable"
        send_message(chat_id, txt)

    elif action == "COPY_CA":
        addr = (bundle.get("market") or {}).get("tokenAddress") or "—"
        send_message(chat_id, f"`{addr}`\\n(hold to copy)")

    elif action == "DELTA_M5":
        ch = (bundle.get("market") or {}).get("priceChanges") or {}
        answer_callback_query(cb_id, f"Δ5m: {ch.get('m5','—')}", True)

    elif action == "DELTA_1H":
        ch = (bundle.get("market") or {}).get("priceChanges") or {}
        answer_callback_query(cb_id, f"Δ1h: {ch.get('h1','—')}", True)

    elif action == "DELTA_6H":
        ch = (bundle.get("market") or {}).get("priceChanges") or {}
        answer_callback_query(cb_id, f"Δ6h: {ch.get('h6','—')}", True)

    elif action == "DELTA_24H":
        ch = (bundle.get("market") or {}).get("priceChanges") or {}
        answer_callback_query(cb_id, f"Δ24h: {ch.get('h24','—')}", True)

    elif action == "UPGRADE":
        answer_callback_query(cb_id, "Upgrade options below.", False)
        send_message(chat_id, "**Metridex Pro — upgrade**", reply_markup=build_upgrade_keyboard())

    else:
        answer_callback_query(cb_id, "Unknown action.", True)

    return jsonify({"ok": True})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})
