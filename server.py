import os, json, traceback, requests, re
from flask import Flask, request, jsonify

# External modules (kept)
from limits import can_scan, register_scan, try_activate_judge_pass, is_judge_active
from state import store_bundle, load_bundle
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

# ===== Helpers =====
MDV2_SPECIALS = r'[_*[\]()~`>#+\-=|{}.!]'
def mdv2_escape(text: str) -> str:
    if text is None: return ""
    # escape special characters; do not escape inside URLs (Telegram accepts raw URLs)
    def esc(m):
        return "\\" + m.group(0)
    return re.sub(MDV2_SPECIALS, esc, str(text))

def tg(method, payload, files=None, timeout=10):
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        try: return r.json()
        except Exception: return {"ok": False, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_message(chat_id, text, reply_markup=None):
    text = mdv2_escape(str(text))
    data = {"chat_id": chat_id, "text": text, "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

def edit_message_text(chat_id, message_id, text, reply_markup=None):
    text = mdv2_escape(str(text))
    data = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("editMessageText", data)

def answer_callback_query(cb_id, text, show_alert=False):
    # answerCallbackQuery does not support parse_mode; keep plain text
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

# Build keyboard (order + Report)
def build_keyboard(chat_id, msg_id, links):
    def cb(a): return f"v1:{a}:{msg_id or 0}:{chat_id or 0}"
    dex = (links or {}).get("dex")
    scan = (links or {}).get("scan")
    rows = [
        [{"text": "More details", "callback_data": cb("DETAILS")},
         {"text": "Why?", "callback_data": cb("WHY")}],
        [{"text": "Why++", "callback_data": cb("WHYPP")},
         {"text": "LP lock", "callback_data": cb("LP")}],
        [{"text": "Report", "callback_data": cb("REPORT")}],
    ]
    nav = []
    if dex: nav.append({"text": "Open in DEX", "url": dex})
    if scan: nav.append({"text": "Open in Scan", "url": scan})
    if nav: rows.append(nav)
    rows.append([{"text": "Upgrade", "callback_data": cb("UPGRADE")}])
    return {"inline_keyboard": rows}

# ===== Routes =====
@app.post(f"/webhook/{BOT_WEBHOOK_SECRET}")
def webhook():
    try:
        upd = request.get_json(force=True, silent=True) or {}
        if "message" in upd: return on_message(upd["message"])
        if "callback_query" in upd: return on_callback(upd["callback_query"])
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True, "status": "degraded"})

# ===== Handlers =====
def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if text.startswith("/start") or text.lower() in ("/help", "help"):
        hello = (
            "*Welcome to Metridex*\\n"
            "Send a token address, TX hash, or a link — I\\'ll run a QuickScan.\\n\\n"
            "*Commands:* /quickscan, /upgrade, /limits\\n"
            "Pricing: metridex\\.com/pricing  •  Help: metridex\\.com/help"
        )
        send_message(chat_id, hello)
        return jsonify({"ok": True})

    if text.upper().startswith("PASS "):
        code = text.split(" ",1)[1].strip()
        ok, msg_txt = try_activate_judge_pass(chat_id, code)
        send_message(chat_id, msg_txt)
        return jsonify({"ok": True})

    token = text
    if not can_scan(chat_id):
        send_message(chat_id, "Free scans exhausted\\. Use /upgrade or enter your Judge Pass\\.")
        return jsonify({"ok": True})

    market = fetch_market(token)
    verdict = compute_verdict(market)
    links = market.get("links") or {}

    # Clean quick text (no inline links to avoid markdown noise)
    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    quick = re.sub(r"\\[.*?\\]\\(.*?\\)", "", quick)  # drop any inline links from renderer
    quick = re.sub(r"\\s*\\|\\s*Site:.*$", "", quick)  # and trailing site block
    quick = re.sub(r"\\s{2,}", " ", quick).strip()

    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = render_why(verdict, DEFAULT_LANG)
    whypp = render_whypp(verdict, {}, DEFAULT_LANG)
    lp = render_lp({}, DEFAULT_LANG)

    # Persist for callbacks
    bundle = {"details": details, "why": why, "whypp": whypp, "lp": lp}
    # Send single message with keyboard right away
    resp = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, None, links))
    msg_id = None
    if resp.get("ok") and resp.get("result"):
        msg_id = resp["result"]["message_id"]
        store_bundle(chat_id, msg_id, bundle)
        # Update callbacks to include real msg_id (optional fine-tune)
        edit_message_text(chat_id, msg_id, quick, reply_markup=build_keyboard(chat_id, msg_id, links))

    register_scan(chat_id)
    return jsonify({"ok": True})

def on_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat",{}).get("id")
    msg_id = msg.get("message_id")

    # Support both "v1:ACTION:msgId:chatId" and "A:ACTION:chatId:msgId"
    m = re.match(r"v1:(\\w+):(\\-?\\d+):(\\-?\\d+)", data) or re.match(r"A:(\\w+):(\\-?\\d+):(\\-?\\d+)", data)
    action = m.group(1) if m else None

    bundle = load_bundle(chat_id, msg_id) or {}

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent\\.", False)
        send_message(chat_id, bundle.get("details","(no details)"))

    elif action == "WHY":
        answer_callback_query(cb_id, bundle.get("why","Why\\? n/a"), True)

    elif action == "WHYPP":
        answer_callback_query(cb_id, "Sent full rationale\\.", False)
        send_message(chat_id, bundle.get("whypp","Why\\+\\+ n/a"))

    elif action == "LP":
        answer_callback_query(cb_id, "LP lock info sent\\.", False)
        send_message(chat_id, bundle.get("lp","LP n/a"))

    elif action == "REPORT":
        answer_callback_query(cb_id, "Report sent\\.", False)
        rep = "*Metridex Report \\(lite\\)*\\n\\n" + (bundle.get("details","(no details)"))
        send_message(chat_id, rep)

    elif action == "UPGRADE":
        answer_callback_query(cb_id, "Upgrade: metridex\\.com/pricing", True)

    else:
        answer_callback_query(cb_id, "Unknown action\\.", True)

    return jsonify({"ok": True})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})
