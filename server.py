import os, json, traceback, requests, re, time
from flask import Flask, request, jsonify

# ---- External project modules (kept as-is) ----
# These must exist in your environment; we don't touch their internals.
from limits import can_scan, register_scan, try_activate_judge_pass, is_judge_active
from state import store_bundle, load_bundle
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
app = Flask(__name__)

# ================= OMEGA UTILITIES =================
class OMEGA:
    BUTTONS_ORDER = [
        "More details",
        "Why?",
        "Why++",
        "LP lock",
        "Report",
        "Open in DEX",
        "Open in Scan",
        "Upgrade",
    ]
    _RU = {
        "Почему?":"Why?","Почему++":"Why++","Подробнее":"More details",
        "Заблокировать LP":"LP lock","Открыть в DEX":"Open in DEX",
        "Открыть в Scan":"Open in Scan","Отчёт":"Report","Обновить":"Upgrade"
    }
    @staticmethod
    def force_en(s: str) -> str:
        if not s: return s
        for ru,en in OMEGA._RU.items(): s = s.replace(ru,en)
        s = re.sub(r"[\\u0400-\\u04FF]+","",s) # strip Cyrillic
        return re.sub(r"[ \\t]{2,}"," ",s).strip()

    @staticmethod
    def verdict_emoji(vdict):
        sev = (vdict or {}).get("severity","").upper()
        return {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(sev,"ℹ️")

# ================= Telegram helpers =================
def tg(method, payload, files=None, timeout=10):
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        if r.status_code != 200:
            print("TG error:", r.status_code, r.text)
        return r.json()
    except Exception as e:
        print("TG exception", e)
        return {"ok":False, "error":str(e)}

def send_message(chat_id, text, parse_mode=None, reply_markup=None):
    text = OMEGA.force_en(text)
    data = {"chat_id": chat_id, "text": text}
    if parse_mode: data["parse_mode"] = parse_mode
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

def edit_message_text(chat_id, message_id, text, parse_mode=None, reply_markup=None):
    text = OMEGA.force_en(text)
    data = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if parse_mode: data["parse_mode"] = parse_mode
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("editMessageText", data)

def answer_callback_query(cb_id, text, show_alert=False):
    text = OMEGA.force_en(text)
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": text, "show_alert": bool(show_alert)})

def build_keyboard_standard(chat_id, msg_id, links):
    # We do not depend on buttons.py; build inline keyboard here, then state can still be used for bundles.
    btn = lambda text, data=None, url=None: {"text": text, **({"callback_data": data} if data else {}), **({"url": url} if url else {})}

    rows = [
        [btn("More details", f"A:DETAILS:{chat_id}:{msg_id}"), btn("Why?", f"A:WHY:{chat_id}:{msg_id}")],
        [btn("Why++", f"A:WHYPP:{chat_id}:{msg_id}"), btn("LP lock", f"A:LP:{chat_id}:{msg_id}")],
        [btn("Report", f"A:REPORT:{chat_id}:{msg_id}")],
    ]
    dex = (links or {}).get("dex") or (links or {}).get("dex_url")
    scan = (links or {}).get("scan") or (links or {}).get("scan_url")
    if dex or scan:
        row = []
        if dex: row.append(btn("Open in DEX", url=dex))
        if scan: row.append(btn("Open in Scan", url=scan))
        if row: rows.append(row)
    rows.append([btn("Upgrade", f"A:UPGRADE:{chat_id}:{msg_id}")])
    return {"inline_keyboard": rows}

# ================= Routes =================
@app.post(f"/webhook/{BOT_WEBHOOK_SECRET}")
def webhook():
    try:
        upd = request.get_json(force=True, silent=True) or {}
        if "message" in upd:
            return on_message(upd["message"])
        if "callback_query" in upd:
            return on_callback(upd["callback_query"])
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True, "status": "degraded"})

# ================= Handlers =================
def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    # /start and /help
    if text.startswith("/start") or text.lower() in ("/help", "help"):
        hello = (
            "Welcome to Metridex.\n"
            "Send a token address, TX hash, or a link — I'll run a QuickScan.\n\n"
            "Commands: /quickscan, /upgrade, /limits\n"
            "Pricing: metridex.com/pricing • Help: metridex.com/help"
        )
        send_message(chat_id, hello)
        return jsonify({"ok": True})

    # Judge pass activation
    if text.upper().startswith("PASS "):
        code = text.split(" ",1)[1].strip()
        ok, msg_txt = try_activate_judge_pass(chat_id, code)
        send_message(chat_id, msg_txt)
        return jsonify({"ok": True})

    # Simple scan flow
    token = text
    if not can_scan(chat_id):
        send_message(chat_id, "Free scans exhausted. Use /upgrade or enter your Judge Pass.")
        return jsonify({"ok": True})

    market = fetch_market(token)
    verdict = compute_verdict(market)  # external module
    links = market.get("links") or {}

    quick = render_quick(verdict, market, links, DEFAULT_LANG)
    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = render_why(verdict, DEFAULT_LANG)  # short bullets with emoji
    whypp = render_whypp(verdict, {}, DEFAULT_LANG)  # long form
    lp = render_lp({}, DEFAULT_LANG)

    # Persist bundle for callbacks
    bundle = {"details": details, "why": why, "whypp": whypp, "lp": lp}
    resp = send_message(chat_id, quick, parse_mode="Markdown")
    msg_id = None
    if resp.get("ok") and resp.get("result"):
        msg_id = resp["result"]["message_id"]
        store_bundle(chat_id, msg_id, bundle)

    # Our standard keyboard (includes Report and proper order)
    kb = build_keyboard_standard(chat_id, msg_id, links)
    if msg_id:
        edit_message_text(chat_id, msg_id, quick, parse_mode="Markdown", reply_markup=kb)
    else:
        send_message(chat_id, quick, parse_mode="Markdown", reply_markup=kb)

    register_scan(chat_id)
    return jsonify({"ok": True})

def on_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat",{}).get("id")
    msg_id = msg.get("message_id")

    m = re.match(r"A:(\w+):(\-?\d+):(\d+)", data or "")
    action = m.group(1) if m else None

    bundle = load_bundle(chat_id, msg_id) or {}

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details", "(no details)"), parse_mode="Markdown")

    elif action == "WHY":
        txt = bundle.get("why","Why? n/a")
        # WHY stays as a popup with emoji (nicer)
        answer_callback_query(cb_id, txt, True)

    elif action == "WHYPP":
        # WHY++ posts a long message in chat (not a popup)
        answer_callback_query(cb_id, "Sent full rationale.", False)
        send_message(chat_id, bundle.get("whypp","Why++ n/a"), parse_mode="Markdown")

    elif action == "LP":
        # LP posts text in chat (not a popup)
        answer_callback_query(cb_id, "LP lock info sent.", False)
        send_message(chat_id, bundle.get("lp","LP n/a"), parse_mode=None)

    elif action == "REPORT":
        # Lightweight report: details + separators (no HTML)
        answer_callback_query(cb_id, "Report sent.", False)
        rep = "*Metridex Report (lite)*\\n\\n" + (bundle.get("details","(no details)"))
        send_message(chat_id, rep, parse_mode="Markdown")

    elif action == "UPGRADE":
        answer_callback_query(cb_id, "Upgrade: metridex.com/pricing", True)

    else:
        answer_callback_query(cb_id, "Unknown action.", True)

    return jsonify({"ok": True})

# Health check
@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})
