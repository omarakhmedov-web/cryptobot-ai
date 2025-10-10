import os, json, re, time, traceback, requests
from flask import Flask, request, jsonify

from limits import can_scan, register_scan, try_activate_judge_pass
from state import store_bundle, load_bundle
from buttons import build_keyboard
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"
DEBUG_TG = os.getenv("DEBUG_TG", "0") == "1"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

# ---------- Robust MarkdownV2 escaping with automatic fallback ----------
_MD2_SPECIALS = r'_*[]()~`>#+-=|{}.!'
_MD2_PATTERN = re.compile('[' + re.escape(_MD2_SPECIALS) + ']')

def mdv2_escape(text: str) -> str:
    if text is None: return ""
    return _MD2_PATTERN.sub(lambda m: '\\\\' + m.group(0), str(text))

def tg(method, payload=None, files=None, timeout=12):
    payload = payload or {}
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        try:
            j = r.json()
        except Exception:
            j = {"ok": False, "status_code": r.status_code, "text": r.text}
        if DEBUG_TG and (not j.get("ok", False)):
            print("TG API ERR:", method, r.status_code, r.text[:400])
        return j
    except Exception as e:
        if DEBUG_TG:
            print("TG EXC:", method, e)
        return {"ok": False, "error": str(e)}

def send_message(chat_id, text, reply_markup=None):
    # Try MarkdownV2 first; if fails, retry plain text
    data = {"chat_id": chat_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    res = tg("sendMessage", data)
    if not res.get("ok"):
        if DEBUG_TG:
            print("Retry sendMessage as plain text")
        data2 = {"chat_id": chat_id, "text": str(text)}
        if reply_markup: data2["reply_markup"] = json.dumps(reply_markup)
        res = tg("sendMessage", data2)
    return res

def edit_message_text(chat_id, message_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "message_id": message_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    res = tg("editMessageText", data)
    if not res.get("ok"):
        if DEBUG_TG:
            print("Retry editMessageText as plain text")
        data2 = {"chat_id": chat_id, "message_id": message_id, "text": str(text)}
        if reply_markup: data2["reply_markup"] = json.dumps(reply_markup)
        res = tg("editMessageText", data2)
    return res

def answer_callback_query(cb_id, text, show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

def send_document(chat_id: int, filename: str, content_bytes: bytes, caption: str | None = None, content_type: str = "text/html"):
    files = { "document": (filename, content_bytes, content_type) }
    payload = {"chat_id": chat_id}
    if caption: payload["caption"] = caption
    return tg("sendDocument", payload, files=files)

# ---------- Callback versioning ----------
VALID_ACTIONS = {"DETAILS","WHY","WHYPP","LP","REPORT","UPGRADE"}
def parse_callback(data: str):
    m = re.match(r"^v1:(\\w+):(\\-?\\d+):(\\-?\\d+)$", data or "")
    if not m: return None
    action, msg_id, chat_id = m.group(1), int(m.group(2)), int(m.group(3))
    if action not in VALID_ACTIONS: return None
    return action, msg_id, chat_id

# ---------- HTML report ----------
def _sev_color(level: str) -> str:
    return {"LOW":"#16a34a","MEDIUM":"#ca8a04","HIGH":"#ea580c","CRITICAL":"#dc2626"}.get((level or "").upper(),"#6b7280")
def _sev_emoji(level: str) -> str:
    return {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get((level or "").upper(), "ℹ️")

def build_html_report(bundle: dict) -> str:
    v = bundle.get("verdict") or {}
    m = bundle.get("market") or {}
    links = bundle.get("links") or {}
    reasons = bundle.get("reasons") or []
    def fmt(x): return "—" if x in (None, "", []) else str(x)
    css = "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,'Noto Sans','Apple Color Emoji','Segoe UI Emoji';background:#0b0f17;color:#e5e7eb;margin:0;padding:24px}.card{background:#0f172a;border:1px solid #1f2937;border-radius:14px;padding:20px;max-width:900px;margin:0 auto;box-shadow:0 6px 28px rgba(0,0,0,.4)}h1{font-size:20px;margin:0 0 12px 0;font-weight:700;display:flex;align-items:center;gap:8px}h2{font-size:16px;margin:20px 0 8px 0}.pill{display:inline-block;padding:4px 10px;border-radius:999px;background:#111827;font-weight:600;color:#fff;border:1px solid #1f2937}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.row{display:flex;justify-content:space-between;background:#0b1220;border:1px solid #1f2937;border-radius:10px;padding:8px 12px}.muted{color:#9ca3af}a{color:#7dd3fc;text-decoration:none}.footer{margin-top:18px;font-size:12px;color:#9ca3af}.reasons li{margin:6px 0}"
    pair = fmt(m.get("pairSymbol")); chain = fmt(m.get("chain")); price = fmt(m.get("price"))
    fdv = fmt(m.get("fdv")); mc = fmt(m.get("mc")); liq = fmt(m.get("liq")); vol24h = fmt(m.get("vol24h"))
    deltas = m.get("priceChanges") or {}; d5m = fmt(deltas.get("m5")); d1h = fmt(deltas.get("h1")); d24h = fmt(deltas.get("h24"))
    token = fmt(m.get("tokenAddress")); pairA = fmt(m.get("pairAddress"))
    level = v.get("level","?"); score = v.get("score","?"); color = _sev_color(level); emoji = _sev_emoji(level)
    html = f"<!doctype html><html><head><meta charset='utf-8'><title>Metridex Report — {pair}</title><meta name='viewport' content='width=device-width,initial-scale=1'><style>{css}</style></head><body><div class='card'><h1>{emoji} Metridex QuickScan — {pair} <span class='pill' style='border-color:{color};color:{color}'>{level} ({score})</span></h1><div class='grid'><div class='row'><div class='muted'>Chain</div><div>{chain}</div></div><div class='row'><div class='muted'>Price</div><div>{price}</div></div><div class='row'><div class='muted'>FDV</div><div>{fdv}</div></div><div class='row'><div class='muted'>Market Cap</div><div>{mc}</div></div><div class='row'><div class='muted'>Liquidity</div><div>{liq}</div></div><div class='row'><div class='muted'>Vol 24h</div><div>{vol24h}</div></div><div class='row'><div class='muted'>Δ5m</div><div>{d5m}</div></div><div class='row'><div class='muted'>Δ1h</div><div>{d1h}</div></div><div class='row'><div class='muted'>Δ24h</div><div>{d24h}</div></div><div class='row'><div class='muted'>Token</div><div>{token}</div></div><div class='row'><div class='muted'>Pair</div><div>{pairA}</div></div></div><h2>Why?</h2><ul class='reasons'>{''.join(f'<li>{re}</li>' for re in reasons[:12]) or '<li>No specific risk flags</li>'}</ul></div></body></html>"
    return html

# ---------- Webhook ----------
@app.post(f"/webhook/{BOT_WEBHOOK_SECRET}")
def webhook():
    try:
        upd = request.get_json(force=True, silent=True) or {}
        if DEBUG_TG:
            print("UPDATE KEYS:", list(upd.keys()))
        if "message" in upd:
            return on_message(upd["message"])
        if "edited_message" in upd:  # handle edits as messages
            return on_message(upd["edited_message"])
        if "callback_query" in upd:
            return on_callback(upd["callback_query"])
        # ignore other update types but return ok
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True, "status": "degraded"})

# ---------- Handlers ----------
def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if text.lower().startswith("/start") or text.lower() in ("/help", "help"):
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

    token = text or ""
    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted\\. Use /upgrade or enter your Judge Pass\\.")
        return jsonify({"ok": True})

    try:
        market = fetch_market(token)
        verdict = compute_verdict(market)
        links = (market or {}).get("links") or {}
    except Exception as e:
        print("PIPELINE ERROR:", e, traceback.format_exc())
        send_message(chat_id, "Temporary error while scanning. Please retry.")
        return jsonify({"ok": True})

    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    # strip inline links; leave clean facts
    quick = re.sub(r"\\[.*?\\]\\(.*?\\)", "", quick).strip()

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
        "details": details, "why": why, "whypp": whypp, "lp": lp,
    }

    kb = build_keyboard(chat_id, None, links)
    sent = send_message(chat_id, quick, reply_markup=kb)
    msg_id = sent.get("result", {}).get("message_id") if sent.get("ok") else None
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
        edit_message_text(chat_id, msg_id, quick, reply_markup=build_keyboard(chat_id, msg_id, links))

    register_scan(chat_id)
    return jsonify({"ok": True})

def on_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat",{}).get("id")
    msg_id = msg.get("message_id")

    parsed = parse_callback(data)
    if not parsed:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})

    action, cb_msg_id, cb_chat_id = parsed
    if chat_id != cb_chat_id or msg_id != cb_msg_id:
        answer_callback_query(cb_id, "This action is no longer available", True)
        return jsonify({"ok": True})

    bundle = load_bundle(chat_id, msg_id) or {}

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details","(no details)"))

    elif action == "WHY":
        answer_callback_query(cb_id, bundle.get("why","Why? n/a"), True)

    elif action == "WHYPP":
        text = bundle.get("whypp","Why++ n/a")
        if len(text) <= 190:
            answer_callback_query(cb_id, text, True)
        else:
            answer_callback_query(cb_id, "Sent extended rationale.", False)
            send_message(chat_id, text)

    elif action == "LP":
        text = bundle.get("lp","LP n/a")
        if len(text) <= 190:
            answer_callback_query(cb_id, text, True)
        else:
            answer_callback_query(cb_id, "LP lock info sent.", False)
            send_message(chat_id, text)

    elif action == "REPORT":
        answer_callback_query(cb_id, "Report sent.", False)
        html = build_html_report(bundle)
        fname = f"Metridex_Report_{int(time.time())}.html"
        send_document(chat_id, fname, html.encode("utf-8"), caption="Metridex QuickScan report")

    elif action == "UPGRADE":
        answer_callback_query(cb_id, "Upgrade: metridex.com/pricing", True)

    else:
        answer_callback_query(cb_id, "Unknown action.", True)

    return jsonify({"ok": True})

# ---------- Debug endpoints ----------
@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

@app.get(f"/ping/{BOT_WEBHOOK_SECRET}")
def ping():
    return jsonify({"ok": True, "ts": int(time.time())})

@app.get(f"/debug/send/{BOT_WEBHOOK_SECRET}")
def debug_send():
    chat_id = request.args.get("chat_id", type=int)
    if not chat_id:
        return jsonify({"ok": False, "error": "chat_id required"}), 400
    res = send_message(chat_id, "Metridex debug: hello 👋")
    return jsonify(res)
