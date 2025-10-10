import os, json, re, time, traceback, requests
from flask import Flask, request, jsonify

from limits import can_scan, register_scan
from state import store_bundle, load_bundle
from buttons import build_keyboard
from dex_client import fetch_market
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp
from chain_client import fetch_onchain_factors
from lp_lite import check_lp_lock_v2

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"

HELP_URL = os.getenv("HELP_URL", "https://metridex.com/help")
DEEP_REPORT_URL = os.getenv("DEEP_REPORT_URL", "https://metridex.com/upgrade/deep-report")
DAY_PASS_URL = os.getenv("DAY_PASS_URL", "https://metridex.com/upgrade/day-pass")
PRO_URL = os.getenv("PRO_URL", "https://metridex.com/upgrade/pro")
TEAMS_URL = os.getenv("TEAMS_URL", "https://metridex.com/upgrade/teams")
FREE_DAILY_SCANS = int(os.getenv("FREE_DAILY_SCANS", "2"))
HINT_CLICKABLE_LINKS = os.getenv("HINT_CLICKABLE_LINKS", "0") == "1"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

_MD2_SPECIALS = r'_*[]()~`>#+-=|{}.!'
_MD2_PATTERN = re.compile('[' + re.escape(_MD2_SPECIALS) + ']')
def mdv2_escape(text: str) -> str:
    if text is None: return ""
    return _MD2_PATTERN.sub(lambda m: '\\' + m.group(0), str(text))

def tg(method, payload=None, files=None, timeout=12):
    payload = payload or {}
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_message(chat_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

def answer_callback_query(cb_id, text, show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

def send_document(chat_id: int, filename: str, content_bytes: bytes, caption: str | None = None, content_type: str = "text/html"):
    files = { "document": (filename, content_bytes, content_type) }
    payload = {"chat_id": chat_id}
    if caption: payload["caption"] = caption
    return tg("sendDocument", payload, files=files)

def parse_cb(data: str):
    m = re.match(r"^v1:(\w+):(\-?\d+):(\-?\d+)$", data or "")
    if not m: return None
    return m.group(1), int(m.group(2)), int(m.group(3))

def _pricing_links():
    return {
        "deep_report": DEEP_REPORT_URL,
        "day_pass": DAY_PASS_URL,
        "pro": PRO_URL,
        "teams": TEAMS_URL,
        "help": HELP_URL,
    }

def build_hint_quickscan(clickable: bool) -> str:
    pair_example = "https://dexscreener.com/ethereum/0x..." if clickable else "dexscreener[.]com/ethereum/0x…"
    return (
        "Paste a *token address*, *TX hash* or *URL* to scan.\n"
        "Examples:\n"
        "`0x6982508145454ce325ddbe47a25d4ec3d2311933`  — ERC‑20\n"
        f"{pair_example} — pair\n\n"
        "Then tap *More details* / *Why?* / *On‑chain* for deeper info."
    )

WELCOME = (
    "Welcome to Metridex.\n"
    "Send a token address, TX hash, or a link — I'll run a QuickScan.\n\n"
    "Commands: /quickscan, /upgrade, /limits\n"
    f"Help: {HELP_URL}"
)
UPGRADE_TEXT = (
    "Metridex Pro — full QuickScan access\n"
    "• Pro $29/mo — fast lane, Deep reports, export\n"
    "• Teams $99/mo — for teams/channels\n"
    "• Day‑Pass $9 — 24h of Pro\n"
    "• Deep Report $3 — one detailed report\n\n"
    f"Choose your access below. How it works: {HELP_URL}"
)

# ---------- Back‑compat wrappers for renderers ----------
def safe_render_why(verdict, market, lang):
    try:
        # New signature: (verdict, market, lang)
        return render_why(verdict, market, lang)
    except TypeError:
        try:
            # Old signature: (verdict, lang)
            return render_why(verdict, lang)
        except TypeError:
            # Very old: (verdict)
            return render_why(verdict)

def safe_render_whypp(verdict, market, lang):
    try:
        return render_whypp(verdict, market, lang)
    except TypeError:
        try:
            return render_whypp(verdict, lang)
        except TypeError:
            return render_whypp(verdict)

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

def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    low = text.lower()

    if low.startswith("/start"):
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/upgrade"):
        send_message(chat_id, UPGRADE_TEXT, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/quickscan"):
        send_message(chat_id, build_hint_quickscan(HINT_CLICKABLE_LINKS), reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/limits"):
        try:
            ok, tier = can_scan(chat_id)
            plan = (tier or "Free")
            allowed = "✅ allowed now" if ok else "⛔ not allowed now"
        except Exception:
            plan, allowed = "Free", "—"
        msg_txt = (
            f"*Plan:* {plan}\n"
            f"*Free quota:* {FREE_DAILY_SCANS}/day\n"
            f"*Now:* {allowed}\n\n"
            "Upgrade for unlimited scans: /upgrade"
        )
        send_message(chat_id, msg_txt, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    # Only non-command messages trigger scan
    if text.startswith("/"):
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted. Use /upgrade.",
                     reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    token = text
    market = fetch_market(token) or {}
    verdict = compute_verdict(market)

    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    details = render_details(verdict, market, {}, DEFAULT_LANG)

    # Back‑compat: Why/Why++ work whether renderers expect (v, m, lang) or (v, lang)
    why = safe_render_why(verdict, market, DEFAULT_LANG)
    whypp = safe_render_whypp(verdict, market, DEFAULT_LANG)

    # LP text backward compatible
    try:
        info = check_lp_lock_v2(market.get("chain","eth"), market.get("pairAddress"))
        lp = render_lp(info, DEFAULT_LANG)
    except TypeError:
        lp = render_lp({"provider":"lite-burn-check","lpAddress": market.get("pairAddress"), "until": "—"})
    except Exception:
        lp = "LP lock: unknown"

    links = (market.get("links") or {})
    bundle = {
        "verdict": {"level": getattr(verdict, "level", None), "score": getattr(verdict, "score", None)},
        "reasons": list(getattr(verdict, "reasons", []) or []),
        "market": {
            "pairSymbol": market.get("pairSymbol"), "chain": market.get("chain"),
            "price": market.get("price"), "fdv": market.get("fdv"), "mc": market.get("mc"),
            "liq": market.get("liq"), "vol24h": market.get("vol24h"),
            "priceChanges": market.get("priceChanges") or {},
            "tokenAddress": market.get("tokenAddress"), "pairAddress": market.get("pairAddress"),
            "ageDays": market.get("ageDays"), "source": market.get("source"), "sources": market.get("sources"), "asof": market.get("asof")
        },
        "links": {"dex": links.get("dex"), "scan": links.get("scan"), "site": links.get("site")},
        "details": details, "why": why, "whypp": whypp, "lp": lp
    }

    # 1) send with temp keyboard (msg_id=0), 2) store bundle, 3) rebind keyboard with real msg_id
    sent = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, 0, links, ctx="quick"))
    msg_id = sent.get("result", {}).get("message_id") if sent.get("ok") else None
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
        try:
            tg("editMessageReplyMarkup", {
                "chat_id": chat_id,
                "message_id": msg_id,
                "reply_markup": json.dumps(build_keyboard(chat_id, msg_id, links, ctx="quick"))
            })
        except Exception as e:
            print("editMessageReplyMarkup failed:", e)
    register_scan(chat_id)
    return jsonify({"ok": True})

def on_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat",{}).get("id")
    current_msg_id = msg.get("message_id")

    m = parse_cb(data)
    if not m:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})
    action, orig_msg_id, orig_chat_id = m

    if orig_msg_id == 0:
        orig_msg_id = current_msg_id

    if chat_id != orig_chat_id and orig_chat_id != 0:
        answer_callback_query(cb_id, "This control expired.", True)
        return jsonify({"ok": True})

    bundle = load_bundle(chat_id, orig_msg_id) or {}
    links = bundle.get("links")

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details","(no details)"),
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))

    elif action == "WHY":
        txt = bundle.get("why","Why? n/a")
        send_message(chat_id, "Why?\n" + txt, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))
        answer_callback_query(cb_id, "Why? posted.", False)

    elif action == "WHYPP":
        txt = bundle.get("whypp","Why++ n/a")
        MAX = 3500
        if len(txt) <= MAX:
            send_message(chat_id, "Why++\n" + txt, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))
        else:
            i = 0
            while txt:
                i += 1
                chunk, txt = txt[:MAX], txt[MAX:]
                prefix = f"Why++ ({i})\n"
                send_message(chat_id, prefix + chunk, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details") if not txt else None)
        answer_callback_query(cb_id, "Why++ posted.", False)

    elif action == "LP":
        text = bundle.get("lp","LP lock: n/a")
        send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))
        answer_callback_query(cb_id, "LP lock posted.", False)

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
            txt = "*On-chain*\n" + json.dumps(f, ensure_ascii=False, indent=2)
        except Exception:
            txt = "On-chain: temporary unavailable"
        send_message(chat_id, txt, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="onchain"))
        answer_callback_query(cb_id, "On-chain posted.", False)

    elif action == "COPY_CA":
        addr = (bundle.get("market") or {}).get("tokenAddress") or "—"
        send_message(chat_id, addr + "\n(hold to copy)",
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))
        answer_callback_query(cb_id, "Address posted.", False)

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

    else:
        answer_callback_query(cb_id, "Unknown action.", True)

    return jsonify({"ok": True})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})
