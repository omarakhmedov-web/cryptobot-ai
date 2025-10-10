import os, json, re, traceback, requests
from flask import Flask, request, jsonify

from limits import can_scan, register_scan
from state import store_bundle, load_bundle
from buttons import build_keyboard
try:
    from dex_client import fetch_market
except Exception as _e:
    try:
        import dex_client as _dex
        fetch_market = getattr(_dex, 'fetch_market')
    except Exception as _e2:
        _err = str(_e2)
        def fetch_market(*args, **kwargs):
            return {'ok': False, 'error': 'market_fetch_unavailable: ' + _err, 'sources': [], 'links': {}}
from risk_engine import compute_verdict
from renderers import render_quick, render_details, render_why, render_whypp, render_lp
try:
    from lp_lite import check_lp_lock_v2
except Exception:
    def check_lp_lock_v2(chain, lp_addr):
        return {"provider": "lite-burn-check", "lpAddress": lp_addr or "—", "until": "—"}

try:
    from onchain_inspector import inspect_token
except Exception:
    inspect_token = None

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
        "`0x6982508145454ce325ddbe47a25d4ec3d2311933`  — ERC-20\n"
        f"{pair_example} — pair\n\n"
        "Then tap *More details* / *Why?* / *On-chain* for deeper info."
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
    "• Day-Pass $9 — 24h of Pro\n"
    "• Deep Report $3 — one detailed report\n\n"
    f"Choose your access below. How it works: {HELP_URL}"
)

def safe_render_why(verdict, market, lang):
    try:
        return render_why(verdict, market, lang)
    except TypeError:
        try:
            return render_why(verdict, lang)
        except TypeError:
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

    # QuickScan flow
    market = fetch_market(text) or {}
    if not market.get("ok"):
        if re.match(r"^0x[a-fA-F0-9]{64}$", text):
            pass
        elif re.match(r"^0x[a-fA-F0-9]{40}$", text):
            market.setdefault("tokenAddress", text)
        market.setdefault("chain", market.get("chain") or "—")
        market.setdefault("sources", [])
        market.setdefault("priceChanges", {})
        market.setdefault("links", {})

    verdict = compute_verdict(market)

    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = safe_render_why(verdict, market, DEFAULT_LANG)
    whypp = safe_render_whypp(verdict, market, DEFAULT_LANG)

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
        try:
            html = "<!doctype html><html><body><pre>" + json.dumps(bundle, ensure_ascii=False, indent=2) + "</pre></body></html>"
            send_document(chat_id, "Metridex_Report.html", html.encode("utf-8"), caption="Metridex QuickScan report")
            answer_callback_query(cb_id, "Report exported.", False)
        except Exception as e:
            answer_callback_query(cb_id, f"Export failed: {e}", True)

    elif action == "ONCHAIN":
        if inspect_token is None:
            answer_callback_query(cb_id, "On-chain module missing.", True)
            return jsonify({"ok": True})
        mkt = (bundle.get("market") or {})
        ch = (mkt.get("chain") or "").lower()
        tok = mkt.get("tokenAddress")
        pair = mkt.get("pairAddress")
        if not tok:
            answer_callback_query(cb_id, "No token in this message.", True)
            return jsonify({"ok": True})
        chain_map = {
            "ethereum":"eth","bsc":"bsc","polygon":"polygon","arbitrum":"arb","optimism":"op",
            "base":"base","avalanche":"avax","fantom":"ftm"
        }
        short = chain_map.get(ch, ch or "eth")
        info = inspect_token(short, tok, pair)
        pretty = "*On-chain*\n" + "```\n" + json.dumps(info, ensure_ascii=False, indent=2) + "\n```"
        send_message(chat_id, pretty, reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="onchain"))
        answer_callback_query(cb_id, "On-chain posted.", False)

    elif action == "COPY_CA":
        token = ((bundle.get("market") or {}).get("tokenAddress") or "—")
        answer_callback_query(cb_id, f"{token}", True)

    elif action.startswith("DELTA_"):
        send_message(chat_id, bundle.get("details","(no details)"),
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))
        answer_callback_query(cb_id, "Posted.", False)

    else:
        answer_callback_query(cb_id, "Unsupported action", True)

    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8000")))
