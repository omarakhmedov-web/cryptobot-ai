# -*- coding: utf-8 -*-
import os, time, re, json, math
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests

APP_NAME = "Metridex"
TG_TOKEN = os.getenv("TG_BOT_TOKEN") or os.getenv("BOT_TOKEN")
TG_API = f"https://api.telegram.org/bot{TG_TOKEN}" if TG_TOKEN else None
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET") or os.getenv("TG_WEBHOOK_SECRET") or "webhook"

PARSE_MODE = "MarkdownV2"
app = Flask(__name__)

# ===== In-memory state for callback buttons =====
_BUNDLES = {}       # (chat_id, message_id) -> dict
_BUNDLES_LRU = []   # LRU for cleanup
_BUNDLES_LIMIT = 500

def _bund_key(chat_id, msg_id): return f"{chat_id}:{msg_id}"

def store_bundle(chat_id, msg_id, data):
    key = _bund_key(chat_id, msg_id)
    _BUNDLES[key] = data
    _BUNDLES_LRU.append(key)
    if len(_BUNDLES_LRU) > _BUNDLES_LIMIT:
        old = _BUNDLES_LRU.pop(0)
        _BUNDLES.pop(old, None)

def load_bundle(chat_id, msg_id):
    return _BUNDLES.get(_bund_key(chat_id, msg_id)) or {}

# ===== Telegram helpers =====
def tg(method, data):
    if not TG_API:
        return {"ok": False, "error": "no_token"}
    try:
        r = requests.post(f"{TG_API}/{method}", json=data, timeout=10)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

def mdv2_escape(text):
    # Minimal MarkdownV2 escape
    s = str(text)
    for ch in r"_*[]()~`>#+-=|{}.!":
        s = s.replace(ch, "\\" + ch)
    return s

def send_message(chat_id, text, reply_markup=None, parse_mode=PARSE_MODE, disable_preview=True):
    data = {"chat_id": chat_id, "text": mdv2_escape(text) if parse_mode=="MarkdownV2" else text}
    if parse_mode: data["parse_mode"] = parse_mode
    if disable_preview is not None: data["disable_web_page_preview"] = disable_preview
    if reply_markup: data["reply_markup"] = reply_markup
    return tg("sendMessage", data)

def edit_message(chat_id, message_id, text, reply_markup=None, parse_mode=PARSE_MODE, disable_preview=True):
    data = {"chat_id": chat_id, "message_id": message_id, "text": mdv2_escape(text) if parse_mode=="MarkdownV2" else text}
    if parse_mode: data["parse_mode"] = parse_mode
    if disable_preview is not None: data["disable_web_page_preview"] = disable_preview
    if reply_markup: data["reply_markup"] = reply_markup
    return tg("editMessageText", data)

def answer_callback_query(cb_id, text="", show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": text, "show_alert": bool(show_alert)})

# ===== DexScreener fetch (direct or via proxy) =====
def fetch_market(query):
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "empty_query"}
    is_addr = bool(re.match(r"^0x[a-fA-F0-9]{40}$", query))
    base = os.getenv("DEXSCREENER_PROXY_BASE") or ""
    path = f"/latest/dex/tokens/{query}" if is_addr else "/latest/dex/search?q=" + requests.utils.quote(query, safe="")
    url = (base.rstrip("/") + path) if base else ("https://api.dexscreener.com" + path)
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"ok": False, "error": f"dexscreener_fetch_failed: {type(e).__name__}: {e}", "links": {}, "sources": []}
    pairs = data.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no_pairs", "links": {}, "sources": []}

    def _liq(p):
        try: return float((p.get("liquidity") or {}).get("usd") or p.get("liquidityUSD") or 0.0)
        except: return 0.0
    P = max(pairs, key=_liq)

    def _num(v):
        try: return float(v)
        except: return None

    price = _num(P.get("priceUsd") or P.get("price") or 0)
    fdv   = _num(P.get("fdv"))
    mc    = _num(P.get("marketCap"))
    liq   = _num((P.get("liquidity") or {}).get("usd") or P.get("liquidityUSD"))
    vol24 = _num((P.get("volume") or {}).get("h24") or P.get("volume24h"))
    chg   = P.get("priceChange") or {}
    price_changes = {"m5": _num(chg.get("m5")), "h1": _num(chg.get("h1")), "h24": _num(chg.get("h24"))}
    baseTok = P.get("baseToken") or {}
    quoteTok= P.get("quoteToken") or {}
    token_addr = baseTok.get("address") or P.get("baseTokenAddress") or (query if is_addr else None)
    pair_addr  = P.get("pairAddress") or P.get("pair")
    chain      = P.get("chainId") or P.get("chain") or P.get("chainIdName")
    pair_sym   = f"{baseTok.get('symbol','')}/{quoteTok.get('symbol','')}".strip("/")
    asof_ms = int(time.time() * 1000)
    pc = P.get("pairCreatedAt") or P.get("launchedAt") or P.get("createdAt")
    age_days = None
    try:
        ts = int(pc)
        if ts < 10**12: ts *= 1000
        age_days = max(0.0, (asof_ms - ts) / (1000*60*60*24))
    except: pass

    # links
    url_ds = P.get("url") or P.get("pairUrl") or (f"https://dexscreener.com/{P.get('chainId') or P.get('chain')}/{pair_addr}" if pair_addr else None)
    url_scan = None
    cl = str(chain or "").lower()
    if token_addr:
        if cl.startswith("eth"): url_scan = f"https://etherscan.io/address/{token_addr}"
        elif "bsc" in cl or "bnb" in cl: url_scan = f"https://bscscan.com/address/{token_addr}"
        elif "poly" in cl: url_scan = f"https://polygonscan.com/address/{token_addr}"
    url_dex = None
    if token_addr:
        if "eth" in cl: url_dex = f"https://app.uniswap.org/#/swap?outputCurrency={token_addr}"
        elif "bsc" in cl or "bnb" in cl: url_dex = f"https://pancakeswap.finance/swap?outputCurrency={token_addr}"
        elif "poly" in cl: url_dex = f"https://quickswap.exchange/#/swap?outputCurrency={token_addr}"

    return {
        "ok": True,
        "pairSymbol": pair_sym or "—",
        "chain": str(chain or ""),
        "price": price, "fdv": fdv, "mc": mc,
        "liq": liq, "vol24h": vol24, "priceChanges": price_changes,
        "tokenAddress": token_addr, "pairAddress": pair_addr,
        "ageDays": age_days, "asof": asof_ms, "source": "DexScreener",
        "links": {"dexscreener": url_ds, "scan": url_scan, "dex": url_dex}
    }

def _fmt_num(v, prefix="$"):
    if v is None: return "—"
    a = abs(v)
    if a >= 1_000_000_000: s = f"{v/1_000_000_000:.2f}B"
    elif a >= 1_000_000:   s = f"{v/1_000_000:.2f}M"
    elif a >= 1_000:       s = f"{v/1_000:.2f}K"
    else:                  s = f"{v:.6f}" if v < 1 else f"{v:.2f}"
    return (prefix + s) if prefix else s

def _fmt_pct(v):
    if v is None: return "—"
    sign = "▲" if v >= 0 else "▼"
    return f"{sign} {abs(v):.2f}%"

def _fmt_time(ms):
    try:
        ts = int(ms)
        if ts < 10**12: ts *= 1000
        return datetime.fromtimestamp(ts/1000.0, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return "—"

def _fmt_age(days):
    try:
        d = float(days)
        if d < 1/24: return "<1h"
        if d < 1: return f"{d*24:.1f}h"
        return f"{d:.1f}d"
    except: return "—"

def build_keyboard(bundle_key, links):
    btns = [
        [{"text":"Details","callback_data":f\"QS|DETAILS|{bundle_key}\"},
         {"text":"Why++","callback_data":f\"QS|WHYPP|{bundle_key}\"}],
        [{"text":"LP lock","callback_data":f\"QS|LP|{bundle_key}\"},
         {"text":"Report","callback_data":f\"QS|REPORT|{bundle_key}\"}]
    ]
    # Attach external links row if present
    url_row = []
    if links.get("dexscreener"): url_row.append({"text":"DexScreener","url":links["dexscreener"]})
    if links.get("dex"): url_row.append({"text":"DEX","url":links["dex"]})
    if links.get("scan"): url_row.append({"text":"Scan","url":links["scan"]})
    if url_row: btns.append(url_row)
    return {"inline_keyboard": btns}

def render_quick(market):
    pair = market.get("pairSymbol") or "—"
    chain= (market.get("chain") or "—").capitalize()
    price = _fmt_num(market.get("price"))
    fdv   = _fmt_num(market.get("fdv"))
    mc    = _fmt_num(market.get("mc"))
    liq   = _fmt_num(market.get("liq"))
    vol   = _fmt_num(market.get("vol24h"))
    ch5   = _fmt_pct((market.get("priceChanges") or {}).get("m5"))
    ch1   = _fmt_pct((market.get("priceChanges") or {}).get("h1"))
    ch24  = _fmt_pct((market.get("priceChanges") or {}).get("h24"))
    age   = _fmt_age(market.get("ageDays"))
    asof  = _fmt_time(market.get("asof"))
    src   = market.get("source") or "—"
    # no risk score here (keep placeholder)
    head = f"*{APP_NAME} QuickScan — {pair}* 🟢 (—)\\n`{chain}`  •  Price: *{price}*"
    body = f"FDV: {fdv}  •  MC: {mc}  •  Liq: {liq}\\nVol 24h: {vol}  •  Δ5m {ch5}  •  Δ1h {ch1}  •  Δ24h {ch24}\\nAge: {age}  •  Source: {src}  •  as of {asof}"
    return head + "\\n" + body

WELCOME = (
    "*Welcome to Metridex QuickScan*\\n"
    "Paste a *token address* (0x…), a *TX hash*, or a *DexScreener pair URL*.\\n"
    "Use /limits and /upgrade for plan info."
)

def handle_start(chat_id):
    send_message(chat_id, WELCOME, reply_markup=None)

def handle_text(chat_id, text, msg):
    low = text.strip().lower()
    if low.startswith("/start"): 
        handle_start(chat_id); 
        return
    # QuickScan if address or URL
    is_addr = bool(re.match(r"^0x[a-fA-F0-9]{40}$", text.strip()))
    is_url  = bool(re.match(r"^https?://\\S+", text.strip()))
    if is_addr or is_url:
        ph = send_message(chat_id, "Processing…")
        ph_id = ph.get("result",{}).get("message_id") if ph.get("ok") else None
        mkt = fetch_market(text)
        if not mkt.get("ok"):
            send_message(chat_id, "Unable to scan this input. Paste a *token address* (0x…), *TX hash*, or a DexScreener pair URL*.")
            return
        quick = render_quick(mkt)
        links = mkt.get("links") or {}
        sent = send_message(chat_id, quick, reply_markup=build_keyboard(f"{chat_id}:{(ph_id or int(time.time()))}", links))
        msg_id = sent.get("result",{}).get("message_id") if sent.get("ok") else None
        if msg_id:
            store_bundle(chat_id, msg_id, {"market": mkt})
        return
    # Otherwise send a hint
    send_message(chat_id, "Send a *token address* (0x…), *TX hash*, or a DexScreener pair URL*.")

def handle_callback(cb):
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg  = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    msg_id  = msg.get("message_id")

    parts = data.split("|")
    if len(parts) < 3 or parts[0] != "QS":
        answer_callback_query(cb_id, "Unsupported action")
        return
    action = parts[1]

    bundle = load_bundle(chat_id, msg_id) or {}
    mkt = bundle.get("market") or {}

    if action == "DETAILS":
        lines = []
        pair = mkt.get("pairSymbol","—")
        lines.append(f"*{pair} — links*")
        links = (mkt.get("links") or {})
        if links.get("dexscreener"): lines.append(f"• DexScreener: {links['dexscreener']}")
        if links.get("scan"):        lines.append(f"• Scan: {links['scan']}")
        if links.get("dex"):         lines.append(f"• DEX: {links['dex']}")
        text = "\\n".join(lines) if lines else "No extra links."
        send_message(chat_id, text)
        answer_callback_query(cb_id, "Details posted.")
    elif action == "WHYPP":
        send_message(chat_id, "Why++ is not available in this hotfix build.")
        answer_callback_query(cb_id, "Why++ posted.")
    elif action == "LP":
        send_message(chat_id, "LP lock info is not available in this hotfix build.")
        answer_callback_query(cb_id, "LP info posted.")
    elif action == "REPORT":
        send_message(chat_id, "Thanks! We recorded your feedback.")
        answer_callback_query(cb_id, "Reported.")
    else:
        answer_callback_query(cb_id, "Unknown action")

@app.route(f"/webhook/<secret>", methods=["POST"])
def webhook(secret):
    if secret != WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "secret_mismatch"}), 403
    try:
        upd = request.get_json(force=True, silent=True) or {}
    except Exception:
        upd = {}
    if "message" in upd:
        msg = upd["message"]
        chat_id = (msg.get("chat") or {}).get("id")
        text = msg.get("text") or msg.get("caption") or ""
        if chat_id and isinstance(text, str):
            handle_text(chat_id, text, msg)
        return jsonify({"ok": True})
    if "callback_query" in upd:
        handle_callback(upd["callback_query"] or {})
        return jsonify({"ok": True})
    return jsonify({"ok": True})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "name": APP_NAME, "ts": int(time.time())})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
