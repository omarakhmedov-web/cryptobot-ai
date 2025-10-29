import os, re, json, time, traceback
from typing import Any, Dict, Optional

from flask import Flask, request, jsonify

# --- Imports from the project (with safe fallbacks) --------------------------
try:
    from dex_client import fetch_market
except Exception as _e:
    def fetch_market(q: str) -> Dict[str, Any]:
        return {"ok": False, "error": f"dex_client unavailable: {str(_e)}"}

try:
    from risk_engine import compute_verdict
except Exception as _e:
    def compute_verdict(market: Dict[str, Any]) -> Dict[str, Any]:
        return {"score": 5, "risks": [], "positives": []}

try:
    import onchain_inspector
    _inspect_token = onchain_inspector.inspect_token
except Exception as _e:
    _inspect_token = None

try:
    import renderers_mdx as _mdx
    from renderers_mdx import render_quick, render_details, render_why, render_whypp
except Exception as _e:
    def render_quick(verdict, market, ctx=None, lang="en"): return "QuickScan — unsupported renderer"
    def render_details(verdict, market, ctx=None, lang="en"): return "Details temporarily unavailable"
    def render_why(verdict, market=None, lang="en"): return "*Why?*\n• Renderer missing"
    def render_whypp(verdict, market=None, lang="en"): return "*Why++*\n• Renderer missing"

try:
    from state import store_bundle, load_bundle
except Exception:
    _BUNDLES: Dict[str, Dict[str, Any]] = {}
    def _key(chat_id: int, msg_id: int) -> str: return f"{chat_id}:{msg_id}"
    def store_bundle(chat_id: int, msg_id: int, bundle: Dict[str, Any]) -> None:
        _BUNDLES[_key(chat_id, msg_id)] = bundle or {}
    def load_bundle(chat_id: int, msg_id: int) -> Dict[str, Any]:
        return _BUNDLES.get(_key(chat_id, msg_id), {})

try:
    from buttons import build_keyboard
except Exception:
    def build_keyboard(chat_id: int, msg_id: int, links: Dict[str,str], ctx: str = "start") -> Dict[str, Any]:
        def _cb(a): return f"v1:{a}:{msg_id}:{chat_id}"
        kb = [
            [{"text": "More details", "callback_data": _cb("DETAILS")},
             {"text": "Why?", "callback_data": _cb("WHY")}],
            [{"text": "Why++", "callback_data": _cb("WHYPP")},
             {"text": "On-chain", "callback_data": _cb("ONCHAIN")}],
            [{"text": "LP", "callback_data": _cb("LP")}],
        ]
        return {"inline_keyboard": kb}

import requests

BOT_TOKEN = os.getenv("BOT_TOKEN","").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET","").strip()
WEBHOOK_PATH = f"/webhook/{BOT_WEBHOOK_SECRET}" if BOT_WEBHOOK_SECRET else "/webhook/secret-not-set"
DEFAULT_LANG = os.getenv("DEFAULT_LANG","en")

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

# --- Telegram helpers --------------------------------------------------------
_MD2_SPECIALS = r'_[]()~>#+-=|{}.!*`'
import re as _re_md
_MD2_PATTERN = _re_md.compile('[' + _re_md.escape(_MD2_SPECIALS) + ']')
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

def edit_message(chat_id, message_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "message_id": message_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("editMessageText", data)

def answer_callback_query(cb_id, text="", show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

def make_cb(action: str, msg_id: int, chat_id: int) -> str:
    return f"v1:{action}:{msg_id}:{chat_id}"

def ensure_lp_button_callback(markup: Dict[str, Any], msg_id: int, chat_id: int) -> Dict[str, Any]:
    """Force LP button callback_data to safe payload (without pair/token addresses)."""
    try:
        ik = (markup or {}).get("inline_keyboard") or []
        changed = False
        for row in ik:
            for btn in row:
                txt = str(btn.get("text") or "")
                if "lp" in txt.lower():
                    btn.pop("url", None)
                    btn["callback_data"] = make_cb("LP", msg_id, chat_id)
                    changed = True
        if changed:
            markup["inline_keyboard"] = ik
    except Exception:
        pass
    return markup or {}

# --- LP formatting (fallback) -----------------------------------------------
def _lp_status_from_oc(oc: Dict[str, Any]) -> str:
    try:
        if oc.get("lp_v3") is True:
            return "v3-NFT (locks not applicable)"
        lp = oc.get("lp_lock_lite") or {}
        burned = lp.get("burned_pct") or 0.0
        lockers = lp.get("lockers") or {}
        anyval = (burned > 0) or any((v or 0) > 0 for v in lockers.values())
        if not anyval:
            return "unlocked"
        total = burned + sum((v or 0) for v in lockers.values())
        return "locked-partial" if total < 95.0 else "locked"
    except Exception:
        return "unknown"

def format_lp_from_oc(chain: str, pair_addr: str, oc: Dict[str, Any]) -> str:
    chain_t = (chain or "—").capitalize()
    status = _lp_status_from_oc(oc or {})
    lp = (oc or {}).get("lp_lock_lite") or {}
    burned = lp.get("burned_pct")
    lockers = lp.get("lockers") or {}
    lines = []
    lines.append(f"LP lock (lite) — {chain_t}")
    lines.append(f"Status: {status}")
    if burned is not None:
        lines.append(f"Burned: {burned:.2f}%  (0xdead + 0x0)")
    if lockers:
        parts = [f"{k}={v:.2f}%" for k, v in lockers.items()]
        lines.append("Locked: " + (", ".join(parts) if parts else "—"))
    else:
        lines.append("Locked: — via —")
    lines.append(f"LP token: {pair_addr or '—'}")
    lines.append("Links: Holders (Etherscan) | UNCX | TeamFinance")
    lines.append("Data source: on-chain (cached)")
    return "\n".join(lines)

# --- Health ------------------------------------------------------------------
@app.route("/healthz", methods=["GET","HEAD"])
def healthz():
    return jsonify({"ok": True, "ts": int(time.time())}), 200

@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": int(time.time())}), 200

# --- Webhook -----------------------------------------------------------------
@app.get(WEBHOOK_PATH)
def probe():
    return jsonify({"ok": True, "method": "GET", "ts": int(time.time())}), 200

def _is_contract_address(s: str) -> bool:
    try:
        return bool(re.match(r"^0x[0-9a-fA-F]{40}$", s or ""))
    except Exception:
        return False

def _derive_token(market: Dict[str, Any]) -> Optional[str]:
    t = (market.get("tokenAddress") or "").strip() if isinstance(market.get("tokenAddress"), str) else ""
    if t.startswith("0x") and len(t) == 42:
        return t
    for k in ("address","token","token0Address","baseTokenAddress","token1Address","baseToken"):
        v = market.get(k)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            return v
        if isinstance(v, dict):
            a = (v.get("address") or "").strip()
            if a.startswith("0x") and len(a) == 42:
                return a
    return None

def _mk_links(chain: str, token: Optional[str], pair: Optional[str], dex_id: Optional[str]) -> Dict[str, str]:
    links = {}
    ch = (chain or "").lower()
    if token:
        scans = {
            "ethereum": "https://etherscan.io/token/",
            "eth": "https://etherscan.io/token/",
            "bsc": "https://bscscan.com/token/",
            "binance": "https://bscscan.com/token/",
            "polygon": "https://polygonscan.com/token/",
            "matic": "https://polygonscan.com/token/",
            "base": "https://basescan.org/token/",
            "arbitrum": "https://arbiscan.io/token/",
            "optimism": "https://optimistic.etherscan.io/token/",
        }
        base = scans.get(ch)
        if base: links["scan"] = base + token
    if pair and ch:
        links["dexscreener"] = f"https://dexscreener.com/{ch}/{pair}"
    if token:
        if (dex_id or "").lower().startswith("pancake") and ch in ("bsc","binance"):
            links["dex"] = f"https://pancakeswap.finance/swap?outputCurrency={token}"
        elif (dex_id or "").lower() in ("uniswap","uniswapv2","uniswapv3") and ch in ("ethereum","base","arbitrum","polygon","optimism"):
            links["dex"] = f"https://app.uniswap.org/explore/tokens/{ch}/{token}"
    return links

@app.post(WEBHOOK_PATH)
def webhook():
    # Optional header secret (accepts WEBHOOK_HEADER_SECRET or BOT_WEBHOOK_SECRET)
    hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    expected = os.getenv("WEBHOOK_HEADER_SECRET","").strip() or (BOT_WEBHOOK_SECRET or "")
    if expected and hdr != expected:
        return jsonify({"ok": False, "err": "bad secret header"}), 403
    upd = request.get_json(force=True, silent=True) or {}
    try:
        if "callback_query" in upd:
            return on_callback(upd["callback_query"])
        if "message" in upd:
            return on_message(upd["message"])
        if "edited_message" in upd:
            return on_message(upd["edited_message"])
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True})

def parse_cb(data: str):
    m = re.match(r"^v1:(\w+):(\-?\d+):(\-?\d+)$", data or "")
    if not m: return None
    return m.group(1), int(m.group(2)), int(m.group(3))

def on_message(msg: Dict[str, Any]):
    chat_id = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or msg.get("caption") or "").strip()

    # Ignore commands here (project keeps its own handlers)
    if not text or text.startswith("/"):
        send_message(chat_id, "Send a token address, TX hash, or pair URL — I'll scan it.")
        return jsonify({"ok": True})

    # QuickScan: fetch market
    try:
        market = fetch_market(text) or {}
    except Exception as e:
        print("fetch_market error:", e, traceback.format_exc())
        market = {}

    # Normalize/derive fields
    chain = (market.get("chain") or market.get("chainId") or "—")
    token = _derive_token(market) or (text if _is_contract_address(text) else None)
    pair  = (market.get("pairAddress") or market.get("pair") or "")
    if isinstance(pair, dict): pair = pair.get("address") or ""

    # On-chain: eager single-shot call to cache LP info (no extra RPC on button)
    oc = {}
    if _inspect_token and token:
        try:
            oc = _inspect_token(token, chain_hint=chain, pair_address=pair) or {}
        except Exception as e:
            print("inspect_token error:", e)

    # Verdict & renders
    verdict = compute_verdict(market)
    ctx = {"webintel": {}, "domain": None}  # pass-through placeholder to match renderer signature
    quick = render_quick(verdict, market, ctx, DEFAULT_LANG)

    # Send message
    sent = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, 0, _mk_links(chain, token, pair, (market.get("links") or {}).get("dexId")), ctx="scan"))
    msg_id = None
    if isinstance(sent, dict) and sent.get("ok"):
        msg_id = ((sent.get("result") or {}).get("message_id"))

    # Persist bundle (pairAddress kept ONLY in server-side bundle)
    if msg_id:
        bundle = {
            "market": market,
            "chain": chain,
            "token": token,
            "pair": pair,
            "verdict": verdict,
            "oc": oc,  # includes lp_v3 / lp_lock_lite when available
        }
        store_bundle(chat_id, msg_id, bundle)

        # Force LP button to safe callback form
        try:
            kb = build_keyboard(chat_id, msg_id, _mk_links(chain, token, pair, (market.get("links") or {}).get("dexId")), ctx="scan")
            kb = ensure_lp_button_callback(kb, msg_id, chat_id)
            edit_message(chat_id, msg_id, quick, reply_markup=kb)
        except Exception:
            pass

    return jsonify({"ok": True})

def on_callback(cb: Dict[str, Any]):
    data = (cb.get("data") or "").strip()
    parsed = parse_cb(data)
    if not parsed:
        answer_callback_query(cb.get("id"), "Unsupported action")
        return jsonify({"ok": True})
    action, msg_id, chat_id = parsed

    msg = (cb.get("message") or {})
    # Load bundle (contains market + oc + pair)
    bundle = load_bundle(chat_id, msg_id) or {}
    market = bundle.get("market") or {}
    chain  = bundle.get("chain") or (market.get("chain") or "—")
    pair   = bundle.get("pair") or (market.get("pairAddress") or "—")
    verdict = bundle.get("verdict") or compute_verdict(market)

    # Route actions
    if action == "DETAILS":
        text = render_details(verdict, market, {"webintel": {}, "domain": None}, DEFAULT_LANG)
        edit_message(chat_id, msg_id, text, reply_markup=ensure_lp_button_callback(build_keyboard(chat_id, msg_id, market.get("links") or {}, ctx="details"), msg_id, chat_id))
        return jsonify({"ok": True})

    if action == "WHY":
        text = render_why(verdict, market, DEFAULT_LANG)
        edit_message(chat_id, msg_id, text, reply_markup=ensure_lp_button_callback(build_keyboard(chat_id, msg_id, market.get("links") or {}, ctx="why"), msg_id, chat_id))
        return jsonify({"ok": True})

    if action == "WHYPP":
        text = render_whypp(verdict, market, DEFAULT_LANG)
        edit_message(chat_id, msg_id, text, reply_markup=ensure_lp_button_callback(build_keyboard(chat_id, msg_id, market.get("links") or {}, ctx="whypp"), msg_id, chat_id))
        return jsonify({"ok": True})

    if action == "ONCHAIN":
        oc = bundle.get("oc") or {}
        # Minimal on-chain print (if renderer is missing)
        o_lines = ["On-chain"]
        if oc.get("contract_code_present") is True:
            o_lines.append("Contract code: present")
        owner = oc.get("owner") or oc.get("owner_address")
        if owner:
            o_lines.append(f"Owner: {owner}")
        text = "\n".join(o_lines) if len(o_lines) > 1 else "On-chain: —"
        edit_message(chat_id, msg_id, text, reply_markup=ensure_lp_button_callback(build_keyboard(chat_id, msg_id, market.get("links") or {}, ctx="onchain"), msg_id, chat_id))
        return jsonify({"ok": True})

    if action == "LP":
        # Reuse cached oc -> lp_lock_lite / lp_v3 (NO extra RPC)
        oc = bundle.get("oc") or {}
        if not oc:
            text = "LP lock: unknown"
        else:
            text = format_lp_from_oc(chain, pair, oc)
        edit_message(chat_id, msg_id, text, reply_markup=ensure_lp_button_callback(build_keyboard(chat_id, msg_id, market.get("links") or {}, ctx="lp"), msg_id, chat_id))
        return jsonify({"ok": True})

    answer_callback_query(cb.get("id"), "Unsupported action")
    return jsonify({"ok": True})
