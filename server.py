import os
import re
import ssl
import json
import time
import socket
import tempfile
import hashlib
import threading
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify

# Project-local utilities (must exist in your project)
from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

# ========================
# Environment & constants
# ========================
APP_VERSION = os.environ.get("APP_VERSION", "0.3.8-quickscan+delta-fallback")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")  # numeric string
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "6.0"))
KNOWN_AUTORELOAD_SEC = int(os.environ.get("KNOWN_AUTORELOAD_SEC", "300"))
SCANNER_URL = os.environ.get("SCANNER_URL", "").strip()
ETH_RPC_URLS = os.environ.get("ETH_RPC_URLS", "").strip()

# Domain meta TTLs
try:
    DOMAIN_META_TTL = int(os.getenv("DOMAIN_META_TTL", "2592000"))      # 30 days
    DOMAIN_META_TTL_NEG = int(os.getenv("DOMAIN_META_TTL_NEG", "120"))  # 2 min for negative WB
except Exception:
    DOMAIN_META_TTL = 2592000
    DOMAIN_META_TTL_NEG = 120

LOC = locale_text
app = Flask(__name__)

# ========================
# Caches
# ========================
cache = SafeCache(ttl=CACHE_TTL_SECONDS)          # general cache if needed
seen_callbacks = SafeCache(ttl=300)               # dedupe callback ids
cb_cache = SafeCache(ttl=600)                     # long callback payloads by hash

# ===== Δ timeframe (DexScreener) helpers =====

# ===== Honeypot.is & LP lock helpers =====
HP_API_BASE = os.environ.get("HP_API_BASE", "https://api.honeypot.is").rstrip("/")
_HP_CACHE = {}
_HP_TTL = int(os.environ.get("HP_TTL", "600"))
_TOPH_CACHE = {}
_TOPH_TTL = int(os.environ.get("TOPH_TTL", "1200"))

DEAD_ADDRS = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dEaD",
    "0xdead000000000000000042069420694206942069",
}

UNCX_LOCKERS = {
    "ethereum": {"v2":"0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214", "v3":"0x7f5c649856f900d15c83741f45ae46f5c6858234"},
    "bsc":      {"v2":"0xc765bddb93b0d1c1a88282ba0fa6b2d00e3e0c83", "v3":"0x0d29598ec01fa03665feead91d4fb423f393886c"},
    "polygon":  {"v2":"0xadb2437e6f65682b85f814fbc12fec0508a7b1d0", "v3":"0xc22218406983bf88bb634bb4bf15fa4e0a1a8c84"},
    "arbitrum": {"v2":"0x275720567e5955f5f2d53a7a1ab8a0fc643de50e", "v3":"0xfa104eb3925a27e6263e05acc88f2e983a890637"},
    "base":     {"v2":"0xc4e637d37113192f4f1f060daebd7758de7f4131", "v3":"0x231278edd38b00b07fbd52120cef685b9baebcc1"},
}

TEAMFINANCE_LOCKERS = {
    "ethereum": ["0xe2fe530c047f2d85298b07d9333c05737f1435fb"],
}
try:
    _extra_tf = os.environ.get("TEAMFINANCE_LOCKERS_JSON","").strip()
    if _extra_tf:
        TEAMFINANCE_LOCKERS.update(json.loads(_extra_tf))
except Exception:
    pass

CHAIN_NAME_TO_ID = {
    "ethereum": 1, "eth": 1,
    "bsc": 56, "bnb":56,
    "polygon": 137, "matic":137,
    "arbitrum": 42161, "arb":42161,
    "base": 8453,
}



# Known blue‑chip token addresses (ETH mainnet, lowercase)
BLUECHIP_ADDRS = {
    # USDC, USDT, WETH, WBTC, DAI
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
}

def _is_bluechip_addr(addr: str) -> bool:
    try:
        return (addr or "").lower() in BLUECHIP_ADDRS
    except Exception:
        return False

def _hp_cache_get(key, ttl):
    try:
        ent = (_HP_CACHE if key.startswith("ISH:") else _TOPH_CACHE).get(key)
        if ent and time.time() - ent.get("ts", 0) < ttl:
            return ent.get("body")
    except Exception:
        return None

def _hp_cache_put(key, body):
    try:
        cache = _HP_CACHE if key.startswith("ISH:") else _TOPH_CACHE
        cache[key] = {"ts": time.time(), "body": body}
    except Exception:
        pass

def _hp_ish(addr: str, chain_name: str = None) -> dict:
    try:
        addr_l = (addr or "").lower()
        chain_id = CHAIN_NAME_TO_ID.get((chain_name or "").lower())
        key = f"ISH:{addr_l}:{chain_id or 'auto'}"
        cached = _hp_cache_get(key, _HP_TTL)
        if cached is not None:
            return cached
        params = {"address": addr_l}
        if chain_id:
            params["chainID"] = chain_id
        headers = {"User-Agent": os.getenv("USER_AGENT","MetridexBot/1.0")}
        url = f"{HP_API_BASE}/v2/IsHoneypot"
        r = requests.get(url, params=params, headers=headers, timeout=8)
        body = r.json() if hasattr(r,"json") else {}
        if r.status_code != 200:
            body = {}
        _hp_cache_put(key, body)
        return body or {}
    except Exception:
        return {}

def _hp_top_holders(token_or_lp_addr: str, chain_name: str) -> dict:
    try:
        addr_l = (token_or_lp_addr or "").lower()
        chain_id = CHAIN_NAME_TO_ID.get((chain_name or "").lower())
        if not chain_id:
            return {}
        key = f"TOP:{addr_l}:{chain_id}"
        cached = _hp_cache_get(key, _TOPH_TTL)
        if cached is not None:
            return cached
        headers = {"User-Agent": os.getenv("USER_AGENT","MetridexBot/1.0")}
        url = f"{HP_API_BASE}/v1/TopHolders"
        r = requests.get(url, params={"address": addr_l, "chainID": chain_id}, headers=headers, timeout=8)
        body = r.json() if hasattr(r,"json") else {}
        if r.status_code != 200:
            body = {}
        _hp_cache_put(key, body)
        return body or {}
    except Exception:
        return {}

def _percent(n, d, decimals=2):
    try:
        if d and d != 0:
            return round(100.0 * float(n) / float(d), decimals)
    except Exception:
        pass
    return 0.0

def _infer_lp_status(pair_addr: str, chain_name: str) -> dict:
    try:
        data = _hp_top_holders(pair_addr, chain_name) or {}
        holders = data.get("holders") or []
        ts = int(data.get("totalSupply") or 0)
        dead_pct = 0.0
        uncx_pct = 0.0
        tf_pct = 0.0
        top_holder = None
        top_holder_pct = 0.0
        locks_map = {k.lower() for k in (TEAMFINANCE_LOCKERS.get(chain_name.lower()) or [])}
        try:
            _uncx = UNCX_LOCKERS.get(chain_name.lower()) or {}
            for v in _uncx.values():
                locks_map.add(str(v).lower())
        except Exception:
            pass
        for h in holders:
            addr = (h.get("address") or "").lower()
            bal  = int(h.get("balance") or 0)
            pct  = _percent(bal, ts)
            if top_holder is None or pct > top_holder_pct:
                top_holder, top_holder_pct = addr, pct
            if addr in DEAD_ADDRS:
                dead_pct += pct
            elif addr in locks_map:
                if addr in set(map(str.lower, TEAMFINANCE_LOCKERS.get(chain_name.lower()) or [])):
                    tf_pct += pct
                else:
                    uncx_pct += pct
        return {
            "totalSupply": ts,
            "dead_pct": round(dead_pct, 2),
            "uncx_pct": round(uncx_pct, 2),
            "team_finance_pct": round(tf_pct, 2),
            "top_holder": top_holder,
            "top_holder_pct": round(top_holder_pct, 2),
            "holders_count": len(holders)
        }
    except Exception:
        return {}

def _holder_concentration(token_addr: str, chain_name: str) -> dict:
    try:
        data = _hp_top_holders(token_addr, chain_name) or {}
        holders = data.get("holders") or []
        ts = int(data.get("totalSupply") or 0)
        gt5 = 0; gt10 = 0
        top_n = min( len([h for h in holders if int(h.get("balance") or 0) > 0]), 20 )
        top_total = 0
        for h in holders[:top_n]:
            bal = int(h.get("balance") or 0)
            pct = _percent(bal, ts)
            if pct >= 10: gt10 += 1
            if pct >= 5:  gt5  += 1
            top_total += pct
        return {"gt5": gt5, "gt10": gt10, "topN": top_n, "topTotalPct": round(top_total, 2)}
    except Exception:
        return {}

def _ds_resolve_pair_and_chain(addr_l: str) -> tuple:
    try:
        url = f"{DEX_BASE}/latest/dex/tokens/{addr_l}"
        r = requests.get(url, timeout=6, headers={"User-Agent": "metridex-bot"})
        if r.status_code != 200:
            return None, None
        body = r.json() if hasattr(r, "json") else {}
        pairs = body.get("pairs") or []
        p = _ds_pick_best_pair(pairs)
        if not p:
            return None, None
        chain = (p or {}).get("chainId") or (p or {}).get("chain")
        return p, (chain or "").lower()
    except Exception:
        return None, None

try:
    DEX_BASE = os.environ.get("DEX_BASE", "https://api.dexscreener.com").rstrip("/")
except Exception:
    DEX_BASE = "https://api.dexscreener.com"

_DELTA_CACHE = {}  # addr_l -> {"ts": epoch, "changes": {"m5": v, "h1": v, "h6": v, "h24": v}}


def _qs_call_safe(func, *args, **kwargs):
    """Call quickscan entrypoints safely, dropping unsupported kwargs like 'lang'/'lean'."""
    try:
        return func(*args, **kwargs)
    except TypeError:
        # Drop lang/lean if present
        for k in ("lang","lean"):
            if k in kwargs:
                kwargs.pop(k, None)
        try:
            return func(*args, **kwargs)
        except TypeError:
            # Try positional-only
            return func(*args)

def _delta_cache_get(addr_l: str, ttl=60):
    try:
        rec = _DELTA_CACHE.get(addr_l or "")
        if not rec:
            return None
        if time.time() - rec.get("ts", 0) > ttl:
            return None
        return rec.get("changes")
    except Exception:
        return None

def _delta_cache_put(addr_l: str, changes: dict):
    try:
        _DELTA_CACHE[addr_l or ""] = {"ts": time.time(), "changes": changes or {}}
    except Exception:
        pass

def _ds_pick_best_pair(pairs):
    if not isinstance(pairs, list):
        return None
    best = None
    best = None
    best_score = -1.0
    for p in pairs:
        try:
            liq = float((((p or {}).get("liquidity") or {}).get("usd")) or 0.0)
        except Exception:
            liq = 0.0
        ch = ((p or {}).get("priceChange") or {})
        coverage = sum(1 for k in ("m5","h1","h6","h24") if ch.get(k) not in (None, ""))
        on_eth = 1.0 if (p or {}).get("chainId") == "ethereum" else 0.0
        score = coverage * 1e12 + liq * 1e3 + on_eth * 1e2
        if score > best_score:
            best_score = score
            best = p
    return best or (pairs[0] if pairs else None)


def _ds_candle_delta(pair: dict, tf: str) -> tuple:
    """
    Try to compute Δ% from candles when priceChange[tf] is missing.
    Returns (value_str, src_tag) or (None, None).
    """
    try:
        pair_id = (pair or {}).get("pairId") or ""
        chain = (pair or {}).get("chainId") or ""
        addr = (pair or {}).get("pairAddress") or (pair or {}).get("pair") or ""
        endpoints = []
        if pair_id:
            endpoints.append(f"{DEX_BASE}/candles/pairs/{pair_id}?timeframe={tf}&limit=2")
            endpoints.append(f"{DEX_BASE}/candles?pairId={pair_id}&tf={tf}&limit=2")
        if chain and addr:
            endpoints.append(f"{DEX_BASE}/candles/pairs/{chain}/{addr}?timeframe={tf}&limit=2")
        for url in endpoints:
            try:
                r = requests.get(url, timeout=6, headers={"User-Agent": "metridex-bot"})
                if r.status_code != 200:
                    continue
                js = r.json() if hasattr(r, "json") else {}
                candles = js.get("candles") or js.get("data") or js.get("result") or []
                if not isinstance(candles, list) or len(candles) < 2:
                    continue
                c1 = candles[-2]; c2 = candles[-1]
                def _get_close(c):
                    return c.get("c") or c.get("close") or c.get("price") or c.get("last")
                v1 = _get_close(c1); v2 = _get_close(c2)
                v1 = float(v1) if v1 is not None else None
                v2 = float(v2) if v2 is not None else None
                if not v1 or not v2:
                    continue
                pct = (v2 - v1) / v1 * 100.0
                return (("+" if pct>=0 else "") + f"{pct:.2f}%", "calc")
            except Exception:
                continue
        return (None, None)
    except Exception:
        return (None, None)


def _delta_src_tag(changes: dict, key: str) -> str:
    try:
        s = (changes or {}).get(f"_src_{key}") or ""
        return " ·computed" if s == "calc" else ""
    except Exception:
        return ""
def _ds_token_changes(addr_l: str) -> dict:
    if not addr_l:
        return {}
    try:
        cached = _delta_cache_get(addr_l)
        if cached:
            return cached
        url = f"{DEX_BASE}/latest/dex/tokens/{addr_l}"
        r = requests.get(url, timeout=6, headers={"User-Agent": "metridex-bot"})
        if r.status_code != 200:
            return {}
        body = r.json() if hasattr(r, "json") else {}
        pairs = body.get("pairs") or []
        p = _ds_pick_best_pair(pairs)
        changes = (p or {}).get("priceChange") or {}
        out = {}
        for k_src, k_dst in (("m5","m5"), ("h1","h1"), ("h6","h6"), ("h24","h24")):
            v = changes.get(k_src)
            try:
                if v is None or v == "":
                    raise ValueError("no ds value")
                v = float(v)
                out[k_dst] = ("+" if v>=0 else "") + f"{v:.2f}%"
                out[f"_src_{k_dst}"] = "ds"
            except Exception:
                vstr = str(v)
                if v not in (None, ""):
                    if not vstr.endswith("%"):
                        vstr += "%"
                    if not vstr.startswith(("+","-")):
                        vstr = "+" + vstr
                    out[k_dst] = vstr
                    out[f"_src_{k_dst}"] = "ds"
        for tf in ("m5","h1","h6"):
            if not out.get(tf):
                val, src = _ds_candle_delta(p, tf)
                if val:
                    out[tf] = val
                    out[f"_src_{tf}"] = src or "calc"
        if out:
            _delta_cache_put(addr_l, out)
        return out
    except Exception:
        return {}
# ===== /Δ timeframe helpers =====
msg2addr = SafeCache(ttl=86400)                   # message_id -> base address mapping (for Why?)
recent_actions = SafeCache(ttl=20)                # action-level dedupe across messages/taps
RISK_CACHE = {}                                   # addr -> {score,label,neg,pos,w_neg,w_pos}

ADDR_RE = re.compile(r'0x[a-fA-F0-9]{40}')
NEWLINE_ESC_RE = re.compile(r'\\n')

# ========================
# Known homepages (seed)
# ========================
KNOWN_HOMEPAGES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "circle.com",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether.to",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "makerdao.com",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum.org",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "bitcoin.org",
}

# Domain metadata cache
DOMAIN_META_CACHE = {}  # domain -> {t, h, created, reg, exp, issuer, wb}
KNOWN_SOURCES = []
KNOWN_PATHS = []
KNOWN_LAST_CHECK = 0
KNOWN_MTIME = {}
KNOWN_LOCK = threading.Lock()

# ========================
# Whitelists
# ========================
WL_DOMAINS_DEFAULT = {
    "circle.com","tether.to","makerdao.com","frax.finance","binance.com","gemini.com","paxos.com",
    "lido.fi","curve.fi","synthetix.io","liquity.org","paypal.com","firstdigital.com"
}
WL_ADDRESSES_DEFAULT = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0x853d955acef822db058eb8505911ed77f175b99e",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
}
def _env_set(name: str):
    try:
        v = os.getenv(name, "")
        return set([s.strip().lower() for s in v.split(",") if s.strip()])
    except Exception:
        return set()
WL_DOMAINS = set([d.lower() for d in WL_DOMAINS_DEFAULT]) | _env_set("WL_DOMAINS")
WL_ADDRESSES = set([a.lower() for a in WL_ADDRESSES_DEFAULT]) | _env_set("WL_ADDRESSES")

# ========================
# Helpers
# ========================
def _send_text(chat_id, text, **kwargs):
    text = NEWLINE_ESC_RE.sub("\n", text or "")
    return tg_send_message(TELEGRAM_TOKEN, chat_id, text, **kwargs)

def _admin_debug(chat_id, text):
    try:
        if ADMIN_CHAT_ID and str(chat_id) == str(ADMIN_CHAT_ID):
            _send_text(chat_id, f"DEBUG: {text}", logger=app.logger)
    except Exception:
        pass

def require_webhook_secret(fn):
    def wrapper(*args, **kwargs):
        if WEBHOOK_HEADER_SECRET:
            header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if header != WEBHOOK_HEADER_SECRET:
                return ("forbidden", 403)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def require_admin_secret(fn):
    def wrapper(*args, **kwargs):
        if not ADMIN_SECRET:
            return ("forbidden: admin secret not set", 403)
        header = request.headers.get("X-Admin-Secret", "")
        if header != ADMIN_SECRET:
            return ("forbidden", 403)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def _compress_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict):
        return kb
    ik = kb.get("inline_keyboard")
    if not ik:
        return kb
    for row in ik:
        for btn in row:
            data = btn.get("callback_data")
            if not data:
                continue
            if len(data) <= 60 and data.startswith(("qs:","qs2:","more:","less:","why:","rep:","hp:","lp:","mon:","tf:")):
                continue
            h = hashlib.sha1(data.encode("utf-8")).hexdigest()[:10]
            token = f"cb:{h}"
            cb_cache.set(token, data)
            btn["callback_data"] = token

    return _kb_dedupe_all({"inline_keyboard": ik})

def _kb_clone(kb):
    if not kb or not isinstance(kb, dict):
        return {"inline_keyboard": []}
    ik = kb.get("inline_keyboard") or []
    return {"inline_keyboard": [[dict(btn) for btn in row] for row in ik]}

def _kb_strip_prefixes(kb, prefixes):
    base = _kb_clone(kb)
    ik = base["inline_keyboard"]
    out = []
    for row in ik:
        new_row = []
        for btn in row:
            data = (btn.get("callback_data") or "")
            if any(data.startswith(p) for p in prefixes):
                continue
            new_row.append(btn)
        if new_row:
            out.append(new_row)
    return {"inline_keyboard": out}





def _answer_why_deep(cq: dict, addr_hint: str = None):
    try:
        msg = cq.get("message") or {}
        chat_id = int((msg.get("chat") or {}).get("id") or 0)
        if chat_id == 0:
            return
        text = msg.get("text") or ""
        addr = (addr_hint or _extract_addr_from_text(text) or "").lower()
        ent = RISK_CACHE.get(addr) or {}
        neg = list(ent.get("neg") or [])
        pos = list(ent.get("pos") or [])
        wneg = list(ent.get("w_neg") or [])
        wpos = list(ent.get("w_pos") or [])

        if len(wneg) < len(neg):
            wneg = list(wneg) + [10] * (len(neg) - len(wneg))
        if len(wpos) < len(pos):
            wpos = list(wpos) + [10] * (len(pos) - len(wpos))
        def _to_int_or_default(x, default=10):
            try:
                return int(x)
            except Exception:
                return default
        wneg = [_to_int_or_default(w, 10) for w in wneg]
        wpos = [_to_int_or_default(w, 10) for w in wpos]

        is_whitelisted = any("Whitelisted by address" in p for p in pos) or any("Blue-chip pair context" in p for p in pos) or _is_bluechip_addr(addr)
        if is_whitelisted and "Owner privileges present" in neg:
            try:
                idxs = [i for i,r in enumerate(neg) if r == "Owner privileges present"]
                for i in reversed(idxs):
                    neg.pop(i); wneg.pop(i)
                pos.append("Admin privileges expected for centralized/whitelisted token")
                wpos.append(0)
            except Exception:
                pass

        lines = []
        def fmt(items, weights, sign):
            for (reason, w) in zip(items, weights):
                sym = "−" if sign=="neg" else "+"
                w = _to_int_or_default(w, 10)
                lines.append(f"{sym}  {reason}" if (w == 0 or str(w)=="0") else f"{sym}{abs(w):>2}  {reason}")

        fmt(neg, wneg, "neg")

        if neg and pos:

            lines.append("—")

        fmt(pos, wpos, "pos")

        if not lines:
            lines = ["No weighted factors captured yet. Tap 🧪 On-chain first."]
        _send_text(chat_id, "Why++ factors\n" + "\n".join(lines[:40]), logger=app.logger)
    except Exception:
        pass


def _ensure_action_buttons(addr, kb, want_more=False, want_why=True, want_report=True, want_hp=True):
    base = _kb_strip_prefixes(kb, ("more:", "why", "rep:", "hp:"))
    ik = base.get("inline_keyboard") or []
    base = _kb_strip_tf_rows(base)
    ik = base.get("inline_keyboard") or []
    # Add 'More details' only in the first message
    if want_more and addr:
        ik.append([{"text": "🔎 More details", "callback_data": f"more:{addr}"}])
    # Row with Why/Report
    row = []
    if want_why and addr:
        row.append({"text": "❓ Why?", "callback_data": f"why:{addr}"});
        row.append({"text": "ℹ️ Why++", "callback_data": f"why2:{addr}"})
    if want_report and addr:
        row.append({"text": "📄 Report (HTML)", "callback_data": f"rep:{addr}"})
    if row:
        ik.append(row)
    # Separate row for On-chain, only if RPCs configured
    if want_hp and addr:
        try:
            has_rpc = bool(_parse_rpc_urls())
        except Exception:
            has_rpc = False
        if has_rpc:
            ik.append([{"text": "🧪 On-chain", "callback_data": f"hp:{addr}"}])
    # Δ timeframe row (single)
    ik.append([
        {"text": "Δ 5m",  "callback_data": "tf:5"},
        {"text": "Δ 1h",  "callback_data": "tf:1"},
        {"text": "Δ 6h",  "callback_data": "tf:6"},
        {"text": "Δ 24h", "callback_data": "tf:24"},
    ])
    return _kb_dedupe_all({"inline_keyboard": ik})

def _extract_addrs_from_pair_payload(data: str):
    try:
        path, _, _ = data.split(":", 1)[1].partition("?")
        _, _, pair_addr = path.partition("/")
        parts = [p for p in pair_addr.split("-") if ADDR_RE.fullmatch(p)]
        return [p.lower() for p in parts]
    except Exception:
        return []

def _pick_addr(addrs):
    for a in addrs:
        if a.lower() in KNOWN_HOMEPAGES:
            return a.lower()
    return addrs[-1].lower() if addrs else None


def _extract_base_addr_from_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict):
        return None
    ik = kb.get("inline_keyboard") or []
    for row in ik:
        for btn in row or []:
            data = str((btn or {}).get("callback_data") or "")
            # Fast path: any known prefixes ('qs2:', 'qs:', 'more:', 'why:', 'rep:', 'hp:') may carry the addr
            for prefix in ("qs2:","qs:","more:","why:","rep:","hp:"):
                if data.startswith(prefix):
                    payload = data.split(":", 1)[1]
                    # Cut after first ? if present
                    payload = payload.split("?", 1)[0]
                    # Prefer qs2 pair parsing (addr1-addr2)
                    if payload.startswith("/pair/"):
                        addrs = _extract_addrs_from_pair_payload(data)
                        picked = _pick_addr(addrs)
                        if picked:
                            return picked
                    # Extract first address-looking token
                    m = ADDR_RE.search(payload) if hasattr(ADDR_RE, "search") else None
                    if m:
                        return m.group(0).lower()
                    # Fallback: split and test tokens
                    for tok in re.split(r"[,|;/\s]+", payload):
                        if ADDR_RE.fullmatch(tok or ""):
                            return tok.lower()
            # Last resort: search address anywhere in callback_data
            m2 = ADDR_RE.search(data) if hasattr(ADDR_RE, "search") else None
            if m2:
                return m2.group(0).lower()
    return None
def _extract_addr_from_text(s: str):
    if not s:
        return None
    m = list(ADDR_RE.finditer(s))
    return m[-1].group(0).lower() if m else None

def _store_addr_for_message(result_obj, addr: str):
    try:
        if not result_obj or not isinstance(result_obj, dict) or not addr:
            return
        if result_obj.get("ok") and isinstance(result_obj.get("result"), dict):
            mid = str(result_obj["result"].get("message_id"))
            if mid and ADDR_RE.fullmatch(addr):
                msg2addr.set(mid, addr)
    except Exception:
        pass

# ========================
# Known domains file auto-reload
# ========================
def _norm_domain(url: str):
    if not url:
        return None
    try:
        u = urlparse(url.strip())
        host = u.netloc or u.path
        host = (host or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host.strip("/")
    except Exception:
        return None

def _collect_paths():
    paths = [os.path.join(os.path.dirname(__file__), "known_domains.json")]
    envp = os.getenv("KNOWN_DOMAINS_FILE") or os.getenv("KNOWN_DOMAINS_PATH")
    if envp and envp not in paths:
        paths.append(envp)
    return paths

def _merge_known_from(path: str, diag_only=False):
    entry = {"path": path, "exists": False, "loaded": 0, "error": "", "mtime": None}
    try:
        if not path:
            entry["error"] = "empty path"
            return entry
        entry["exists"] = os.path.exists(path)
        if not entry["exists"]:
            return entry
        entry["mtime"] = os.path.getmtime(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = 0
        if not diag_only:
            for k, v in (data or {}).items():
                addr = (k or "").lower().strip()
                if not ADDR_RE.fullmatch(addr):
                    continue
                dom = v[0] if isinstance(v, list) else v
                dom = _norm_domain(dom)
                if dom:
                    KNOWN_HOMEPAGES[addr] = dom
                    merged += 1
        else:
            for k in (data or {}):
                addr = (k or "").lower().strip()
                if ADDR_RE.fullmatch(addr):
                    merged += 1
        entry["loaded"] = merged
        return entry
    except Exception as e:
        entry["error"] = str(e)
        return entry

def _load_known_domains():
    global KNOWN_SOURCES, KNOWN_PATHS, KNOWN_MTIME, KNOWN_LAST_CHECK
    with KNOWN_LOCK:
        KNOWN_PATHS = _collect_paths()
        KNOWN_SOURCES = []
        for p in KNOWN_PATHS:
            e = _merge_known_from(p, diag_only=False)
            KNOWN_SOURCES.append(e)
            if e["exists"]:
                KNOWN_MTIME[p] = e["mtime"]
        KNOWN_LAST_CHECK = time.time()

def _maybe_reload_known(force=False):
    global KNOWN_LAST_CHECK
    now = time.time()
    if not force and (KNOWN_AUTORELOAD_SEC <= 0 or now - KNOWN_LAST_CHECK < KNOWN_AUTORELOAD_SEC):
        return
    with KNOWN_LOCK:
        KNOWN_LAST_CHECK = now
        paths = _collect_paths()
        changed = False
        for p in paths:
            try:
                m = os.path.getmtime(p)
                if KNOWN_MTIME.get(p) != m:
                    changed = True
            except Exception:
                if p in KNOWN_MTIME:
                    changed = True
        if not changed and set(paths) == set(KNOWN_PATHS):
            return
        KNOWN_PATHS[:] = paths
        KNOWN_SOURCES.clear()
        for p in KNOWN_PATHS:
            e = _merge_known_from(p, diag_only=False)
            KNOWN_SOURCES.append(e)
            if e["exists"]:
                KNOWN_MTIME[p] = e["mtime"]

_load_known_domains()

# ========================
# Domain meta (RDAP/SSL/WB)
# ========================
def _normalize_date_iso(s: str):
    try:
        if not s or s == "—":
            return "—"
        s = s.strip()
        m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
        if m:
            return m.group(1)
        try:
            dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            pass
        m = re.match(r"^(\d{4})(\d{2})(\d{2})", s)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        return s
    except Exception:
        return s or "—"

def _normalize_registrar(reg: str, handle: str, domain: str):
    reg = reg or "—"
    h = (handle or "").upper()
    if "GOVERNMENT OF KINGDOM OF TONGA" in reg.upper() or "TONIC" in h or domain.endswith(".to"):
        return "Tonic (.to)"
    return reg

def _rdap(domain: str):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=HTTP_TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200:
            return ("—", "—", "—")
        j = r.json()
        handle = j.get("handle") or "—"
        created = "—"
        for ev in j.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate", "—")
                break
        registrar = "—"
        for ent in j.get("entities", []):
            if (ent.get("roles") or []) and "registrar" in ent["roles"]:
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) == 2:
                    for item in v[1]:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break
        return (handle, created, registrar)
    except Exception:
        return ("—", "—", "—")

def _ssl_info(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp = cert.get("notAfter", "—")
        issuer = cert.get("issuer", [])
        cn = "—"
        for tup in issuer:
            for k, v in tup:
                if k.lower() == "commonName".lower():
                    cn = v
                    break
        return (_normalize_date_iso(exp), cn)
    except Exception:
        return ("—", "—")

def _wayback_available(domain: str):
    try:
        headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
        for scheme in ("http", "https"):
            url = "https://archive.org/wayback/available"
            params = {"url": f"{scheme}://{domain}/", "timestamp": "19960101"}
            r = requests.get(url, params=params, timeout=6, headers=headers)
            if r.status_code != 200:
                continue
            j = r.json() or {}
            snap = (j.get("archived_snapshots") or {}).get("closest") or {}
            ts = snap.get("timestamp")
            if ts and len(ts) >= 8:
                return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass
    return None

def _wayback_cdx(domain: str, require_200: bool):
    headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
    for host in (domain, f"www.{domain}"):
        for scheme in ("http", "https"):
            for path in (f"{scheme}://{host}/*", f"{scheme}://{host}/"):
                try:
                    params = {
                        "url": path,
                        "output": "json",
                        "fl": "timestamp,statuscode,original",
                        "limit": "1",
                        "from": "1996",
                        "to": "2035",
                        "collapse": "timestamp:8"
                    }
                    if require_200:
                        params["filter"] = "statuscode:200"
                    r = requests.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=8, headers=headers)
                    if r.status_code != 200:
                        continue
                    j = r.json()
                    if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and len(j[1]) >= 1:
                        ts = str(j[1][0])
                        if len(ts) >= 8:
                            return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
                except Exception:
                    continue
    return None

def _wayback_first(domain: str):
    try:
        d = _wayback_cdx(domain, require_200=True)
        if d:
            return d
        d = _wayback_cdx(domain, require_200=False)
        if d:
            return d
        d = _wayback_available(domain)
        return d or "—"
    except Exception:
        return "—"

def _domain_meta(domain: str):
    now = int(time.time())
    ent = DOMAIN_META_CACHE.get(domain)
    if ent:
        ttl = DOMAIN_META_TTL_NEG if ent.get("wb") in (None, "—") else DOMAIN_META_TTL
        if now - ent.get("t", 0) < ttl:
            return ent["h"], ent["created"], ent["reg"], ent["exp"], ent["issuer"], ent.get("wb", "—")
    h, created, reg = _rdap(domain)
    exp, issuer = _ssl_info(domain)
    wb = _wayback_first(domain)
    created = _normalize_date_iso(created)
    reg = _normalize_registrar(reg, h, domain)
    DOMAIN_META_CACHE[domain] = {"t": now, "h": h, "created": created, "reg": reg, "exp": exp, "issuer": issuer, "wb": wb}
    return h, created, reg, exp, issuer, wb

def _cg_homepage(addr: str):
    addr_l = (addr or "").lower()
    if addr_l in KNOWN_HOMEPAGES:
        return KNOWN_HOMEPAGES[addr_l]
    try:
        url = f"https://api.coingecko.com/api/v3/coins/ethereum/contract/{addr_l}"
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200:
            return None
        data = r.json()
        hp = (data.get("links") or {}).get("homepage") or []
        for u in hp:
            d = _norm_domain(u)
            if d:
                return d
    except Exception:
        return None
    return None

def _symbol_homepage_hint(text: str):
    t = (text or "").upper()
    hints = [
        ("USDT", "tether.to"),
        ("USDC", "circle.com"),
        ("DAI", "makerdao.com"),
        ("TUSD", "tusd.io"),
        ("FRAX", "frax.finance"),
        ("WBTC", "wbtc.network"),
        ("ETH", "ethereum.org"),
        ("BUSD", "binance.com"),
        ("USDP", "paxos.com"),
        ("GUSD", "gemini.com"),
        ("PYUSD", "paypal.com"),
        ("FDUSD", "firstdigital.com"),
        ("LUSD", "liquity.org"),
        ("SUSD", "synthetix.io"),
        ("CRVUSD", "curve.fi"),
        ("USDE", "ether.fi"),
    ]
    for sym, dom in hints:
        if sym in t:
            return dom
    return None

def _extract_domain_from_text(text: str):
    try:
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("Domain:"):
                dom = line.split(":", 1)[1].strip()
                if dom and (" " not in dom) and ("." in dom):
                    return dom
    except Exception:
        return None
    return None

# ========================
# Risk engine (weighted)
# ========================
try:
    RISK_LIQ_LOW = float(os.getenv("RISK_LIQ_LOW", "20000"))      # <$20k => +25
    RISK_LIQ_MED = float(os.getenv("RISK_LIQ_MED", "100000"))     # <$100k => +10
    RISK_VOL_LOW = float(os.getenv("RISK_VOL_LOW", "5000"))       # <  $5k => +10
    RISK_THRESH_CAUTION = int(os.getenv("RISK_THRESH_CAUTION", "30"))
    RISK_THRESH_HIGH    = int(os.getenv("RISK_THRESH_HIGH", "60"))
    RISK_POSITIVE_LIQ   = float(os.getenv("RISK_POSITIVE_LIQ", "1000000"))  # >$1M => positive
    RISK_POSITIVE_AGE_Y = int(os.getenv("RISK_POSITIVE_AGE_Y", "2018"))     # domain created <=2018 => positive
except Exception:
    RISK_LIQ_LOW = 20000.0; RISK_LIQ_MED = 100000.0; RISK_VOL_LOW = 5000.0
    RISK_THRESH_CAUTION = 30; RISK_THRESH_HIGH = 60
    RISK_POSITIVE_LIQ = 1_000_000.0; RISK_POSITIVE_AGE_Y = 2018

def _parse_float_km(s):
    try:
        s = (s or "").strip().upper().replace("$","")
        m = re.match(r'^([0-9]+(?:\.[0-9]+)?)\s*([KMB])?$', s)
        if not m:
            return None
        num = float(m.group(1))
        suf = m.group(2) or ""
        mult = {"K":1e3, "M":1e6, "B":1e9}.get(suf, 1.0)
        return num * mult
    except Exception:
        return None

def _parse_metric_from_dexline(text, key):
    try:
        patt = rf'{key}\s+([0-9\.\$]+\s*[KMB]?)'
        m = re.search(patt, text, re.IGNORECASE)
        return _parse_float_km(m.group(1)) if m else None
    except Exception:
        return None

def _parse_bool(text, key):
    try:
        m = re.search(rf'{re.escape(key)}:\s*(✅|✔️|Yes|True|No|❌|—)', text, re.IGNORECASE)
        if not m:
            return None
        val = m.group(1)
        return val in ("✅","✔️","Yes","True")
    except Exception:
        return None

def _parse_roles(text):
    roles = {}
    try:
        m = re.search(r'Roles:\s*([^\n]+)', text)
        if not m:
            return roles
        chunk = m.group(1)
        for pair in re.split(r'\s*\|\s*', chunk):
            kv = pair.split(":", 1)
            if len(kv) == 2:
                roles[kv[0].strip()] = ("✅" in kv[1]) or ("✔" in kv[1]) or ("Yes" in kv[1])
        return roles
    except Exception:
        return roles

def _parse_domain_meta(block):
    d = {"created": None, "registrar": None, "ssl_exp": None, "wayback": None}
    try:
        m = re.search(r'Created:\s*([0-9\-TZ: ]+)', block); d["created"] = m.group(1) if m else None
        m = re.search(r'Registrar:\s*([^\n]+)', block); d["registrar"] = m.group(1).strip() if m else None
        m = re.search(r'Expires:\s*([0-9\-TZ: ]+)', block); d["ssl_exp"] = m.group(1) if m else None
        m = re.search(r'Wayback:\s*first\s+([0-9\-—]+)', block); d["wayback"] = m.group(1) if m else None
    except Exception:
        pass
    return d

def _is_whitelisted(addr: str, text: str):
    try:
        a = (addr or "").lower()
        if a in WL_ADDRESSES:
            return True, "address"
        dom = _extract_domain_from_text(text) or ""
        if dom.lower() in WL_DOMAINS:
            return True, "domain"
    except Exception:
        pass
    return False, None

def _risk_verdict(addr, text):
    score = 0
    neg = []
    pos = []
    weights_neg = []
    weights_pos = []
    whitelisted, wl_type = _is_whitelisted(addr, text)

    liq = _parse_metric_from_dexline(text, "Liq")
    vol = _parse_metric_from_dexline(text, "Vol24h")
    if liq is not None:
        if liq < RISK_LIQ_LOW:
            w = (8 if whitelisted else 25); score += w; neg.append("Low liquidity (<${:,})".format(int(RISK_LIQ_LOW))); weights_neg.append(w)
        elif liq < RISK_LIQ_MED:
            w = (3 if whitelisted else 10); score += w; neg.append("Moderate liquidity (<${:,})".format(int(RISK_LIQ_MED))); weights_neg.append(w)
        elif liq >= RISK_POSITIVE_LIQ:
            w = 15; pos.append("High liquidity (≥${:,})".format(int(RISK_POSITIVE_LIQ))); weights_pos.append(w)
    if vol is not None and vol < RISK_VOL_LOW:
        w = 10; score += w; neg.append("Very low 24h volume (<$5k)"); weights_neg.append(w)

    t_upper = (text or "").upper()
    if whitelisted:
        w = 20; pos.append(f"Whitelisted by {wl_type}"); weights_pos.append(w)
    if ("USDT" in t_upper and "USDC" in t_upper) or ("WBTC" in t_upper and "ETH" in t_upper):
        w = 10; pos.append("Blue-chip pair context"); weights_pos.append(w)

    proxy = _parse_bool(text, "Proxy")
    if proxy is True:
        w = (0 if whitelisted else 15); score += w; neg.append("Upgradeable proxy (owner can change logic)"); weights_neg.append(w)

    roles = _parse_roles(text)
    if roles.get("owner", False):
        w = (0 if whitelisted else 20); score += w; neg.append("Owner privileges present"); weights_neg.append(w)
    if roles.get("blacklister", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Blacklisting capability"); weights_neg.append(w)
    if roles.get("pauser", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Pausing capability"); weights_neg.append(w)
    if roles.get("minter", False) or roles.get("masterMinter", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Minting capability"); weights_neg.append(w)

    dom = _parse_domain_meta(text)
    try:
        if dom.get("created") and dom["created"] != "—":
            y = int(dom["created"][:4])
            if y >= 2024:
                w = 15; score += w; neg.append("Very new domain"); weights_neg.append(w)
            elif y >= 2022:
                w = 5; score += w; neg.append("Newish domain"); weights_neg.append(w)
            elif y <= RISK_POSITIVE_AGE_Y:
                w = 10; pos.append(f"Established domain (≤{RISK_POSITIVE_AGE_Y})"); weights_pos.append(w)
        if dom.get("wayback") in (None, "—"):
            if not whitelisted:
                w = 5; score += w; neg.append("No Wayback snapshots"); weights_neg.append(w)
            else:
                w = 8; pos.append("Trusted (no WB penalty)"); weights_pos.append(w)
        else:
            w = 8; pos.append("Historical presence (Wayback found)"); weights_pos.append(w)
    except Exception:
        pass

    if score >= RISK_THRESH_HIGH:
        label = "HIGH RISK 🔴"
    elif score >= RISK_THRESH_CAUTION:
        label = "CAUTION 🟡"
    else:
        label = "LOW RISK 🟢"

    # --- Whitelist post-filter: drop zero-weight negatives and add a single positive marker ---
    try:
        if whitelisted or vars().get('is_whitelisted') or vars().get('whitelist_hit'):
            # normalize containers
            neg_list = neg if 'neg' in locals() else []
            wneg_list = weights_neg if 'weights_neg' in locals() else []
            pos_list = pos if 'pos' in locals() else []
            wpos_list = weights_pos if 'weights_pos' in locals() else []
    
            # remove zero-weight negatives
            neg2, wneg2 = [], []
            for r, w in zip(neg_list, wneg_list):
                try:
                    wi = int(w)
                except Exception:
                    wi = 10
                if wi > 0:
                    neg2.append(r); wneg2.append(w)
            neg, weights_neg = neg2, wneg2
    
            # add expected-admin positive once
            expected_msg = "Admin privileges expected for centralized/whitelisted token"
            if not any(expected_msg in p for p in pos_list):
                pos_list.append(expected_msg); wpos_list.append(0)
    
            pos, weights_pos = pos_list, wpos_list
    except NameError:
        pass
    
    return int(min(100, score)), label, {"neg": neg, "pos": pos, "w_neg": weights_neg, "w_pos": weights_pos}


def _wrap_kv_line(prefix: str, items, width: int = 96, indent: int = 2) -> str:
    """Wrap a 'Key: a; b; c; ...' line across multiple lines,
    keeping words intact and indenting continuation lines."""
    try:
        items = [str(x) for x in (items or []) if str(x).strip()]
        if not items:
            return f"{prefix}: n/a"
        head = f"{prefix}: "
        avail = max(20, width) - len(head)
        out_lines = []
        cur = ""
        for i, it in enumerate(items):
            sep = "" if i == 0 else "; "
            token = sep + it
            if len(cur) + len(token) <= avail:
                cur += token
            else:
                out_lines.append(head + cur)
                head = " " * (len(prefix) + 2 + indent)
                avail = max(20, width) - len(head)
                cur = it
        if cur:
            out_lines.append(head + cur)
        return "\n".join(out_lines)
    except Exception:
        return f"{prefix}: " + "; ".join(items or [])
def _append_verdict_block(addr, text):
    score, label, rs = _risk_verdict(addr, text)
    try:
        RISK_CACHE[(addr or "").lower()] = {
            "score": score, "label": label,
            "neg": rs.get("neg", []), "pos": rs.get("pos", []),
            "w_neg": rs.get("w_neg", []), "w_pos": rs.get("w_pos", [])
        }
    except Exception:
        pass
    lines = [f"Trust verdict: {label} (score {score}/100)"]
    if rs.get("neg"):
        lines.append(_wrap_kv_line("⚠️ Signals", rs.get("neg")))
    if rs.get("pos"):
        lines.append(_wrap_kv_line("✅ Positives", rs.get("pos")))
    return text + "\n" + "\n".join(lines)

# ========================
# On-chain lite inspector (ETH RPC)
# ========================
# --- RPC provider list & failover ---
_RPC_LAST_GOOD = 0

def _mask_host(u: str):
    try:
        o = urlparse(u)
        return (o.hostname or u).split('@')[-1]
    except Exception:
        return u

def _parse_rpc_urls():
    urls = []
    # Primary single URL
    primary = os.environ.get("ETH_RPC_URL", "").strip()
    if primary:
        urls.append(primary)
    # Indexed URLs: ETH_RPC_URL1..ETH_RPC_URL6 (accept up to 12)
    for i in range(1, 13):
        val = os.environ.get(f"ETH_RPC_URL{i}", "").strip()
        if val:
            urls.append(val)
    # Comma-separated list
    extra = os.environ.get("ETH_RPC_URLS", "").strip()
    if extra:
        urls.extend([u.strip() for u in extra.split(",") if u.strip()])
    # Dedupe, keep order
    seen = set()
    ordered = []
    for u in urls:
        if u and u not in seen:
            ordered.append(u); seen.add(u)
    return ordered

def _rpc_call(method, params):
    urls = _parse_rpc_urls()
    if not urls:
        raise RuntimeError("ETH_RPC_URL(S) not configured")
    global _RPC_LAST_GOOD
    # Start from last known good
    order = list(range(len(urls)))
    if 0 <= _RPC_LAST_GOOD < len(urls):
        order = order[_RPC_LAST_GOOD:] + order[:_RPC_LAST_GOOD]
    last_err = None
    for idx in order:
        url = urls[idx]
        try:
            payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            r = requests.post(url, json=payload, timeout=8, headers={"Content-Type":"application/json"})
            j = r.json()
            if "error" in j:
                last_err = RuntimeError(f"RPC {method} error from {_mask_host(url)}: {j['error']}")
                continue
            res = j.get("result")
            if res in (None, "", []):
                last_err = RuntimeError(f"RPC {method} null/empty result from {_mask_host(url)}")
                continue
            _RPC_LAST_GOOD = idx
            return res
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"All RPC providers failed for {method}: {type(last_err).__name__}: {last_err}")

def _eth_getCode(addr):
    return _rpc_call("eth_getCode", [addr, "latest"])

def _eth_getStorageAt(addr, slot):
    return _rpc_call("eth_getStorageAt", [addr, slot, "latest"])

def _eth_call(addr, data, from_addr=None):
    callobj = {"to": addr, "data": data}
    if from_addr:
        callobj["from"] = from_addr
    return _rpc_call("eth_call", [callobj, "latest"])

# Known selectors (precomputed)
SEL_NAME            = "0x06fdde03"
SEL_SYMBOL          = "0x95d89b41"
SEL_DECIMALS        = "0x313ce567"
SEL_TOTAL_SUPPLY    = "0x18160ddd"
SEL_BALANCE_OF      = "0x70a08231"
SEL_OWNER           = "0x8da5cb5b"
SEL_GET_OWNER       = "0x8f32d59b"  # may fail; optional
SEL_PAUSED          = "0x5c975abb"

def _dec_uint(hexstr: str):
    try:
        return int(hexstr, 16)
    except Exception:
        return None

def _dec_bool32(hexstr: str):
    return _dec_uint(hexstr) == 1

def _dec_address32(hexstr: str):
    hx = hexstr[-40:]
    return "0x"+hx

def _dec_string(ret: str):
    # Robust ABI string decoder: supports dynamic string and bytes32 fallback
    try:
        if not ret or ret == "0x":
            return None
        data_hex = ret[2:]
        data = bytes.fromhex(data_hex)
        # Try dynamic string: [offset][...][len][bytes]
        if len(data) >= 96:
            off = int.from_bytes(data[0:32], 'big')
            if 0 <= off <= len(data) - 32:
                ln = int.from_bytes(data[off:off+32], 'big')
                start = off + 32
                end = start + ln
                if 0 <= ln <= len(data) and end <= len(data):
                    s = data[start:end]
                    try:
                        return s.decode('utf-8', errors='replace').rstrip('\x00')
                    except Exception:
                        pass
        # Fallback: bytes32-as-string (some older tokens)
        if len(data) >= 32:
            s = data[0:32].decode('utf-8', errors='replace').split('\x00')[0]
            s = s.strip()
            if s:
                return s
        return None
    except Exception:
        return None

def _format_supply(ts, decimals):
    try:
        if ts is None or decimals is None:
            return None
        if decimals < 0 or decimals > 36:
            return None
        human = ts / (10 ** decimals)
        if human >= 1e9:
            return f"{human:,.3f}"
        else:
            return f"{human:,.6g}"
    except Exception:
        return None

def _call_str(addr, selector):
    try:
        ret = _eth_call(addr, selector)
        return _dec_string(ret)
    except Exception:
        return None

def _call_u8(addr, selector):
    try:
        ret = _eth_call(addr, selector)
        if not ret or ret=="0x": return None
        return _dec_uint(ret[2+64-2:2+64])
    except Exception:
        return None


def _call_bytes32(addr: str, selector_hex: str):
    try:
        data = selector_hex if selector_hex.startswith("0x") else ("0x" + selector_hex)
        out = _eth_call(addr, data)
        if out and isinstance(out, str) and out.startswith("0x") and len(out) >= 66:
            return out[:66]
        return None
    except Exception:
        return None

def _call_u256(addr, selector):
    try:
        ret = _eth_call(addr, selector)
        if not ret or ret=="0x": return None
        return _dec_uint(ret[2:])
    except Exception:
        return None

def _call_bool(addr, selector):
    try:
        ret = _eth_call(addr, selector)
        if not ret or ret=="0x": return None
        return _dec_bool32(ret[2:66])
    except Exception:
        return None

def _call_owner(addr):
    # try owner() then getOwner()
    try:
        ret = _eth_call(addr, SEL_OWNER)
        if ret and len(ret)>=66:
            return _dec_address32(ret[2:66])
    except Exception:
        pass
    try:
        ret = _eth_call(addr, SEL_GET_OWNER)
        if ret and len(ret)>=66:
            return _dec_address32(ret[2:66])
    except Exception:
        pass
    return None

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def _fmt_int(v):
    try:
        n = int(v)
        return f"{n:,}"
    except Exception:
        try:
            f = float(v)
            return f"{f:,.0f}"
        except Exception:
            return str(v)

def _short_addr(a: str, take: int = 6) -> str:
    try:
        a = str(a or "")
        if len(a) <= 2 + take*2:
            return a
        return a[:2+take] + "…" + a[-take:]
    except Exception:
        return a
def _onchain_inspect(addr: str):
    info = {}
    out = []

    # info reset removed by patch
# --- Honeypot.is simulation & LP/holders ---
    try:
        pair_from_ds, chain_name = _ds_resolve_pair_and_chain(addr)
    except Exception:
        pair_from_ds, chain_name = None, None
    hp = _hp_ish(addr, chain_name=chain_name) if ADDR_RE.fullmatch(addr or "") else {}
    if hp:
        sim_ok = hp.get("simulationSuccess", False)
        out.append(f"Honeypot.is: simulation={'OK' if sim_ok else 'FAIL'} | risk={((hp.get('summary') or {}).get('risk') or '—')} | level={((hp.get('summary') or {}).get('riskLevel') or '—')}")
        sim = hp.get("simulationResult") or {}
        bt = sim.get("buyTax"); st = sim.get("sellTax"); tt = sim.get("transferTax")
        if bt is not None or st is not None or tt is not None:
            ## FIXED4 CONTEXT: detect blue-chip / whitelist / liquidity
            liq_usd = None
            try:
                _p, _chain = _ds_resolve_pair_and_chain(addr)
                if _p:
                    liq_usd = ((_p.get('liquidity') or {}).get('usd'))
            except Exception:
                pass
            _cache_ent = RISK_CACHE.get((addr or '').lower()) or {}
            _pos = _cache_ent.get('pos') or []
            is_whitelisted = any('Whitelisted by address' in p for p in _pos) or any('Blue-chip pair context' in p for p in _pos) or _is_bluechip_addr(addr)

            out.append(f"Taxes: buy={bt if bt is not None else '—'}% | sell={st if st is not None else '—'}% | transfer={tt if tt is not None else '—'}%")
        if not sim_ok and hp.get("simulationError"):
            try:
                if ("is_whitelisted" in locals() and is_whitelisted) or ("liq_usd" in locals() and (liq_usd is not None) and isinstance(liq_usd,(int,float)) and liq_usd >= 1_000_000):
                    out.append("Honeypot quick-test: ℹ️ skipped DEX simulation (blue-chip/centralized)")
                else:
                    out.append("Honeypot quick-test: ⚠️ static only (no DEX sell simulation)")
            except Exception:
                out.append("Honeypot quick-test: ⚠️ static only (no DEX sell simulation)")
            
            out.append(f"SimError: {str(hp.get('simulationError'))[:140]}")
        info['hp'] = {"risk": ((hp.get('summary') or {}).get('risk')),
                      "riskLevel": ((hp.get('summary') or {}).get('riskLevel')),
                      "isHoneypot": ((hp.get('honeypotResult') or {}).get('isHoneypot')),
                      "buyTax": bt, "sellTax": st, "transferTax": tt}
        pair_addr = ((hp.get("pair") or {}).get("pair") or {}).get("address") or (pair_from_ds or {}).get("pairAddress")
        if pair_addr and chain_name:
            lp = _infer_lp_status(pair_addr, chain_name)
            if lp:
                out.append(f"LP: burned={lp.get('dead_pct',0)}% | UNCX={lp.get('uncx_pct',0)}% | TeamFinance={lp.get('team_finance_pct',0)}% | topHolder={lp.get('top_holder_pct',0)}%")
                info['lp'] = lp
            conc = _holder_concentration(addr, chain_name)
            if conc:
                out.append(f"Holders: top{conc.get('topN',0)} own {conc.get('topTotalPct',0)}% | >10% addrs: {conc.get('gt10',0)} | >5% addrs: {conc.get('gt5',0)}")
                info['holders'] = conc
    
        urls = _parse_rpc_urls()
    if not urls:
        return "On-chain: not configured (set ETH_RPC_URL or ETH_RPC_URL1..N or ETH_RPC_URLS)", {}
    try:
        addr = addr.lower()
        out = []
        info = {}
        code = _eth_getCode(addr)
        is_contract = code and code != "0x"
        info["is_contract"] = bool(is_contract)
        out.append(f"Contract code: {'present' if is_contract else 'absent'}")
        if not is_contract:
            return "\n".join(out), info

        # ERC20 basics
        name  = _call_str(addr, SEL_NAME)
        symbol= _call_str(addr, SEL_SYMBOL)
        dec   = _call_u8(addr, SEL_DECIMALS)
        ts    = _call_u256(addr, SEL_TOTAL_SUPPLY)
        info.update({"name": name, "symbol": symbol, "decimals": dec, "total_supply": ts})

        if name or symbol:
            out.append(f"Token: {name or '?'} ({symbol or '?'})")
        if dec is not None:
            out.append(f"Decimals: {dec}")
        if ts is not None and dec is not None:
            fmt = _format_supply(ts, dec)
            if fmt is not None:
                out.append(f"Total supply: ~{fmt}")

        # Ownership
        owner = _call_owner(addr)
        if owner:
            info["owner"] = owner
            out.append(f"Owner: {_short_addr(owner)}")
        paused = _call_bool(addr, SEL_PAUSED)
        if paused is True:
            out.append("Paused: ✅")
            info["paused"] = True
        elif paused is False:
            out.append("Paused: ❌")
            info["paused"] = False

        # Proxy detection by storage slots
        impl = _eth_getStorageAt(addr, EIP1967_IMPL_SLOT)
        beacon = _eth_getStorageAt(addr, EIP1967_BEACON_SLOT)
        admin = _eth_getStorageAt(addr, EIP1967_ADMIN_SLOT)
        proxy = False
        if impl and impl != "0x" and impl != "0x" + ("0"*64):
            impl_addr = "0x" + impl[-40:]
            out.append(f"EIP-1967 impl: {impl_addr}")
            info["impl"] = impl_addr
            proxy = True
        if beacon and beacon != "0x" and beacon != "0x" + ("0"*64):
            beacon_addr = "0x" + beacon[-40:]
            out.append(f"EIP-1967 beacon: {beacon_addr}")
            info["beacon"] = beacon_addr
            proxy = True
        if admin and admin != "0x" and admin != "0x" + ("0"*64):
            admin_addr = "0x" + admin[-40:]
            out.append(f"EIP-1967 admin: {admin_addr}")
            info["admin"] = admin_addr
            proxy = True or proxy
        info["proxy"] = proxy
        if proxy:
            out.append("Proxy: ✅ (upgrade risk)")

        # Honeypot note (static)
        out.append("Honeypot quick-test: ⚠️ static only (no DEX sell simulation)")

        return "\n".join(out), info
    except Exception as e:
        return f"On-chain error: {type(e).__name__}: {e}", {"error": str(e)}
def _merge_onchain_into_risk(addr: str, info: dict):
    try:
        key = (addr or "").lower()
        if not key:
            return
        entry = RISK_CACHE.get(key) or {"score": 0, "label": "LOW RISK 🟢", "neg": [], "pos": [], "w_neg": [], "w_pos": []}
        # Address-level whitelist: de-weight negatives
        is_wl_addr = key in WL_ADDRESSES
        def W(w):
            return 0 if is_wl_addr else w

        added = False
        def add_neg(reason, weight):
            nonlocal added
            if not reason:
                return
            if reason not in entry["neg"]:
                entry["neg"].append(reason)
                entry["w_neg"].append(weight)
                entry["score"] = int(min(100, entry.get("score", 0) + (weight or 0)))
                added = True

        # Merge proxy/paused/owner (weights adapt to whitelist)
        if info.get("proxy"):
            add_neg("Upgradeable proxy (owner can change logic)", W(15))
        if info.get("paused") is True:
            add_neg("Contract is paused", W(20))
        if info.get("owner"):
            add_neg("Owner privileges present", W(20))
        # Honeypot.is based signals
        try:
            hp = info.get("hp") or {}
            if hp.get("isHoneypot"):
                add_neg("Honeypot detected by Honeypot.is", W(90))
            rl = hp.get("riskLevel")
            if isinstance(rl, (int, float)) and rl >= 80:
                add_neg(f"Honeypot.is risk level {rl}", W(40))
            for k, label in (("buyTax","High buy tax"), ("sellTax","High sell tax"), ("transferTax","High transfer tax")):
                v = hp.get(k)
                if isinstance(v, (int,float)):
                    if v >= 25:
                        add_neg(f"{label}: {v}%", W(35))
                    elif v >= 10:
                        add_neg(f"{label}: {v}%", W(20))
        except Exception:
            pass

        # LP lock/burn inference
        try:
            lp = info.get("lp") or {}
            dead = lp.get("dead_pct") or 0.0
            uncx = lp.get("uncx_pct") or 0.0
            tf   = lp.get("team_finance_pct") or 0.0
            topH = lp.get("top_holder_pct") or 0.0
            if dead >= 50:
                add_pos(f"LP burned: {dead}% in dead/zero addresses", 25)
            if (uncx + tf) >= 50:
                add_pos(f"LP locked via lockers: {round(uncx+tf,2)}%", 20)
            if topH >= 40 and (uncx + tf + dead) < 30:
                add_neg(f"LP concentrated in a single holder: {topH}%", W(30))
        except Exception:
            pass

        # Holder concentration (token)
        try:
            hc = info.get("holders") or {}
            if (hc.get("gt10") or 0) >= 2:
                add_neg(f"Many large holders (>=10%): {hc.get('gt10')}", W(25))
            elif (hc.get("gt5") or 0) >= 5:
                add_neg(f"Top holders concentration (>=5%): {hc.get('gt5')}", W(15))
            top_total = hc.get("topTotalPct")
            if isinstance(top_total, (int,float)) and top_total >= 80:
                add_neg(f"Top holders (top {hc.get('topN')}) own {top_total}%", W(25))
        except Exception:
            pass

# Recompute label
        if entry["score"] >= RISK_THRESH_HIGH:
            entry["label"] = "HIGH RISK 🔴"
        elif entry["score"] >= RISK_THRESH_CAUTION:
            entry["label"] = "CAUTION 🟡"
        else:
            entry["label"] = "LOW RISK 🟢"
        if added:
            RISK_CACHE[key] = entry
    except Exception:
        pass

# ========================
# Report (HTML)
# ========================
def _tg_send_document(token: str, chat_id: int, filepath: str, caption: str = None):
    try:
        url = f"https://api.telegram.org/bot{token}/sendDocument"
        with open(filepath, "rb") as f:
            files = {"document": (os.path.basename(filepath), f, "text/html")}
            data = {"chat_id": chat_id}
            if caption:
                data["caption"] = caption[:1000]
            r = requests.post(url, data=data, files=files, timeout=20)
        try:
            return True, r.json()
        except Exception:
            return False, {"ok": False, "status": r.status_code}
    except Exception as e:
        return False, {"ok": False, "error": str(e)}

def _render_report(addr: str, text: str):
    text = _enrich_full(addr, text)
    info = RISK_CACHE.get((addr or "").lower()) or {}
    neg = info.get("neg") or []
    pos = info.get("pos") or []
    wn = info.get("w_neg") or []
    wp = info.get("w_pos") or []
    def lines(items, weights):
        out = []
        for i, t in enumerate(items):
            w = weights[i] if i < len(weights) else None
            out.append(f"- {t}" + (f" (+{w})" if isinstance(w, (int, float)) else ""))
        return "\n".join(out) if out else "—"
    dom = _extract_domain_from_text(text) or "—"
    # Parse pair/dex/chain from the first lines
    pair = None; dex = None; chain = None
    m = re.search(r"^\s*([A-Za-z0-9_\-\.\/]+)\s+on\s+([A-Za-z0-9_\-\.]+)\s*\(([^)]+)\)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        pair, dex, chain = m.group(1), m.group(2), m.group(3)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Metridex Report — {addr}</title>
<style>body{{font-family:Arial,Helvetica,sans-serif;max-width:900px;margin:20px auto;}}h1,h2{{margin:0.5em 0}}.box{{border:1px solid #ddd;padding:12px;border-radius:8px;margin:12px 0;white-space:pre-wrap}}</style>
</head><body>
<h1>Metridex QuickScan — Report</h1>
<div class="box"><b>Generated:</b> {ts}<br><b>Address:</b> {addr}<br>""" + (f"<b>Pair:</b> {pair} " if pair else "") + (f"<b>on:</b> {dex} " if dex else "") + (f"<b>Chain:</b> {chain}<br>" if chain else "<br>") + f"""<b>Domain:</b> {dom}""" + (f"<br><b>Scanner:</b> {SCANNER_URL}" if SCANNER_URL else "") + """</div>
<div class="box"><h2>Summary</h2><pre>""" + text + """</pre></div>
<div class="box"><h2>Risk verdict</h2><p><b>""" + str(info.get('label','?')) + " (" + str(info.get('score','?')) + """/100)</b></p>
<h3>Signals</h3><pre>""" + lines(neg, wn) + """</pre><h3>Positives</h3><pre>""" + lines(pos, wp) + """</pre></div>
<footer><small>Generated by Metridex</small></footer>
</body></html>"""
    try:
        tsf = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_addr = (addr or "unknown")[:10]
        filename = f"metridex_report_{safe_addr}_{tsf}.html"
        path = os.path.join(tempfile.gettempdir(), filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path, html
    except Exception:
        return None, html

# ========================
# HTTP routes
# ========================

@app.route("/version", methods=["GET"])
def version():
    try:
        import hashlib, inspect
        h = hashlib.sha256(inspect.getsourcefile(version).encode() if hasattr(version, "__code__") else b"").hexdigest()[:12]
    except Exception:
        h = ""
    return jsonify({"ok": True, "version": APP_VERSION, "code_hash": h})
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "version": APP_VERSION})

@app.route("/reload_meta", methods=["POST", "GET"])
def reload_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True})

@app.route("/admin/reload_meta", methods=["POST"])
@require_admin_secret
def admin_reload_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True, "ts": int(time.time())})

@app.route("/admin/clear_meta", methods=["POST"])
@require_admin_secret
def admin_clear_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True, "ts": int(time.time())})

@app.route("/admin/diag", methods=["GET"])
@require_admin_secret
def admin_diag():
    lines = []
    # Wayback/RDAP
    try:
        r = requests.get("https://rdap.org/domain/circle.com", timeout=6)
        lines.append({"name":"RDAP", "status": r.status_code})
    except Exception as e:
        lines.append({"name":"RDAP", "error": str(e)})
    try:
        r = requests.get("https://web.archive.org/cdx/search/cdx?url=circle.com/*&output=json&limit=1", timeout=6)
        lines.append({"name":"Wayback CDX", "status": r.status_code})
    except Exception as e:
        lines.append({"name":"Wayback CDX", "error": str(e)})
    # RPCs
    urls = _parse_rpc_urls()
    rpc = []
    for u in urls:
        try:
            r = requests.post(u, json={"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}, timeout=6, headers={"Content-Type":"application/json"})
            try:
                body = r.json()
            except Exception:
                body = {"http": r.status_code}
            rec = {"url": _mask_host(u), "status": r.status_code}
            if isinstance(body, dict) and "error" in body:
                rec["error"] = body.get("error")
            rec["result"] = body.get("result")
            if rec.get("result") in (None, "", []):
                rec.setdefault("note", "null/empty result")
            rpc.append(rec)
        except Exception as e:
            rpc.append({"url": _mask_host(u), "error": str(e)})
    return jsonify({"ok": True, "version": APP_VERSION, "diag": lines, "rpc": rpc})

# ========================
# Telegram webhook & callbacks
# ========================
def _answer_why_quickly(cq, addr_hint=None):
    try:
        msg_obj = cq.get("message", {}) or {}
        text = msg_obj.get("text") or ""
        addr = (addr_hint or msg2addr.get(str(msg_obj.get("message_id"))) or _extract_addr_from_text(text) or "").lower()
        info = RISK_CACHE.get(addr) if addr else None
        if not info:
            score, label, rs = _risk_verdict(addr or "", text or "")
            info = {"score": score, "label": label, "neg": rs.get("neg", []), "pos": rs.get("pos", []), "w_neg": rs.get("w_neg", []), "w_pos": rs.get("w_pos", [])}
        pairs_neg = list(zip(info.get("neg", []), info.get("w_neg", [])))
        pairs_pos = list(zip(info.get("pos", []), info.get("w_pos", [])))
        pairs_neg.sort(key=lambda x: x[1] if isinstance(x[1], (int, float)) else 0, reverse=True)
        pairs_pos.sort(key=lambda x: x[1] if isinstance(x[1], (int, float)) else 0, reverse=True)
        neg_s = "; ".join([f"{t} (+{w})" for t, w in pairs_neg[:2] if t]) if pairs_neg else ""
        pos_s = "; ".join([f"{t} (+{w})" for t, w in pairs_pos[:2] if t]) if pairs_pos else ""
        body = f"{info.get('label','?')} ({info.get('score',0)}/100)"
        if neg_s:
            body += f" — ⚠️ {neg_s}"
        if pos_s:
            body += f" — ✅ {pos_s}"
        if len(body) > 190:
            body = body[:187] + "…"
        tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), body, logger=app.logger)
    except Exception:
        tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "No cached reasons yet. Tap “More details” first.", logger=app.logger)

@app.route("/webhook/<secret>", methods=["POST"])
@require_webhook_secret
def webhook(secret):
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        return ("forbidden", 403)
    _maybe_reload_known(force=False)
    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        return ("ok", 200)

    # Callback queries
    if "callback_query" in update:
        cq = update["callback_query"]
        chat_id = cq["message"]["chat"]["id"]
        data = cq.get("data", "")
        msg_obj = cq.get("message", {})
        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
            return ("ok", 200)

        # Inflate hashed payloads early
        if data.startswith("cb:"):
            orig = cb_cache.get(data)
            if orig:
                data = orig
            else:
                # Smart fallback: try to extract Δ24h from the message text, else reply n/a
                txt = (msg_obj.get("text") or "")
                m_ = re.search(r"Δ24h[^\n]*", txt)
                ans = m_.group(0) if m_ else None
                if not ans:
                    addr_fb = _extract_addr_from_text(txt) or _extract_base_addr_from_keyboard(msg_obj.get("reply_markup") or {})
                    ch = _ds_token_changes((addr_fb or "").lower()) if addr_fb else {}
                    if ch.get("h24"):
                        ans = f"Δ24h {ch['h24']}"
                if not ans:
                    ans = "Δ: n/a (no data from source)"
                
                if lab in {"24","24h","h24"} and ADDR_RE.fullmatch(addr_l or ""):
                    try:
                        url = f"{DEX_BASE}/latest/dex/tokens/{addr_l}"
                        r = requests.get(url, timeout=6, headers={"User-Agent": "metridex-bot"})
                        if r.status_code == 200:
                            body = r.json() if hasattr(r, "json") else {}
                            p = _ds_pick_best_pair(body.get("pairs") or [])
                            if p:
                                liq = ((p.get("liquidity") or {}).get("usd"))
                                tx = (p.get("txns") or {}).get("h24") or {}
                                buys = tx.get("buys"); sells = tx.get("sells")
                                add = []
                                if liq is not None: add.append(f"liq≈${int(liq):,}")
                                if buys is not None and sells is not None: add.append(f"buys:sells={buys}:{sells}")
                                if add:
                                    ans = ans + " | " + " • ".join(add)
                    except Exception:
                        pass
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), ans, logger=app.logger)
                return ("ok", 200)


        # >>> TF_HANDLER_EARLY
        if isinstance(data, str) and re.match(r'^(tf:(5|1|6|24)|/24h|5|1|6|24)$', data):
            lab = data.replace("tf:","").replace("/","")
            # Determine base address from message map or text or keyboard
            try:
                mid = str((msg_obj or {}).get("message_id"))
            except Exception:
                mid = None
            addr0 = None
            if mid:
                try:
                    addr0 = msg2addr.get(mid)
                except Exception:
                    addr0 = None
            if not addr0:
                addr0 = _extract_addr_from_text(msg_obj.get("text") or "")
            if not addr0:
                addr0 = _extract_base_addr_from_keyboard(msg_obj.get("reply_markup") or {})
            addr_l = (addr0 or "").lower()
            changes = _ds_token_changes(addr_l) if ADDR_RE.fullmatch(addr_l or "") else {}
            key = {"5":"m5","1":"h1","6":"h6","24":"h24","24h":"h24"}.get(lab, None)
            if key and changes.get(key):
                pretty = {"m5":"5m","h1":"1h","h6":"6h","h24":"24h"}[key]
                ans = f"Δ{pretty} {changes[key]}" + (" ·computed" if changes.get(f"_src_{key}")=="calc" else "")
            elif lab in {"24","24h"}:
                txt = (msg_obj.get("text") or "")
                m_ = re.search(r"Δ24h[^\n]*", txt)
                ans = m_.group(0) if m_ else "Δ24h n/a"
            else:
                ans = "Δ: n/a (no data from source)"
            tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), ans, logger=app.logger)
            return ("ok", 200)
        # <<< TF_HANDLER_EARLY
            # <<< TF_HANDLER_EARLY


        
        
# Δ timeframe buttons
        # Δ timeframe buttons
            
# [removed duplicate TF handler]

# Dedupe
        cqid = cq.get("id")
        if cqid and seen_callbacks.get(cqid):
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "updated", logger=app.logger)
            return ("ok", 200)
        if cqid:
            seen_callbacks.set(cqid, True)

        try:
            if data.startswith("qs2:"):
                addrs = _extract_addrs_from_pair_payload(data)
                base_addr = _pick_addr(addrs)
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "updating…", logger=app.logger)
                text_out, keyboard = _qs_call_safe(quickscan_pair_entrypoint, data)
                base_addr = base_addr or _extract_base_addr_from_keyboard(keyboard)
                keyboard = _ensure_action_buttons(base_addr, keyboard, want_more=True, want_why=True, want_report=True, want_hp=True)
                keyboard = _compress_keyboard(keyboard)
                st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                _store_addr_for_message(body, base_addr)
                return ("ok", 200)

            if data.startswith("qs:"):
                payload = data.split(":", 1)[1]
                base_addr = payload.split("?", 1)[0]
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "updating…", logger=app.logger)
                text_out, keyboard = _qs_call_safe(quickscan_entrypoint, base_addr)
                keyboard = _ensure_action_buttons(base_addr, keyboard, want_more=True, want_why=True, want_report=True, want_hp=True)
                keyboard = _compress_keyboard(keyboard)
                st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                _store_addr_for_message(body, base_addr)
                return ("ok", 200)

            if data.startswith("more:"):
                addr = data.split(":", 1)[1].strip().lower()
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "loading…", logger=app.logger)
                base_text = msg_obj.get("text") or ""
                enriched = _enrich_full(addr, base_text)
                enriched = _append_verdict_block(addr, enriched)
                kb0 = msg_obj.get("reply_markup") or {}
                kb1 = _ensure_action_buttons(addr, {}, want_more=False, want_why=True, want_report=True, want_hp=True)
                kb1 = _compress_keyboard(kb1)
                st, body = _send_text(chat_id, enriched, reply_markup=kb1, logger=app.logger)
                _store_addr_for_message(body, addr)
                return ("ok", 200)

            
            # Δ timeframe buttons
            if data in {"5","1","6","24","/24h"} or data.startswith("tf:"):
                lab = data.replace("/", "").replace("tf:", "")
                try:
                    mid = str((msg_obj or {}).get("message_id"))
                except Exception:
                    mid = None
                addr0 = None
                if mid:
                    try:
                        addr0 = msg2addr.get(mid)
                    except Exception:
                        addr0 = None
                if not addr0:
                    addr0 = _extract_addr_from_text(msg_obj.get("text") or "")
                addr_l = (addr0 or "").lower()
                changes = _ds_token_changes(addr_l) if ADDR_RE.fullmatch(addr_l or "") else {}
                key = {"5":"m5","1":"h1","6":"h6","24":"h24","24h":"h24"}.get(lab, None)
                ans = None
                if key and changes.get(key):
                    pretty = {"m5":"5m","h1":"1h","h6":"6h","h24":"24h"}[key]
                    ans = f"Δ{pretty} {changes[key]}"
                elif lab in {"24","24h"}:
                    txt = (msg_obj.get("text") or "")
                    m = re.search(r"Δ24h[^\n]*", txt)
                    ans = m.group(0) if m else "Δ24h: n/a"
                else:
                    ans = "Δ: n/a (no data from source)"
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), ans, logger=app.logger)
                return ("ok", 200)

            if data.startswith("why2:"):
                addr_hint = data.split(":",1)[1].strip().lower()
                _answer_why_deep(cq, addr_hint=addr_hint)
                return ("ok", 200)

            if data.startswith("why"):
                addr_hint = None
                if ":" in data:
                    addr_hint = data.split(":", 1)[1].strip().lower()
                _answer_why_quickly(cq, addr_hint=addr_hint)
                return ("ok", 200)

            if data.startswith("hp:"):
                addr = data.split(":",1)[1].strip().lower()
                # Override with the base address from this message if available
                try:
                    mid = str((msg_obj or {}).get("message_id"))
                except Exception:
                    mid = None
                if mid:
                    try:
                        addr_m = msg2addr.get(mid)
                    except Exception:
                        addr_m = None
                    if addr_m and ADDR_RE.fullmatch(addr_m or ""):
                        addr = addr_m.lower()
                # Fallback to scanning address seen in the message text
                if not ADDR_RE.fullmatch(addr or ""):
                    addr_t = _extract_addr_from_text(msg_obj.get("text") or "")
                    if addr_t and ADDR_RE.fullmatch(addr_t or ""):
                        addr = addr_t.lower()
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "running on-chain…", logger=app.logger)
                out, meta = _onchain_inspect(addr)
                _merge_onchain_into_risk(addr, meta)
                kb0 = msg_obj.get("reply_markup") or {}
                kb1 = _ensure_action_buttons(addr, {}, want_more=False, want_why=True, want_report=True, want_hp=False)
                kb1 = _compress_keyboard(kb1)
                _send_text(chat_id, "On-chain\n" + out, reply_markup=kb1, logger=app.logger)
                return ("ok", 200)

            if data.startswith("rep:"):
                addr = data.split(":", 1)[1].strip().lower()
                # Ensure on-chain factors are present in cache (best-effort)
                try:
                    _onchain_inspect(addr)
                except Exception:
                    pass
                act_key = f"rep:{chat_id}:{addr}"
                if recent_actions.get(act_key):
                    tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "report already sent", logger=app.logger)
                    return ("ok", 200)
                recent_actions.set(act_key, True)
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "building report…", logger=app.logger)
                base_text = msg_obj.get("text") or ""
                path, html = _render_report(addr, base_text)
                caption = ""
                info = RISK_CACHE.get(addr) or {}
                if info:
                    caption = f"{info.get('label','?')} (score {info.get('score','?')}/100)"
                sent = False
                if path:
                    sent, _ = _tg_send_document(TELEGRAM_TOKEN, chat_id, path, caption=caption)
                if not sent:
                    teaser = "Report ready.\n" + (caption + "\n" if caption else "") + "⚠️/✅ details above."
                    _send_text(chat_id, teaser, logger=app.logger)
                return ("ok", 200)

            tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "unknown", logger=app.logger)
            return ("ok", 200)
        except Exception as e:
            _admin_debug(chat_id, f"callback error: {type(e).__name__}: {e}")
            tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "error", logger=app.logger)
            return ("ok", 200)

    # Regular messages
    msg = update.get("message") or update.get("edited_message")
    if not msg or (msg.get("from") or {}).get("is_bot"):
        return ("ok", 200)
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
        return ("ok", 200)
    if not text:
        _send_text(chat_id, "empty", logger=app.logger)
        return ("ok", 200)

    if text.startswith("/"):
        parts = text.split(maxsplit=1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ""
        if cmd in ("/start", "/help"):
            _send_text(chat_id, LOC("en","help").format(bot=BOT_USERNAME), parse_mode="Markdown", logger=app.logger)
            return ("ok", 200)
        if cmd in ("/reload_meta", "/clear_meta"):
            if ADMIN_CHAT_ID and str(chat_id) != str(ADMIN_CHAT_ID):
                _send_text(chat_id, "403: forbidden", logger=app.logger)
                return ("ok", 200)
            DOMAIN_META_CACHE.clear()
            _send_text(chat_id, "Meta cache cleared ✅", logger=app.logger)
            return ("ok", 200)
        if cmd in ("/diag",):
            if ADMIN_CHAT_ID and str(chat_id) != str(ADMIN_CHAT_ID):
                _send_text(chat_id, "403: forbidden", logger=app.logger)
                return ("ok", 200)
            lines = []
            import time as _t
            def check(url, name):
                t0 = _t.time()
                try:
                    r = requests.get(url, timeout=6, headers={"User-Agent": os.getenv("USER_AGENT","MetridexBot/1.0")})
                    dt = int((_t.time()-t0)*1000)
                    return f"{name}: {r.status_code} in {dt}ms"
                except Exception as e:
                    dt = int((_t.time()-t0)*1000)
                    return f"{name}: ERROR {type(e).__name__} {e} in {dt}ms"
            lines.append(check("https://rdap.org/domain/circle.com","RDAP"))
            lines.append(check("https://web.archive.org/cdx/search/cdx?url=circle.com/*&output=json&limit=1","Wayback CDX"))
            # RPC providers check
            urls = _parse_rpc_urls()
            if urls:
                lines.append("RPC providers: " + ", ".join([_mask_host(u) for u in urls]))
                for u in urls:
                    try:
                        r = requests.post(u, json={"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}, timeout=6, headers={"Content-Type":"application/json"})
                        ok = ""
                        try:
                            ok = r.json().get("result","")
                        except Exception:
                            ok = f"HTTP {r.status_code}"
                        lines.append(f"RPC {_mask_host(u)}: {ok}")
                    except Exception as e:
                        lines.append(f"RPC {_mask_host(u)}: ERROR {type(e).__name__}: {e}")
            else:
                lines.append("RPC providers: none configured")
            try:
                _ = _qs_call_safe(quickscan_entrypoint, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
                lines.append("QuickScan: OK")
            except Exception as e:
                lines.append(f"QuickScan: ERROR {type(e).__name__}: {e}")
            _send_text(chat_id, "Diag:\n" + "\n".join(lines), logger=app.logger)
            return ("ok", 200)
        if cmd in ("/onchain",):
            if not arg:
                _send_text(chat_id, "Usage: /onchain <contract_address>", logger=app.logger)
            else:
                base_addr = _extract_addr_from_text(arg) or arg.strip()
                details, meta = _onchain_inspect(base_addr)
                _merge_onchain_into_risk(base_addr, meta)
                _send_text(chat_id, "On-chain\n" + details, logger=app.logger)
            return ("ok", 200)
        if cmd in ("/quickscan","/scan"):
            if not arg:
                _send_text(chat_id, LOC("en","scan_usage"), logger=app.logger)
            else:
                try:
                    text_out, keyboard = _qs_call_safe(quickscan_entrypoint, arg)
                    base_addr = _extract_addr_from_text(arg) or _extract_base_addr_from_keyboard(keyboard)
                    keyboard = _ensure_action_buttons(base_addr, keyboard, want_more=True, want_why=True, want_report=True, want_hp=True)
                    keyboard = _compress_keyboard(keyboard)
                    st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                    _store_addr_for_message(body, base_addr)
                except Exception as e:
                    _admin_debug(chat_id, f"scan failed: {type(e).__name__}: {e}")
                    _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
            return ("ok", 200)
        _send_text(chat_id, LOC("en","unknown"), logger=app.logger)
        return ("ok", 200)

    _send_text(chat_id, "Processing…", logger=app.logger)
    try:
        text_out, keyboard = _qs_call_safe(quickscan_entrypoint, text)
        base_addr = _extract_addr_from_text(text) or _extract_base_addr_from_keyboard(keyboard)
        keyboard = _ensure_action_buttons(base_addr, keyboard, want_more=True, want_why=True, want_report=True, want_hp=True)
        keyboard = _compress_keyboard(keyboard)
        st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
        _store_addr_for_message(body, base_addr)
    except Exception as e:
        _admin_debug(chat_id, f"scan failed: {type(e).__name__}: {e}")
        _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
    return ("ok", 200)


def _enrich_full(addr: str, base_text: str) -> str:
    try:
        text = base_text or ""
        addr_l = (addr or "").lower()
        dom = None
        try:
            dom = _extract_domain_from_text(text)
        except Exception:
            dom = None
        try:
            if not dom and ADDR_RE.fullmatch(addr_l or ""):
                dom = KNOWN_HOMEPAGES.get(addr_l)
        except Exception:
            pass
        try:
            if not dom:
                hint = _symbol_homepage_hint(text)
                if hint:
                    dom = hint
        except Exception:
            pass
        try:
            if not dom and ADDR_RE.fullmatch(addr_l or ""):
                dom = _cg_homepage(addr_l)
        except Exception:
            pass
        if not dom:
            return text
        try:
            h, created, reg, exp, issuer, wb = _domain_meta(dom)
        except Exception:
            h, created, reg, exp, issuer, wb = ("—", "—", "—", "—", "—", "—")
        try:
            reg = _normalize_registrar(reg, h, dom)
        except Exception:
            pass
        domain_line = f"Domain: {dom}"
        whois_line  = f"WHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}"
        ssl_prefix  = "SSL: OK" if exp and exp != "—" else "SSL: —"
        ssl_line    = f"{ssl_prefix} | Expires: {exp or '—'} | Issuer: {issuer or '—'}"
        wayback_line= f"Wayback: first {wb if wb else '—'}"
        import re as _re
        def _replace_or_append(body, label, newline):
            patt = _re.compile(rf"(?m)^{_re.escape(label)}[^\n]*$")
            if patt.search(body or ""):
                return patt.sub(newline, body)
            if body and not body.endswith("\n"):
                body += "\n"
            return body + newline
        text = _replace_or_append(text, "Domain:",     domain_line)
        text = _replace_or_append(text, "WHOIS/RDAP:", whois_line)
        text = _replace_or_append(text, "SSL:",        ssl_line)
        text = _replace_or_append(text, "Wayback:",    wayback_line)
        return text
    except Exception:
        return base_text or ""


def _kb_dedupe_all(kb: dict) -> dict:
    try:
        ik = (kb or {}).get("inline_keyboard") or []
        out = []
        seen = set()
        for row in ik:
            new_row = []
            for btn in (row or []):
                cd = str((btn or {}).get("callback_data") or "")
                key = ("cd", cd) if cd else ("tx", str((btn or {}).get("text") or ""))
                if key in seen:
                    continue
                seen.add(key)
                new_row.append(btn)
            if new_row:
                out.append(new_row)
        return {"inline_keyboard": out}
    except Exception:
        return kb or {}


def _kb_strip_tf_rows(kb: dict) -> dict:
    """Remove any Δ timeframe rows regardless of encoding."""
    try:
        base = _kb_clone(kb)
        ik = (base or {}).get("inline_keyboard") or []
        out = []
        for row in ik:
            delta_like = 0
            new_row = []
            for btn in (row or []):
                cd = str((btn or {}).get("callback_data") or "")
                tx = str((btn or {}).get("text") or "")
                if cd.startswith("tf:") or cd in {"5","1","6","24","/24h"}:
                    continue
                if tx.strip().startswith("Δ"):
                    delta_like += 1
                else:
                    new_row.append(btn)
            if delta_like >= 3:
                continue
            if new_row:
                out.append(new_row)
        return {"inline_keyboard": out}
    except Exception:
        return kb or {}

def _normalize_hp_line(addr, text, block:str) -> str:
    """Post-process on-chain block: if token is whitelisted/centralized,
    replace 'Honeypot quick-test: ⚠️ static only...' with a neutral skip note."""
    try:
        whitelisted, _ = _is_whitelisted(addr, text)
        if whitelisted:
            return _normalize_hp_line(addr, text, block).replace("Honeypot quick-test: ⚠️ static only (no DEX sell simulation)",
                                 "Honeypot: ℹ️ skipped for centralized/whitelisted token")
        return _normalize_hp_line(addr, text, block)
    except Exception:
        return _normalize_hp_line(addr, text, block)


def _html_sanitize_risk(risk):
    try:
        neg = list(risk.get("neg") or [])
        wneg = list(risk.get("w_neg") or [])
        pos = list(risk.get("pos") or [])
        wpos = list(risk.get("w_pos") or [])
        # drop zero-weight negatives
        neg2, wneg2 = [], []
        for r, w in zip(neg, wneg):
            try:
                wi = int(w)
            except Exception:
                wi = 10
            if wi > 0:
                neg2.append(r); wneg2.append(w)
        risk["neg"], risk["w_neg"] = neg2, wneg2
        # ensure expected-admin positive once
        expected = "Admin privileges expected for centralized/whitelisted token"
        if not any(expected in p for p in pos):
            pos.append(expected); wpos.append(0)
        risk["pos"], risk["w_pos"] = pos, wpos
    except Exception:
        pass
    return risk
