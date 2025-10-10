from __future__ import annotations
"""
dex_client.py — free-first, backward-compatible
- Primary: DexScreener (no key)
- Secondary: on-chain reserves (UniswapV2) via public RPC
- Autodetect сети по ENABLED_NETWORKS
- Backcompat: один позиционный аргумент трактуется как query (адрес/URL)
"""
import os, time, math, re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import requests

# Берём список сетей из .env
def enabled_networks() -> list[str]:
    s = os.getenv("ENABLED_NETWORKS", "eth,bsc,polygon,base,arb,op,avax,ftm,sol")
    return [x.strip() for x in s.split(",") if x.strip()]

DEX_BASE = os.getenv("DEXSCREENER_BASE", "https://api.dexscreener.com")
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS","10"))
RPC_TIMEOUT = int(os.getenv("PROVIDER_TIMEOUT_SECONDS","8"))
UA = os.getenv("HTTP_UA","MetridexBot/1.0 (+https://metridex.com)")
HEADERS = {"User-Agent": UA}

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SIG_DECIMALS = "0x313ce567"     # decimals()
SIG_GETRESERVES = "0x0902f1ac"  # getReserves()
SIG_TOKEN0 = "0x0dfe1681"
SIG_TOKEN1 = "0xd21220a7"       # token1()

CHAIN_RPC_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY", "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY", "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY", "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY", "ftm":"FTM_RPC_URL_PRIMARY"
}

def _http_get(url: str, params: Dict[str, Any] | None = None):
    try:
        r = requests.get(url, params=params or {}, timeout=HTTP_TIMEOUT, headers=HEADERS)
        if "json" in (r.headers.get("content-type") or ""): return r.status_code, r.json()
        return r.status_code, r.text
    except Exception as e:
        return 599, {"error": str(e)}

def _rpc_call(rpc: str, method: str, params: list) -> Any:
    payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    r = requests.post(rpc, json=payload, timeout=RPC_TIMEOUT, headers=HEADERS)
    r.raise_for_status(); return r.json()

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = _rpc_call(rpc, "eth_call", [{"to": to, "data": data}, "latest"])
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _read_u256(raw: bytes) -> int:
    return 0 if not raw else int.from_bytes(raw[-32:], "big", signed=False)

def _rpc_for_chain(chain:str) -> str | None:
    env = CHAIN_RPC_ENV.get(chain); 
    return (os.getenv(env, "") or "").strip() or None

def _pair_tokens(rpc: str, pair: str) -> tuple[str,str]:
    t0 = _eth_call(rpc, pair, SIG_TOKEN0); t1 = _eth_call(rpc, pair, SIG_TOKEN1)
    a0 = "0x"+t0[-20:].hex() if t0 else ""; a1 = "0x"+t1[-20:].hex() if t1 else ""
    return a0, a1

def _decimals(rpc: str, addr: str) -> int:
    return _read_u256(_eth_call(rpc, addr, SIG_DECIMALS)) or 18

def _get_reserves(rpc: str, pair: str) -> tuple[int,int,int]:
    raw = _eth_call(rpc, pair, SIG_GETRESERVES)
    if not raw or len(raw) < 96: return 0,0,0
    r0 = int.from_bytes(raw[0:32], "big"); r1 = int.from_bytes(raw[32:64], "big")
    ts = int.from_bytes(raw[64:96], "big"); return r0, r1, ts

def _price_from_reserves(r0:int, d0:int, r1:int, d1:int, want_token0: bool) -> float:
    if r0==0 or r1==0: return float("nan")
    if want_token0:
        return (r1 * (10**d0)) / (r0 * (10**d1))
    return (r0 * (10**d1)) / (r1 * (10**d0))

def _normalize_market(ds: Dict[str, Any]) -> Dict[str, Any]:
    m = {
        "pairSymbol": f"{ds.get('baseToken',{}).get('symbol','?')}/{ds.get('quoteToken',{}).get('symbol','?')}",
        "chain": ds.get("chainId") or ds.get("chain") or "—",
        "price": float(ds.get("priceUsd") or 0) or None,
        "fdv": ds.get("fdv"), "mc": ds.get("marketCap"),
        "liq": ds.get("liquidity",{}).get("usd"), "vol24h": ds.get("volume",{}).get("h24"),
        "priceChanges": { "m5": ds.get("priceChange",{}).get("m5"),
                          "h1": ds.get("priceChange",{}).get("h1"),
                          "h24": ds.get("priceChange",{}).get("h24") },
        "ageDays": None, "pairAddress": ds.get("pairAddress"),
        "baseAddress": ds.get("baseToken",{}).get("address"),
        "quoteAddress": ds.get("quoteToken",{}).get("address"),
        "sources": ["DexScreener"],
        "asof": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
    }
    if ds.get("age"):
        try: m["ageDays"] = round(float(ds["age"])/86400, 1)
        except Exception: pass
    return m

def _ds_by_pair(chain: str, pair: str) -> Dict[str, Any]:
    code, d = _http_get(f"{DEX_BASE}/latest/dex/pairs/{chain}/{pair}")
    if code != 200 or not isinstance(d, dict): return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []; 
    if not pairs: return {"ok": False, "error": "no pairs"}
    m = _normalize_market(pairs[0]); m["ok"] = True; return m

def _ds_by_token(chain: str, token: str) -> Dict[str, Any]:
    code, d = _http_get(f"{DEX_BASE}/latest/dex/tokens/{token}")
    if code != 200 or not isinstance(d, dict): return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []; 
    if not pairs: return {"ok": False, "error": "no pairs"}
    for p in pairs:
        if (p.get("chainId") or p.get("chain")) == chain:
            m = _normalize_market(p); m["ok"] = True; return m
    m = _normalize_market(pairs[0]); m["ok"] = True; return m

def _add_onchain_source(market: Dict[str, Any]) -> None:
    chain = (market.get("chain") or "").lower(); pair = market.get("pairAddress")
    rpc = _rpc_for_chain(chain)
    if not (rpc and pair): return
    try:
        r0,r1,_ = _get_reserves(rpc, pair)
        if r0 and r1:
            t0,t1 = _pair_tokens(rpc, pair)
            d0 = _decimals(rpc, t0) if t0 else 18
            d1 = _decimals(rpc, t1) if t1 else 18
            price2 = _price_from_reserves(r0,d0,r1,d1, True)
            market.setdefault("meta", {})["reservePrice"] = price2
            srcs = market.get("sources") or []
            if "On-chain reserves" not in srcs:
                srcs.append("On-chain reserves")
                market["sources"] = srcs
    except Exception as e:
        market.setdefault("meta", {})["reserves_error"] = str(e)

def _parse_query(q: str) -> tuple[str|None, str|None, str|None]:
    q = (q or "").strip()
    if not q: return None, None, None
    if "dexscreener.com" in q:
        try:
            u = urlparse(q if q.startswith("http") else "https://" + q)
            parts = [p for p in u.path.split("/") if p]
            if len(parts) >= 2:
                chain = parts[-2].lower(); pair = parts[-1]
                if ADDR_RE.match(pair): return chain, None, pair
        except Exception: pass
    if ADDR_RE.match(q): return None, q, None
    return None, None, None

def fetch_market(_pos: str | None = None, *, chain: str | None = None,
                 token: str | None = None, pair: str | None = None) -> Dict[str, Any]:
    # back-compat: один позиционный аргумент = query
    if _pos and not (chain or token or pair):
        c,t,p = _parse_query(_pos); chain = chain or c; token = token or t; pair = pair or p

    # если адрес попал в chain — это старая ошибка вызова: лечим
    if chain and ADDR_RE.match(chain):
        token = token or chain; chain = None

    # 1) явная сеть + (pair/token)
    if chain and (pair or token):
        ch = chain.strip().lower()
        m = _ds_by_pair(ch, pair) if pair else _ds_by_token(ch, token)
        if m.get("ok"): _add_onchain_source(m); return m

    # 2) есть токен — autodetect сети
    if token and not pair:
        for ch in enabled_networks():
            m = _ds_by_token(ch, token)
            if m.get("ok"): _add_onchain_source(m); m["chain"] = ch; return m

    # 3) есть пара — autodetect сети
    if pair and not chain:
        for ch in enabled_networks():
            m = _ds_by_pair(ch, pair)
            if m.get("ok"): _add_onchain_source(m); m["chain"] = ch; return m

    return {"ok": False, "error": "no market found", "sources": [], "chain": chain or "—"}
