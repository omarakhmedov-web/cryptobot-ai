
"""
market_aggregator_free.py — Free-first market aggregator
- Primary: DexScreener (no key)
- Secondary (EVM): on-chain reserves math via JSON-RPC (getReserves + decimals)
Outputs a normalized market dict with 'sources' and 'asof'.
"""
from __future__ import annotations
import os, time, json, math
from typing import Dict, Any, Optional, Tuple
import requests

DEX_BASE = os.getenv("DEXSCREENER_BASE", "https://api.dexscreener.com")
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS","10"))
RPC_TIMEOUT = int(os.getenv("PROVIDER_TIMEOUT_SECONDS","8"))
UA = os.getenv("HTTP_UA","MetridexBot/1.0 (+https://metridex.com)")

HEADERS = {"User-Agent": UA}

# Minimal ABI selectors
SIG_DECIMALS = "0x313ce567"  # decimals()
SIG_GETRESERVES = "0x0902f1ac"  # getReserves()
SIG_TOKEN0 = "0x0dfe1681"
SIG_TOKEN1 = "0xd21220a7"  # token1()

CHAIN_RPC_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY",
    "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY",
    "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY",
    "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY",
    "ftm":"FTM_RPC_URL_PRIMARY"
}

def _http_get(url: str, params: Dict[str, Any] | None = None):
    try:
        r = requests.get(url, params=params or {}, timeout=HTTP_TIMEOUT, headers=HEADERS)
        if "json" in (r.headers.get("content-type") or ""):
            return r.status_code, r.json()
        return r.status_code, r.text
    except Exception as e:
        return 599, {"error": str(e)}

def _rpc_call(rpc: str, method: str, params: list) -> Any:
    payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    r = requests.post(rpc, json=payload, timeout=RPC_TIMEOUT, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def _hex_to_int(x:str) -> int:
    return int(x,16) if isinstance(x,str) and x.startswith("0x") else int(x)

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = _rpc_call(rpc, "eth_call", [{"to": to, "data": data}, "latest"])
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _read_u256(raw: bytes) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw[-32:], "big", signed=False)

def _pair_tokens(rpc: str, pair: str):
    t0 = _eth_call(rpc, pair, SIG_TOKEN0)
    t1 = _eth_call(rpc, pair, SIG_TOKEN1)
    a0 = "0x"+t0[-20:].hex() if t0 else ""
    a1 = "0x"+t1[-20:].hex() if t1 else ""
    return a0, a1

def _decimals(rpc: str, addr: str) -> int:
    raw = _eth_call(rpc, addr, SIG_DECIMALS)
    return _read_u256(raw) or 18

def _get_reserves(rpc: str, pair: str):
    raw = _eth_call(rpc, pair, SIG_GETRESERVES)
    if not raw or len(raw) < 96:
        return 0,0,0
    r0 = int.from_bytes(raw[0:32], "big")
    r1 = int.from_bytes(raw[32:64], "big")
    ts = int.from_bytes(raw[64:96], "big")
    return r0, r1, ts

def _price_from_reserves(r0:int, d0:int, r1:int, d1:int, want_token0: bool) -> float:
    if r0==0 or r1==0:
        return float("nan")
    if want_token0:
        num = r1 * (10**d0)
        den = r0 * (10**d1)
        return float(num)/float(den)
    else:
        num = r0 * (10**d1)
        den = r1 * (10**d0)
        return float(num)/float(den)

def _rpc_for_chain(chain:str):
    env = CHAIN_RPC_ENV.get(chain)
    if not env:
        return None
    url = os.getenv(env, "").strip()
    return url or None

def _normalize_market(ds: dict) -> dict:
    m = {
        "pairSymbol": f"{ds.get('baseToken',{}).get('symbol','?')}/{ds.get('quoteToken',{}).get('symbol','?')}",
        "chain": ds.get("chainId") or ds.get("chain") or "—",
        "price": float(ds.get("priceUsd") or 0) or None,
        "fdv": ds.get("fdv"),
        "mc": ds.get("marketCap"),
        "liq": ds.get("liquidity",{}).get("usd"),
        "vol24h": ds.get("volume",{}).get("h24"),
        "priceChanges": {
            "m5": ds.get("priceChange",{}).get("m5"),
            "h1": ds.get("priceChange",{}).get("h1"),
            "h24": ds.get("priceChange",{}).get("h24"),
        },
        "ageDays": None,
        "pairAddress": ds.get("pairAddress"),
        "baseAddress": ds.get("baseToken",{}).get("address"),
        "quoteAddress": ds.get("quoteToken",{}).get("address"),
        "sources": ["DexScreener"],
        "asof": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
    }
    if ds.get("age"):
        try:
            m["ageDays"] = round(float(ds["age"])/86400, 1)
        except Exception:
            pass
    return m

def fetch_market(chain: str, token: str | None = None, pair: str | None = None) -> dict:
    # 1) DexScreener
    if pair:
        ds_url = f"{DEX_BASE}/latest/dex/pairs/{chain}/{pair}"
    elif token:
        ds_url = f"{DEX_BASE}/latest/dex/tokens/{token}"
    else:
        return {"ok": False, "error": "token or pair required"}
    code, d = _http_get(ds_url)
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no pairs"}
    ds = pairs[0]
    m = _normalize_market(ds)
    m["ok"] = True

    # 2) On-chain reserves for EVM chains (if pair known)
    rpc = _rpc_for_chain(chain)
    if rpc and m.get("pairAddress"):
        try:
            r0,r1,_ = _get_reserves(rpc, m["pairAddress"])
            if r0 and r1:
                t0,t1 = _pair_tokens(rpc, m["pairAddress"])
                d0 = _decimals(rpc, t0) if t0 else 18
                d1 = _decimals(rpc, t1) if t1 else 18
                price2 = _price_from_reserves(r0,d0,r1,d1, True)
                if price2 == price2:  # not NaN
                    if isinstance(m.get("price"), (int,float)) and m["price"]:
                        dev = abs(price2 - m["price"]) / m["price"]
                        m.setdefault("meta", {})["reservePrice"] = price2
                        m.setdefault("meta", {})["priceDeviation"] = dev
                    m["sources"].append("On-chain reserves")
        except Exception as e:
            m.setdefault("meta", {})["reserves_error"] = str(e)

    return m
