from __future__ import annotations
import os, time, re
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests

# -------- Config --------
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS","10"))
RPC_TIMEOUT  = int(os.getenv("PROVIDER_TIMEOUT_SECONDS","8"))
UA = os.getenv("HTTP_UA","MetridexBot/1.0 (+https://metridex.com)")
HEADERS = {"User-Agent": UA, "Accept": "application/json"}

# DexScreener hosts (try in order)
DS_BASES = [b.strip() for b in (os.getenv("DEXSCREENER_BASES") or os.getenv("DEXSCREENER_BASE") or "https://api.dexscreener.com,https://io.dexscreener.com,https://cdn.dexscreener.com").split(",") if b.strip()]

# Supported networks (input short-hands)
def enabled_networks() -> list[str]:
    s = os.getenv("ENABLED_NETWORKS", "eth,bsc,polygon,base,arb,op,avax,ftm,sol")
    return [x.strip() for x in s.split(",") if x.strip()]

# Aliases between short codes and DexScreener chainIds
DS_CHAIN_FROM_SHORT = {
    "eth": "ethereum",
    "arb": "arbitrum",
    "op":  "optimism",
    "avax":"avalanche",
    "ftm": "fantom",
    "bsc": "bsc",
    "polygon": "polygon",
    "base": "base",
    "sol": "solana",
}
SHORT_FROM_DS_CHAIN = {v:k for k,v in DS_CHAIN_FROM_SHORT.items()}

# Scanners map for "Open in Scan" buttons
SCAN_HOST = {
    "ethereum": "etherscan.io",
    "bsc": "bscscan.com",
    "polygon": "polygonscan.com",
    "arbitrum": "arbiscan.io",
    "optimism": "optimistic.etherscan.io",
    "base": "basescan.org",
    "avalanche": "snowtrace.io",
    "fantom": "ftmscan.com",
    "solana": "solscan.io",
}

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

TX_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")

EXPLORER_CHAIN_BY_HOST = {
    "etherscan.io": "ethereum",
    "bscscan.com": "bsc",
    "polygonscan.com": "polygon",
    "arbiscan.io": "arbitrum",
    "optimistic.etherscan.io": "optimism",
    "basescan.org": "base",
    "snowtrace.io": "avalanche",
    "ftmscan.com": "fantom",
    "solscan.io": "solana",
}

def _detect_chain_by_txhash(txhash: str) -> str | None:
    if not TX_RE.match(txhash or ""): return None
    for ch in enabled_networks():
        rpc = _rpc_for_chain(ch)
        if not rpc: continue
        try:
            j = _rpc_call(rpc, "eth_getTransactionByHash", [txhash])
            if j.get("result"):
                return ch
        except Exception:
            continue
    return None

# ---- Minimal on-chain (optional reserves signal) ----
SIG_DECIMALS = "0x313ce567"
SIG_GETRESERVES = "0x0902f1ac"
SIG_TOKEN0 = "0x0dfe1681"
SIG_TOKEN1 = "0xd21220a7"

CHAIN_RPC_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY",
    "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY",
    "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY",
    "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY",
    "ftm":"FTM_RPC_URL_PRIMARY",
}

def _rpc_for_chain(short_chain:str) -> str | None:
    env = CHAIN_RPC_ENV.get(short_chain)
    return (os.getenv(env, "") or "").strip() or None

def _rpc_call(rpc: str, method: str, params: list) -> Any:
    payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    r = requests.post(rpc, json=payload, timeout=RPC_TIMEOUT, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = _rpc_call(rpc, "eth_call", [{"to": to, "data": data}, "latest"])
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _read_u256(raw: bytes) -> int:
    return 0 if not raw else int.from_bytes(raw[-32:], "big", signed=False)

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
    if want_token0: return (r1 * (10**d0)) / (r0 * (10**d1))
    return (r0 * (10**d1)) / (r1 * (10**d0))

# -------- HTTP helpers --------
def _http_get_json(url: str, params: Dict[str, Any] | None = None) -> tuple[int, Any]:
    """GET JSON; tolerant to wrong content-type; returns (status, obj|text)."""
    try:
        r = requests.get(url, params=params or {}, timeout=HTTP_TIMEOUT, headers=HEADERS)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 599, {"error": str(e)}

def _ds_get(path: str) -> tuple[int, Any]:
    """Try multiple DexScreener hosts until one succeeds."""
    last_code, last_body = 599, {"error": "no hosts"}
    for base in DS_BASES:
        url = base.rstrip("/") + path
        code, body = _http_get_json(url)
        # Accept 200 with dict body; anything else keep trying
        if code == 200 and isinstance(body, dict):
            return code, body
        last_code, last_body = code, body
    return last_code, last_body

# -------- Normalization --------
def _normalize_market(ds: Dict[str, Any]) -> Dict[str, Any]:
    m = {
        "pairSymbol": f"{ds.get('baseToken',{}).get('symbol','?')}/{ds.get('quoteToken',{}).get('symbol','?')}",
        "chain": ds.get("chainId") or ds.get("chain") or "—",
        "price": float(ds.get("priceUsd") or 0) or None,
        "fdv": ds.get("fdv"),
        "mc": ds.get("marketCap"),
        "liq": (ds.get("liquidity") or {}).get("usd"),
        "vol24h": (ds.get("volume") or {}).get("h24"),
        "priceChanges": {
            "m5": (ds.get("priceChange") or {}).get("m5"),
            "h1": (ds.get("priceChange") or {}).get("h1"),
            "h24": (ds.get("priceChange") or {}).get("h24"),
        },
        "ageDays": None,
        "pairAddress": ds.get("pairAddress"),
        "baseAddress": (ds.get("baseToken") or {}).get("address"),
        "quoteAddress": (ds.get("quoteToken") or {}).get("address"),
        "tokenAddress": (ds.get("baseToken") or {}).get("address"),
        "sources": ["DexScreener"],
        "source": "DexScreener",
        "links": {},
        "asof": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
    }
    if ds.get("age"):
        try:
            m["ageDays"] = round(float(ds["age"])/86400, 1)
        except Exception:
            pass
    # DEX link
    if m.get("pairAddress") and m.get("chain"):
        m["links"]["dex"] = f"https://dexscreener.com/{m['chain']}/{m['pairAddress']}"
    # Website
    site = (ds.get("info") or {}).get("website")
    if site: m["links"]["site"] = site
    # Scan link (token)
    ch = (m.get("chain") or "").lower()
    host = SCAN_HOST.get(ch)
    if host and m.get("tokenAddress"):
        m["links"]["scan"] = f"https://{host}/token/{m['tokenAddress']}"
    return m

# -------- DexScreener adapters --------
def _ds_by_pair(chain: str, pair: str) -> Dict[str, Any]:
    if not pair: return {"ok": False, "error": "no pair"}
    # Map short alias if given
    chain_id = DS_CHAIN_FROM_SHORT.get(chain, chain).lower()
    code, d = _ds_get(f"/latest/dex/pairs/{chain_id}/{pair}")
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no pairs"}
    # Prefer highest USD liquidity
    best = max(pairs, key=lambda x: ((x.get("liquidity") or {}).get("usd") or 0))
    m = _normalize_market(best); m["ok"] = True
    return m

def _ds_by_token(chain: str, token: str) -> Dict[str, Any]:
    if not token: return {"ok": False, "error": "no token"}
    code, d = _ds_get(f"/latest/dex/tokens/{token}")
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no pairs"}
    # Prefer pairs on requested chain (if any) and with the token as baseToken
    chain_id = DS_CHAIN_FROM_SHORT.get(chain, chain).lower() if chain else None
    def score(p: Dict[str, Any]) -> tuple[int, float]:
        c = (p.get("chainId") or p.get("chain") or "").lower()
        is_req_chain = 1 if (chain_id and c == chain_id) else 0
        is_base = 1 if ((p.get("baseToken") or {}).get("address","").lower() == (token or "").lower()) else 0
        liq = ((p.get("liquidity") or {}).get("usd") or 0.0)
        return (is_req_chain + is_base, float(liq))
    best = max(pairs, key=score)
    m = _normalize_market(best); m["ok"] = True; m["tokenAddress"] = token
    return m

# -------- Optional on-chain enrichment --------
def _add_onchain_source(market: Dict[str, Any]) -> None:
    # Try to compute a reserve-based price as an extra source where possible
    ds_chain = (market.get("chain") or "").lower()
    short = SHORT_FROM_DS_CHAIN.get(ds_chain, ds_chain)  # keep if already short
    pair = market.get("pairAddress")
    rpc = _rpc_for_chain(short)
    if not (rpc and pair):
        return
    try:
        r0,r1,_ = _get_reserves(rpc, pair)
        if r0 and r1:
            # derive a comparative price and mark as additional source
            t0,t1 = _pair_tokens(rpc, pair)
            d0 = _decimals(rpc, t0) if t0 else 18
            d1 = _decimals(rpc, t1) if t1 else 18
            price2 = _price_from_reserves(r0,d0,r1,d1, True)
            market.setdefault("meta", {})["reservePrice"] = price2
            srcs = list(market.get("sources") or [])
            if "On-chain reserves" not in srcs:
                srcs.append("On-chain reserves")
            market["sources"] = srcs
            market["source"] = ", ".join(srcs)
    except Exception as e:
        market.setdefault("meta", {})["reserves_error"] = str(e)

# -------- Query parsing --------
def _parse_query(q: str) -> tuple[str|None, str|None, str|None]:
    q = (q or "").strip()
    if not q: return None, None, None
    # DexScreener pair URL
    if "dexscreener.com" in q:
        try:
            u = urlparse(q if q.startswith("http") else "https://" + q)
            parts = [p for p in u.path.split("/") if p]
            if len(parts) >= 2:
                chain = parts[-2].lower(); pair = parts[-1]
                if ADDR_RE.match(pair): return chain, None, pair
        except Exception:
            pass
    # Explorer URL (token or tx)
    try:
        if "://" not in q and "." in q:
            u = urlparse("https://" + q)
        else:
            u = urlparse(q)
        host = u.netloc.lower()
        ch = EXPLORER_CHAIN_BY_HOST.get(host)
        if ch:
            parts = [p for p in u.path.split("/") if p]
            if "token" in parts:
                idx = parts.index("token")
                if idx+1 < len(parts) and ADDR_RE.match(parts[idx+1]):
                    return ch, parts[idx+1], None
            if "tx" in parts:
                idx = parts.index("tx")
                if idx+1 < len(parts) and TX_RE.match(parts[idx+1]):
                    return ch, None, None
    except Exception:
        pass
    # Plain addresses / tx
    if ADDR_RE.match(q): return None, q, None
    if TX_RE.match(q):   return None, None, None
    return None, None, Nonet
