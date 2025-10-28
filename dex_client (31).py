
# dex_client.py — Metridex SAFE resolver (v0.4.1)
# Resolves token or pair to "market" dict expected by server.renderers_mdx
# Uses DEXSCREENER_PROXY_BASE if present; else direct DexScreener API.
import os, re, time
import requests

DS_BASE = (os.getenv("DEXSCREENER_PROXY_BASE") or os.getenv("DS_PROXY_BASE") or "").rstrip("/")
if not DS_BASE:
    DS_BASE = "https://api.dexscreener.com/latest/dex"  # direct

UA = os.getenv("HTTP_UA", "Metridex/market-resolver 0.4.1")

_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_CHAIN_MAP = { # DexScreener -> short
    "ethereum": "eth", "eth": "eth", "1":"eth",
    "bsc": "bsc", "56":"bsc", "binance-smart-chain":"bsc",
    "polygon": "polygon", "matic":"polygon", "137":"polygon",
    "base":"base", "8453":"base",
    "arbitrum":"arb", "42161":"arb", "arbitrum-one":"arb",
    "optimism":"op", "10":"op",
    "avalanche":"avax", "43114":"avax",
    "fantom":"ftm", "250":"ftm",
}

def _http_json(url, timeout=6):
    h = {"User-Agent": UA, "Accept": "application/json"}
    r = requests.get(url, timeout=timeout, headers=h)
    r.raise_for_status()
    return r.json()

def _pick_best_pair(pairs):
    # Choose the pair with the highest USD liquidity; fallback to first.
    best, best_liq = None, -1.0
    for p in (pairs or []):
        try:
            liq = float(((p.get("liquidity") or {}).get("usd") or 0) or 0)
        except Exception:
            liq = 0.0
        if liq > best_liq:
            best, best_liq = p, liq
    return best

def _short_chain(p):
    raw = str(p.get("chainId") or p.get("chain") or "").lower()
    return _CHAIN_MAP.get(raw, raw or "eth")

def _price_changes(p):
    ch = p.get("priceChange") or {}
    # DexScreener uses m5, h1, h6, h24 keys already
    out = {}
    for k in ("m5","h1","h6","h24"):
        v = ch.get(k)
        try:
            out[k] = float(v) if v is not None else None
        except Exception:
            out[k] = None
    return out

def _links(p):
    out = {}
    url = p.get("url")
    if isinstance(url, str):
        out["pair"] = url
    # prefer project website if present
    site = (p.get("info") or {}).get("website")
    if isinstance(site, str):
        out["site"] = site
    return out

def _asof(p):
    # DexScreener doesn't give "as of" directly; approximate by now.
    return int(time.time())

def _market_from_pair(p):
    # Compose market dict expected by renderers/keyboard, tolerant to missing fields
    base_token = (p.get("baseToken") or {})
    quote_token = (p.get("quoteToken") or {})
    fdv = p.get("fdv")
    mcap = p.get("marketCap") or p.get("mc")
    liq = ((p.get("liquidity") or {}).get("usd") or None)
    vol24 = ((p.get("volume") or {}).get("h24") or None)

    try:
        price_usd = float(p.get("priceUsd")) if p.get("priceUsd") is not None else None
    except Exception:
        price_usd = None

    age_days = None
    try:
        ts_ms = p.get("pairCreatedAt") or p.get("createdAt")
        if ts_ms:
            age_days = max(0.0, (time.time()*1000 - float(ts_ms)) / (1000*60*60*24))
    except Exception:
        pass

    return {
        "ok": True,
        "source": "DexScreener",
        "chain": _short_chain(p),
        "dexId": p.get("dexId"),
        "pairAddress": p.get("pairAddress"),
        "tokenAddress": base_token.get("address"),
        "tokenSymbol": base_token.get("symbol"),
        "priceUsd": price_usd,
        "fdv": fdv,
        "marketCap": mcap,
        "liquidity": liq,
        "volume24h": vol24,
        "ageDays": age_days,
        "priceChanges": _price_changes(p),
        "links": _links(p),
        "asOf": _asof(p),
    }

def fetch_market(text: str):
    """Resolve user input (token or pair address, or URL) to market dict.

    Returns: { ok: bool, ... } with keys used by renderers_mdx.render_quick/render_details.
    Always includes 'sources' (list) and 'links' (dict).
    """
    raw = (text or "").strip()
    links = {}
    sources = []

    # Handle raw 0x… address (assume token by default)
    addr = None
    m = _ADDR_RE.search(raw)
    if m:
        addr = m.group(0)

    # Try token endpoint
    if addr:
        url = f"{DS_BASE}/tokens/{addr}"
        try:
            j = _http_json(url, timeout=7)
            sources.append(url)
            pairs = j.get("pairs") or []
            if pairs:
                p = _pick_best_pair(pairs)
                out = _market_from_pair(p)
                out["sources"] = sources
                out["links"] = {**links, **(out.get("links") or {})}
                return out
        except Exception as e:
            err = str(e)

    # If not found, try pair endpoint if the input looks like a pair
    if addr:
        url = f"{DS_BASE}/pairs/{addr}"
        try:
            j = _http_json(url, timeout=7)
            sources.append(url)
            p = (j.get("pair") or (j.get("pairs") or [None])[0])
            if isinstance(p, dict):
                out = _market_from_pair(p)
                out["sources"] = sources
                out["links"] = {**links, **(out.get("links") or {})}
                return out
        except Exception:
            pass

    # As a last resort, return a neutral stub (so renderer still works)
    return {
        "ok": False,
        "error": "not_found_or_no_pools",
        "sources": sources,
        "links": links,
    }
