import os
import json
import requests
from typing import Optional, Dict, Any
from common import short
from cache import cache_get, cache_set
from common import getenv_int

DEX_TTL = int(os.getenv("CACHE_TTL_DEX_SEC", "90"))
DS_BASE = os.getenv("DS_BASE", "https://api.dexscreener.com")
DS_PROXY = os.getenv("DS_PROXY_URL", "").strip()

def _http_get_json(url: str, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

def fetch_market(token_or_url: str) -> Dict[str, Any]:
    """
    Returns a dict with keys:
      chain, pairSymbol, price, fdv, mc, liq, vol24h, delta24h, source, tokenAddress, pairAddress, links{site, dex, scan}
    On failure returns {'source':'partial', 'error': '...'} minimally.
    """
    key = f"ds:{token_or_url}"
    cached = cache_get(key)
    if cached:
        try: return json.loads(cached)
        except Exception: pass

    base = DS_PROXY if DS_PROXY else DS_BASE
    # Guess endpoint: use /latest/dex/tokens/{address} if address-like, else try search
    url = f"{base}/latest/dex/search?q={token_or_url}"
    data = _http_get_json(url) or {}

    result = {"source": "partial"}
    try:
        pairs = data.get("pairs") or []
        if not pairs:
            cache_set(key, json.dumps(result), DEX_TTL)
            return result
        p = pairs[0]
        chain = p.get("chainId") or p.get("chain") or "ethereum"
        price = p.get("priceUsd") or p.get("priceNative")
        fdv = p.get("fdv")
        mc = p.get("marketCap")
        liq = None
        if isinstance(p.get("liquidity"), dict):
            liq = p["liquidity"].get("usd") or p["liquidity"].get("base")
        vol24h = p.get("volume", {}).get("h24") if isinstance(p.get("volume"), dict) else p.get("h24Volume")
        delta24h = p.get("priceChange", {}).get("h24") if isinstance(p.get("priceChange"), dict) else p.get("h24Change")
        baseToken = p.get("baseToken", {})
        quoteToken = p.get("quoteToken", {})
        pairSym = f"{baseToken.get('symbol','?')}/{quoteToken.get('symbol','?')}"

        tokenAddress = baseToken.get("address")
        pairAddress = p.get("pairAddress")
        urlDex = p.get("url")
        urlSite = p.get("info", {}).get("websites", [{}])[0].get("url")

        result = {
            "chain": chain,
            "pairSymbol": pairSym,
            "price": price,
            "fdv": fdv,
            "mc": mc,
            "liq": liq,
            "vol24h": vol24h,
            "delta24h": delta24h,
            "source": "DexScreener",
            "tokenAddress": tokenAddress,
            "pairAddress": pairAddress,
            "links": {
                "site": urlSite,
                "dex": urlDex,
            }
        }
    except Exception as e:
        result = {"source":"partial","error":str(e)}

    cache_set(key, json.dumps(result), DEX_TTL)
    return result
