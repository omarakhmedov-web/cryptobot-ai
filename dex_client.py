
import os, json, requests, time
from typing import Optional, Dict, Any
from cache import cache_get, cache_set

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

def _age_days(ms: Optional[int]) -> Optional[float]:
    if not ms:
        return None
    try:
        return max(0.0, (time.time()*1000 - float(ms)) / (1000*60*60*24))
    except Exception:
        return None

def fetch_market(token_or_url: str) -> Dict[str, Any]:
    """
    Returns dict with:
      chain, pairSymbol, price, fdv, mc, liq, vol24h, delta24h,
      priceChanges {m5,h1,h6,h24}, volumes {m5,h1,h6,h24},
      ageDays, tokenAddress, pairAddress, links{site,dex,scan}
    """
    key = f"ds:{token_or_url}"
    cached = cache_get(key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    base = DS_PROXY if DS_PROXY else DS_BASE
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
        fdv = p.get("fdv"); mc = p.get("marketCap")

        liq = None
        if isinstance(p.get("liquidity"), dict):
            liq = p["liquidity"].get("usd") or p["liquidity"].get("base")

        vol = p.get("volume") or {}
        vol24h = vol.get("h24")
        volumes = {"m5": vol.get("m5"), "h1": vol.get("h1"), "h6": vol.get("h6"), "h24": vol.get("h24")}

        chg = p.get("priceChange") or {}
        priceChanges = {"m5": chg.get("m5"), "h1": chg.get("h1"), "h6": chg.get("h6"), "h24": chg.get("h24")}
        delta24h = priceChanges.get("h24")

        baseToken = p.get("baseToken", {}) or {}
        quoteToken = p.get("quoteToken", {}) or {}
        pairSym = f"{baseToken.get('symbol','?')}/{quoteToken.get('symbol','?')}"
        tokenAddress = baseToken.get("address")
        pairAddress = p.get("pairAddress")

        urlDex = p.get("url")
        urlSite = (p.get("info", {}).get("websites") or [{}])[0].get("url")

        scan = None
        if chain and tokenAddress:
            cl = chain.lower()
            if cl.startswith("eth"):
                scan = f"https://etherscan.io/token/{tokenAddress}"
            elif cl.startswith("bsc") or cl.startswith("bnb"):
                scan = f"https://bscscan.com/token/{tokenAddress}"
            elif cl.startswith("polygon") or cl == "matic":
                scan = f"https://polygonscan.com/token/{tokenAddress}"

        ageDays = _age_days(p.get("pairCreatedAt"))

        result = {
            "chain": chain,
            "pairSymbol": pairSym,
            "price": price,
            "fdv": fdv, "mc": mc, "liq": liq,
            "vol24h": vol24h, "priceChanges": priceChanges, "volumes": volumes,
            "delta24h": delta24h, "ageDays": ageDays,
            "source": "DexScreener",
            "tokenAddress": tokenAddress, "pairAddress": pairAddress,
            "links": {"site": urlSite, "dex": urlDex, "scan": scan}
        }
    except Exception as e:
        result = {"source": "partial", "error": str(e)}

    cache_set(key, json.dumps(result), DEX_TTL)
    return result
