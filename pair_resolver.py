# pair_resolver.py — OMEGA-713K
from __future__ import annotations
import os, json
from typing import Optional, Dict, Any
from urllib.request import Request, urlopen
from urllib.parse import quote
from urllib.error import URLError, HTTPError

def _http_get(url: str, timeout: float = 6.0) -> Optional[Dict[str,Any]]:
    try:
        req = Request(url, headers={"User-Agent":"Metridex/OMEGA-713K"})
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8","ignore")
        return json.loads(raw)
    except Exception:
        return None

def resolve_pair(chain_short: str, token_addr: Optional[str]) -> Optional[str]:
    """
    Return best pairAddress for given chain ('eth','bsc','polygon',...) and token address.
    Strategy: DexScreener /tokens/<chain>/<token> and pick top-liquidity pair in that chain.
    """
    if not token_addr: 
        return None
    chain_short = (chain_short or "").lower()
    url = f"https://api.dexscreener.com/latest/dex/tokens/{quote(chain_short)}/{quote(token_addr)}"
    j = _http_get(url, timeout=float(os.getenv("PAIR_RESOLVER_TIMEOUT_S","5")))
    if not j: 
        return None
    pairs = j.get("pairs") or []
    best = None
    best_liq = -1.0
    for p in pairs:
        if (p.get("chainId") or "").lower() != chain_short:
            continue
        liq = 0.0
        try:
            liq = float((p.get("liquidity") or {}).get("usd") or 0.0)
        except Exception:
            pass
        if liq > best_liq and p.get("pairAddress"):
            best = p
            best_liq = liq
    return (best or {}).get("pairAddress")
