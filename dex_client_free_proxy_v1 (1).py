# dex_client_free_proxy_v1.py
# Thin proxy to use market_aggregator_free with existing fetch_market(text) signature.
import re
from typing import Dict, Any, Optional

try:
    from market_aggregator_free import fetch_market as _agg_fetch
except Exception as _e:
    _agg_fetch = None

_HEX40 = re.compile(r"^0x[a-fA-F0-9]{40}$")
_HEX64 = re.compile(r"^0x[a-fA-F0-9]{64}$")

def _parse_input(text: str):
    """Return tuple (chain, token, pair) suitable for market_aggregator_free.fetch_market()."""
    t = (text or "").strip()
    if _HEX40.match(t):
        return None, t, None  # token address
    if _HEX64.match(t):
        # TX hash — let upstream resolve; here we don't support direct TX → pair
        return None, None, None
    low = t.lower()
    # DexScreener URLs
    # examples:
    #   https://dexscreener.com/ethereum/0xPAIR
    #   https://dexscreener.com/ethereum/0xTOKEN?...
    m = re.search(r"dexscreener\.com/([a-z0-9\-]+)/0x([0-9a-f]{40})", low)
    if m:
        chain = m.group(1)
        addr = "0x" + m.group(2)
        return chain, addr, None
    return None, None, None

def fetch_market(text: str) -> Dict[str, Any]:
    """Match the legacy signature and delegate to free aggregator."""
    if _agg_fetch is None:
        return {"ok": False, "error": "free_aggregator_unavailable", "sources": [], "links": {}}
    chain, token, pair = _parse_input(text)
    try:
        res = _agg_fetch(chain, token=token, pair=pair) or {}
    except Exception as e:
        return {"ok": False, "error": f"free_aggregator_error: {e}", "sources": [], "links": {}}
    # Ensure minimum fields expected by renderers
    res.setdefault("sources", [])
    res.setdefault("links", {})
    res.setdefault("priceChanges", {})
    # Back-compat: source label
    if "source" not in res and res.get("sources"):
        res["source"] = ",".join(str(s) for s in res["sources"] if s)
    return res
