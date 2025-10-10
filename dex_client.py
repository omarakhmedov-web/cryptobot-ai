from __future__ import annotations
import os
from typing import Dict, Any, Optional, List
from market_aggregator_free import fetch_market as _fetch_market_core
from common import enabled_networks

def fetch_market(chain: Optional[str] = None, token: Optional[str] = None, pair: Optional[str] = None) -> Dict[str, Any]:
    """
    Free-first market fetch with autodetect:
    - If chain is provided, query that chain.
    - Else iterate over ENABLED_NETWORKS and return first successful result.
    Returns normalized market dict with 'ok', 'sources', 'asof', etc.
    """
    # Normalize chain id
    if chain and chain.strip() in ("—", "-", "_", "unknown", "none", "n/a"):
        chain = None
    if chain:
        res = _fetch_market_core(chain.strip().lower(), token=token, pair=pair)
        if res.get("ok"):
            return res
        # Fallback: try autodetect if single chain failed
    for ch in enabled_networks():
        res = _fetch_market_core(ch, token=token, pair=pair)
        if res.get("ok"):
            res["chain"] = ch
            return res
    return {"ok": False, "error": "no market found", "sources": [], "chain": chain or "—"}
