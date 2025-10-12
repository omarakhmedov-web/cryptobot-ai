# dex_client.py — FIXED (2025-10-12)
# Drop-in replacement providing robust DexScreener fetch with safe parsing.
# Public API:
#   fetch_market(q: str) -> dict
#
# Returned dict shape (keys are stable and safe for renderers):
# {
#   "chain": str or None,
#   "symbol": str or None,
#   "price": float or None,
#   "fdv": float or None,
#   "mc": float or None,
#   "liquidity": float or None,
#   "vol24h": float or None,
#   "delta_5m": float or None,
#   "delta_1h": float or None,
#   "delta_24h": float or None,
#   "age_days": float or None,
#   "token_address": str or None,
#   "pair_address": str or None,
#   "dex_url": str or None,
#   "scan_url": str or None,
#   "site": str or None,
#   "source": "DexScreener",
# }
#
# Notes:
# - Uses DS_PROXY_URL or DEX_API_BASE if set, else falls back to DexScreener public API.
# - Never raises on network/parse errors; returns empty dict instead.
# - Chooses the best pair by (liquidity_usd, vol24h) heuristics.
#
from __future__ import annotations

import os
import re
import time
import math
import json
from typing import Any, Dict, Optional, List, Tuple

try:
    import requests  # Render image already has requests; if not, add to requirements.txt
except Exception:  # pragma: no cover
    requests = None  # type: ignore

HEX_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")

def _now_ms() -> int:
    return int(time.time() * 1000)

def _env_base() -> str:
    # Priority: Cloudflare worker proxy > Custom base > Public API
    return (
        os.getenv("DS_PROXY_URL")
        or os.getenv("DEX_API_BASE")
        or "https://api.dexscreener.com/latest/dex"
    ).rstrip("/")

def _headers() -> Dict[str, str]:
    return {
        "User-Agent": "MetridexBot/1.0 (+https://metridex.com)",
        "Accept": "application/json",
    }

def _http_get(url: str, params: Optional[Dict[str, Any]] = None, timeout: float = 8.0) -> Dict[str, Any]:
    if requests is None:
        return {}
    try:
        r = requests.get(url, params=params or {}, headers=_headers(), timeout=timeout)
        if r.status_code != 200:
            return {}
        return r.json() if r.headers.get("content-type","").startswith("application/json") else {}
    except Exception:
        return {}

def _pick_best_pair(pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not pairs:
        return {}
    # Score by liquidityUSD first, then vol24h; be resilient to missing keys
    def score(p: Dict[str, Any]) -> Tuple[float, float]:
        liq = 0.0
        vol = 0.0
        # liquidity may be dict {'usd': ...} or flat 'liquidity' with nested usd
        liq_val = None
        liq_block = p.get("liquidity") or {}
        if isinstance(liq_block, dict):
            liq_val = liq_block.get("usd") or liq_block.get("base") or liq_block.get("quote")
        if isinstance(liq_val, (int, float)):
            liq = float(liq_val)

        vol_val = p.get("volume",{}).get("h24") if isinstance(p.get("volume"), dict) else None
        if not isinstance(vol_val, (int, float)):
            vol_val = p.get("volume24h") or p.get("volume24hUsd") or 0.0
        if isinstance(vol_val, (int, float)):
            vol = float(vol_val)
        return (liq, vol)

    pairs_sorted = sorted(pairs, key=score, reverse=True)
    return pairs_sorted[0] if pairs_sorted else {}

def _derive_scan_url(chain: Optional[str], token: Optional[str]) -> Optional[str]:
    if not chain or not token:
        return None
    chain = chain.lower()
    if chain in ("eth","ethereum"):
        return f"https://etherscan.io/token/{token}"
    if chain in ("bsc","bnb","bnb-smart-chain","binance-smart-chain"):
        return f"https://bscscan.com/token/{token}"
    if chain in ("polygon","matic"):
        return f"https://polygonscan.com/token/{token}"
    if chain in ("arbitrum","arbitrum-one"):
        return f"https://arbiscan.io/token/{token}"
    if chain in ("base",):
        return f"https://basescan.org/token/{token}"
    # Fallback generic
    return None

def _safe_float(v: Any) -> Optional[float]:
    try:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return float(v)
        # strings like "123.45"
        return float(str(v).replace(",", "").strip())
    except Exception:
        return None

def _age_days_from_ms(pair_created_at_ms: Optional[int]) -> Optional[float]:
    if not isinstance(pair_created_at_ms, (int, float)):
        return None
    try:
        age_ms = max(0, _now_ms() - int(pair_created_at_ms))
        return round(age_ms / (1000 * 60 * 60 * 24), 1)
    except Exception:
        return None

def _parse_market_from_pair(p: Dict[str, Any]) -> Dict[str, Any]:
    # Defensive parsing across API shape variants
    chain = (p.get("chainId") or p.get("chain") or "").lower() or None
    symbol = p.get("baseToken",{}).get("symbol") and p.get("quoteToken",{}).get("symbol")
    # Build symbol "BASE/QUOTE" if possible
    base_sym = (p.get("baseToken") or {}).get("symbol")
    quote_sym = (p.get("quoteToken") or {}).get("symbol")
    if isinstance(base_sym, str) and isinstance(quote_sym, str):
        symbol = f"{base_sym}/{quote_sym}"
    else:
        symbol = p.get("symbol") or None

    price = _safe_float(p.get("priceUsd") or p.get("price") or p.get("priceUsdDecimal"))

    fdv = _safe_float(p.get("fdv") or (p.get("fdvInfo") or {}).get("fdv"))
    mc = _safe_float(p.get("marketCap") or (p.get("mcInfo") or {}).get("marketCap"))

    # Liquidity
    liq_usd = None
    liq_block = p.get("liquidity")
    if isinstance(liq_block, dict):
        liq_usd = _safe_float(liq_block.get("usd"))
    if liq_usd is None:
        liq_usd = _safe_float(p.get("liquidityUsd") or p.get("liqUsd"))

    # Volume
    vol24 = None
    vol_block = p.get("volume")
    if isinstance(vol_block, dict):
        vol24 = _safe_float(vol_block.get("h24"))
    if vol24 is None:
        vol24 = _safe_float(p.get("volume24h") or p.get("volume24hUsd"))

    # Deltas
    ch = p.get("priceChange") or {}
    delta_5m = _safe_float(ch.get("m5"))
    delta_1h = _safe_float(ch.get("h1"))
    delta_24h = _safe_float(ch.get("h24"))

    # Addresses
    token_addr = (p.get("baseToken") or {}).get("address")
    pair_addr = p.get("pairAddress") or p.get("pairCreatedAddress") or p.get("pair")

    # Links
    dex_url = p.get("url") or None
    scan_url = _derive_scan_url(chain, token_addr)

    # Age
    age_days = _age_days_from_ms(p.get("pairCreatedAt"))

    site = None  # not provided by DexScreener reliably; leave None

    out = {
        "chain": chain,
        "symbol": symbol,
        "price": price,
        "fdv": fdv,
        "mc": mc,
        "liquidity": liq_usd,
        "vol24h": vol24,
        "delta_5m": delta_5m,
        "delta_1h": delta_1h,
        "delta_24h": delta_24h,
        "age_days": age_days,
        "token_address": token_addr,
        "pair_address": pair_addr,
        "dex_url": dex_url,
        "scan_url": scan_url,
        "site": site,
        "source": "DexScreener",
    }
    # Sanity: ensure FDV >= MC if both exist; if inverted, swap as a safe heuristic
    if out["fdv"] is not None and out["mc"] is not None and out["fdv"] < out["mc"]:
        # Some API shapes may label fields backwards; correct for display
        out["fdv"], out["mc"] = out["mc"], out["fdv"]
    return out

def _ds_tokens_endpoint(addr: str) -> str:
    return f"{_env_base()}/tokens/{addr}"

def _ds_search_endpoint(q: str) -> str:
    return f"{_env_base()}/search"

def _extract_hex(q: str) -> Optional[str]:
    q = (q or "").strip()
    m = HEX_ADDR.match(q)
    return m.group(0) if m else None

def fetch_market(q: str) -> Dict[str, Any]:
    """
    Resolve token/URL/text -> best market snapshot via DexScreener.
    Returns {} on failure, never raises.
    """
    addr = _extract_hex(q)
    # Fallback: extract address from a URL if present
    if addr is None and isinstance(q, str):
        m = re.search(r"(0x[a-fA-F0-9]{40})", q)
        if m:
            addr = m.group(1)

    # Try tokens endpoint if we have an address
    data = {}
    if addr:
        data = _http_get(_ds_tokens_endpoint(addr))
    # If no data or no pairs, try search
    pairs = (data or {}).get("pairs") or []
    if not pairs:
        s = _http_get(_ds_search_endpoint(addr or (q or "")))
        pairs = (s or {}).get("pairs") or []

    if not isinstance(pairs, list) or not pairs:
        return {}  # ensure graceful unknown state upstream

    best = _pick_best_pair(pairs)
    if not best:
        return {}

    market = _parse_market_from_pair(best)
    # Ensure minimal keys exist even if None (renderers rely on presence)
    base = {
        "chain": None,"symbol": None,"price": None,"fdv": None,"mc": None,
        "liquidity": None,"vol24h": None,"delta_5m": None,"delta_1h": None,"delta_24h": None,
        "age_days": None,"token_address": None,"pair_address": None,"dex_url": None,"scan_url": None,
        "site": None,"source": "DexScreener",
    }
    base.update({k: market.get(k) for k in base.keys()})
    return base
