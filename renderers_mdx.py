# renderers_mdx.py — small safety utilities for MDX renderers (FDV/MC sanity, Age)
from __future__ import annotations
from typing import Dict, Any, Optional

def _num(x):
    try:
        return float(x)
    except Exception:
        return None

def sanitize_market_fields(m: Dict[str, Any]) -> Dict[str, Any]:
    """Fix common anomalies without changing upstream fetchers."""
    m = dict(m or {})
    fdv = _num(m.get("fdv") or m.get("fdvUSD"))
    mc  = _num(m.get("mc")  or m.get("marketCap") or m.get("mcUSD"))
    if fdv is not None and mc is not None and fdv < mc:
        # Swap display only
        m["fdv"], m["mc"] = mc, fdv
        m["__note_fdv_mc_fixed"] = True
    # Age from pairCreatedAt*
    ts = m.get("pairCreatedAtMs") or m.get("pairCreatedAt") or None
    if isinstance(ts, (int, float)) and ts:
        import time
        if ts < 10**12:  # seconds -> ms
            ts *= 1000
        age_days = max(0.0, (time.time()*1000 - ts) / (1000*60*60*24))
        m["ageDays"] = age_days
    return m

def age_label(age_days: Optional[float]) -> Optional[str]:
    try:
        d = float(age_days)
    except Exception:
        return None
    if d >= 365*3: return f"Long-standing (>3 years) (~{d/365.0:.1f}y)"
    if d >= 365*2: return f"Long-standing (>2 years) (~{d/365.0:.1f}y)"
    if d >= 365:   return f"Established >1 year (~{d/365.0:.1f}y)"
    if d >= 180:   return f"Established >6 months (~{d:.0f}d)"
    if d >= 90:    return f"Established >3 months (~{d:.0f}d)"
    if d >= 30:    return f"Established >1 month (~{d:.0f}d)"
    if d >= 7:     return f"Established >1 week (~{d:.0f}d)"
    return f"Newly created (~{d:.0f}d)"

__all__ = ["sanitize_market_fields", "age_label"]
