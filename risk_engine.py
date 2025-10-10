from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class Verdict:
    score: int
    level: str
    reasons: List[str]

def _to_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None

def _bucket(score: int) -> str:
    # Higher score = higher risk
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"

def compute_verdict(market: Dict[str, Any]) -> Verdict:
    """
    Compute a simple, transparent risk score from market dict.
    The function is defensive and only uses dict.get() (no attribute access).
    """
    reasons: List[str] = []
    score = 0

    # Extract inputs safely
    liq = _to_float((market or {}).get("liq"))
    vol24 = _to_float((market or {}).get("vol24h"))
    delta24 = _to_float(((market or {}).get("priceChanges") or {}).get("h24"))
    delta5m = _to_float(((market or {}).get("priceChanges") or {}).get("m5"))
    age_days = _to_float((market or {}).get("ageDays"))
    fdv = _to_float((market or {}).get("fdv"))
    mc = _to_float((market or {}).get("mc"))
    token_addr = (market or {}).get("tokenAddress")

    # Liquidity checks
    if liq is None:
        score += 10; reasons.append("No liquidity data")
    else:
        if liq < 3000:
            score += 30; reasons.append(f"Very low liquidity (${liq:,.0f})")
        elif liq < 10000:
            score += 18; reasons.append(f"Low liquidity (${liq:,.0f})")
        elif liq < 25000:
            score += 8; reasons.append(f"Modest liquidity (${liq:,.0f})")
        else:
            reasons.append(f"Healthy liquidity (${liq:,.0f})")

    # Volume checks
    if vol24 is None:
        score += 5; reasons.append("No 24h volume data")
    else:
        if vol24 < 5000:
            score += 12; reasons.append(f"Thin 24h volume (${vol24:,.0f})")
        elif vol24 < 50000:
            score += 5; reasons.append(f"Modest 24h volume (${vol24:,.0f})")
        else:
            reasons.append(f"Active trading (${vol24:,.0f} / 24h)")

    # Price change momentum risk
    if delta24 is not None:
        if delta24 > 300:
            score += 22; reasons.append(f"Parabolic 24h pump (+{delta24:.0f}%)")
        elif delta24 > 100:
            score += 12; reasons.append(f"Strong 24h pump (+{delta24:.0f}%)")
        elif delta24 < -70:
            score += 10; reasons.append(f"Severe 24h dump ({delta24:.0f}%)")
    if delta5m is not None and abs(delta5m) > 50:
        score += 8; reasons.append(f"Extreme 5m volatility ({delta5m:+.0f}%)")

    # Age risk
    if age_days is None:
        score += 8; reasons.append("Unknown pair age")
    else:
        if age_days < 1/24:  # <1 hour
            score += 28; reasons.append("Pair is <1h old")
        elif age_days < 1:
            score += 20; reasons.append("Pair is <1 day old")
        elif age_days < 7:
            score += 10; reasons.append("Pair is <1 week old")
        else:
            reasons.append(f"Established pair (~{age_days:.1f}d)")

    # FDV/MC sanity (optional)
    if fdv is not None and mc is not None and fdv > 0 and mc > 0:
        ratio = fdv / mc if mc else None
        if ratio is not None and ratio > 5:
            score += 6; reasons.append(f"FDV/MC unusually high (~{ratio:.1f}x)")
    else:
        reasons.append("FDV/MC not available")

    # Token metadata
    if not token_addr:
        score += 6; reasons.append("Token address missing")

    # Clamp score
    if score < 0: score = 0
    if score > 100: score = 100

    level = _bucket(score)

    # Ensure reasons are not empty
    if not reasons:
        reasons.append("No specific risk flags")

    return Verdict(score=score, level=level, reasons=reasons)
