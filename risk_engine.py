from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# --- Tunable thresholds (aligned with Why++ heuristics) ---
LIQ_POSITIVE      = 25_000     # >= — healthy
LIQ_LOW           = 10_000     # < — low
LIQ_VERY_LOW      = 3_000      # < — very low

VOL_ACTIVE        = 50_000     # >= — active
VOL_THIN          = 5_000      # < — thin

DELTA24_PUMP2     = 300        # > — parabolic
DELTA24_PUMP1     = 100        # > — strong
DELTA24_DUMP      = -70        # < — severe dump
DELTA24_OK_LOW    = -30        # -30% .. +80% ~ moderate band
DELTA24_OK_HIGH   = 80

AGE_WEEK_D        = 7.0        # >= — established
AGE_DAY_D         = 1.0        # < — <1d
AGE_HOUR_D        = 1.0/24.0   # < — <1h

FDV_MC_RISK       = 5.0        # ratio > — watch

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
    Transparent, defensive risk scoring based on market signals.
    Reasons include both risk flags and positives (to feed Why/Why++ consistently).
    """
    reasons: List[str] = []
    score = 0

    m = market or {}
    liq     = _to_float(m.get("liq"))
    vol24   = _to_float(m.get("vol24h"))
    delta24 = _to_float((m.get("priceChanges") or {}).get("h24"))
    delta5m = _to_float((m.get("priceChanges") or {}).get("m5"))
    age_d   = _to_float(m.get("ageDays"))
    fdv     = _to_float(m.get("fdv"))
    mc      = _to_float(m.get("mc"))
    token   = m.get("tokenAddress")
    price   = _to_float(m.get("price"))

    # Unknown / empty market
    if all(x is None for x in (liq, vol24, fdv, mc, price)):
        reasons.append("No market data (liq/vol/FDV/MC/price) — verdict set to UNKNOWN")
        return Verdict(score=0, level="UNKNOWN", reasons=reasons)

    # Liquidity
    if liq is None:
        score += 10; reasons.append("Liquidity data unavailable")
    else:
        if liq < LIQ_VERY_LOW:
            score += 30; reasons.append(f"Very low liquidity (${liq:,.0f})")
        elif liq < LIQ_LOW:
            score += 18; reasons.append(f"Low liquidity (${liq:,.0f})")
        elif liq < LIQ_POSITIVE:
            score += 8;  reasons.append(f"Modest liquidity (${liq:,.0f})")
        else:
            reasons.append(f"Healthy liquidity (${liq:,.0f})")

    # 24h Volume
    if vol24 is None:
        score += 5; reasons.append("24h trading volume unavailable")
    else:
        if vol24 < VOL_THIN:
            score += 12; reasons.append(f"Thin 24h volume (${vol24:,.0f})")
        elif vol24 < VOL_ACTIVE:
            score += 5;  reasons.append(f"Modest 24h volume (${vol24:,.0f})")
        else:
            reasons.append(f"Active trading (${vol24:,.0f} / 24h)")

    # Momentum / Volatility
    if delta24 is not None:
        if delta24 > DELTA24_PUMP2:
            score += 22; reasons.append(f"Parabolic 24h pump (+{delta24:.0f}%)")
        elif delta24 > DELTA24_PUMP1:
            score += 12; reasons.append(f"Strong 24h pump (+{delta24:.0f}%)")
        elif delta24 < DELTA24_DUMP:
            score += 10; reasons.append(f"Severe 24h dump ({delta24:.0f}%)")
        elif DELTA24_OK_LOW < delta24 < DELTA24_OK_HIGH:
            reasons.append(f"Moderate 24h move ({delta24:+.0f}%)")

    if delta5m is not None and abs(delta5m) > 50:
        score += 8; reasons.append(f"Extreme 5m volatility ({delta5m:+.0f}%)")

    # Age
    if age_d is None:
        score += 8; reasons.append("Unknown pair age")
    else:
        if age_d < AGE_HOUR_D:
            score += 28; reasons.append("Pair is <1h old")
        elif age_d < AGE_DAY_D:
            score += 20; reasons.append("Pair is <1 day old")
        elif age_d < AGE_WEEK_D:
            score += 10; reasons.append("Pair is <1 week old")
        else:
            reasons.append(f"Established pair (~{age_d:.1f}d)")

    # FDV / MC
    if fdv is not None and mc is not None and fdv > 0 and mc > 0:
        ratio = fdv / mc
        if ratio > FDV_MC_RISK:
            score += 6; reasons.append(f"FDV/MC unusually high (~{ratio:.1f}x)")
    else:
        reasons.append("FDV/MC not available")

    # Token metadata
    if not token:
        score += 6; reasons.append("Token address not provided")

    # Clamp & bucket
    if score < 0: score = 0
    if score > 100: score = 100
    level = _bucket(score)

    if not reasons:
        reasons.append("No specific risk flags")

    # De-duplicate reasons preserving order
    seen = set()
    deduped: List[str] = []
    for r in reasons:
        if r and r not in seen:
            deduped.append(r); seen.add(r)

    return Verdict(score=score, level=level, reasons=deduped)
