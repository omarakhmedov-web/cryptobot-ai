from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import os

# --- Default thresholds (fallbacks) ---
DEFAULTS = {
    "LIQ_POSITIVE": 25_000,
    "LIQ_LOW": 10_000,
    "LIQ_VERY_LOW": 3_000,
    "VOL_ACTIVE": 50_000,
    "VOL_THIN": 5_000,
}

# --- Chain-aware baselines (can be tuned) ---
# Rationale: on Ethereum depth requirements are materially higher than on BSC/Polygon.
CHAIN_BASE = {
    "eth":     {"LIQ_POSITIVE": 1_000_000, "LIQ_LOW": 200_000, "LIQ_VERY_LOW": 50_000,  "VOL_ACTIVE": 2_000_000, "VOL_THIN": 25_000},
    "bsc":     {"LIQ_POSITIVE":   300_000, "LIQ_LOW":  60_000, "LIQ_VERY_LOW": 12_000,  "VOL_ACTIVE":   600_000, "VOL_THIN": 12_000},
    "polygon": {"LIQ_POSITIVE":   200_000, "LIQ_LOW":  40_000, "LIQ_VERY_LOW":  8_000,  "VOL_ACTIVE":   400_000, "VOL_THIN":  8_000},
    # other chains fall back to DEFAULTS
}

def _env_num(key: str, default: int) -> int:
    try:
        v = os.getenv(key)
        if v is None or v == "":
            return default
        return int(float(v))
    except Exception:
        return default

def _short_chain(market: Dict[str, Any]) -> str:
    ch = (market or {}).get("chain") or ""
    ch = str(ch).strip().lower()
    mp = {"ethereum":"eth","eth":"eth","bsc":"bsc","binance smart chain":"bsc","polygon":"polygon","matic":"polygon",
          "arbitrum":"arb","arb":"arb","optimism":"op","op":"op","base":"base","avalanche":"avax","avax":"avax",
          "fantom":"ftm","ftm":"ftm","sol":"sol","solana":"sol"}
    return mp.get(ch, ch)

def _thresholds(market: Dict[str, Any]) -> Dict[str, int]:
    short = _short_chain(market)
    base = dict(DEFAULTS)
    base.update(CHAIN_BASE.get(short, {}))
    # Env overrides (global and per-chain). Example: LIQ_POSITIVE_ETH=1500000
    def maybe_override(name: str) -> None:
        nonlocal base, short
        base[name] = _env_num(name, base[name])
        per_chain = _env_num(f"{name}_{short.upper()}", base[name])
        base[name] = per_chain
    for k in ("LIQ_POSITIVE","LIQ_LOW","LIQ_VERY_LOW","VOL_ACTIVE","VOL_THIN"):
        maybe_override(k)
    return base

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
    Chain-aware risk scoring.
    Reasons include both risk flags and positives (to feed Why/Why++ consistently).
    """
    reasons: List[str] = []
    score = 0

    m = market or {}
    thr = _thresholds(m)

    liq     = _to_float(m.get("liq"))
    vol24   = _to_float(m.get("vol24h"))
    delta24 = _to_float((m.get("priceChanges") or {}).get("h24"))
    delta5m = _to_float((m.get("priceChanges") or {}).get("m5"))
    age_d   = _to_float(m.get("ageDays"))
    fdv     = _to_float(m.get("fdv"))
    mc      = _to_float(m.get("mc"))
    price   = _to_float(m.get("price"))

    # Explicit "not tradable" / no-pool case
    if (not m.get("ok")) and (m.get("pairAddress") in (None, "", "—")) and (liq is None) and (vol24 is None):
        reasons.append("No pools (not tradable)")
        return Verdict(score=80, level="HIGH", reasons=reasons)

    # Unknown / empty market
    if all(x is None for x in (liq, vol24, fdv, mc, price)):
        reasons.append("No market data (liq/vol/FDV/MC/price) — verdict set to UNKNOWN")
        return Verdict(score=0, level="UNKNOWN", reasons=reasons)

    # Liquidity
    if liq is None:
        score += 10; reasons.append("Liquidity data unavailable")
    else:
        if liq < thr["LIQ_VERY_LOW"]:
            score += 30; reasons.append(f"Very low liquidity (${liq:,.0f})")
        elif liq < thr["LIQ_LOW"]:
            score += 18; reasons.append(f"Low liquidity (${liq:,.0f})")
        elif liq < thr["LIQ_POSITIVE"]:
            score += 8;  reasons.append(f"Modest liquidity (${liq:,.0f})")
        else:
            reasons.append(f"Healthy liquidity (${liq:,.0f})")

    # 24h Volume
    if vol24 is None:
        score += 5; reasons.append("24h trading volume unavailable")
    else:
        if vol24 < thr["VOL_THIN"]:
            score += 12; reasons.append(f"Thin 24h volume (${vol24:,.0f})")
        elif vol24 < thr["VOL_ACTIVE"]:
            score += 5;  reasons.append(f"Modest 24h volume (${vol24:,.0f})")
        else:
            reasons.append(f"Active trading (${vol24:,.0f} / 24h)")

    # Price action
    if delta24 is not None:
        if delta24 > 300:  # parabolic pumps
            score += 12; reasons.append(f"Extreme 24h move ({delta24:+.0f}%)")
        elif delta24 > 100:
            score += 6;  reasons.append(f"Strong 24h move ({delta24:+.0f}%)")
        elif delta24 < -70:
            score += 10; reasons.append(f"Severe 24h drawdown ({delta24:+.0f}%)")
        elif -30 < delta24 < 80:
            reasons.append(f"Moderate 24h move ({delta24:+.0f}%)")

    # Age risks/positives
    if age_d is None:
        score += 6; reasons.append("Pair age unknown")
    else:
        if age_d < 1/24:
            score += 18; reasons.append("Just launched (<1h)")
        elif age_d < 1:
            score += 12; reasons.append("Newly created pair (<1d)")
        elif age_d >= 7:
            reasons.append(f"Established >1 week (~{age_d:.1f}d)")

    # FDV/MC sanity
    if fdv is not None and mc is not None and mc > 0:
        ratio = fdv/mc
        if ratio > 5.0:
            score += 3; reasons.append(f"FDV/MC high (~{ratio:.1f}x)")

    level = _bucket(score)
    return Verdict(score=score, level=level, reasons=reasons)
