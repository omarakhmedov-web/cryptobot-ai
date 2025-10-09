from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

@dataclass
class Factors:
    # Contract risks
    honeypot: bool
    blacklist: bool
    pausable: bool
    upgradeable: bool
    mint: bool
    maxTx: float | None
    maxWallet: float | None
    taxes: Dict[str, float]  # {"buy":x,"sell":y}
    # Liquidity/trade
    liq_usd: float | None
    fdv: float | None
    vol24h: float | None
    delta24h: float | None
    # Web footprint
    whois_created: str | None
    ssl_ok: bool | None
    wayback_first: str | None

@dataclass
class Verdict:
    score: int
    level: str
    reasons: List[str]

def _level(score: int) -> str:
    if score <= 24: return "LOW"
    if score <= 49: return "MEDIUM"
    if score <= 74: return "HIGH"
    return "CRITICAL"

def compute_verdict(f: Factors) -> Verdict:
    score = 0
    reasons: List[str] = []

    # Contract risks (40 pts total potential)
    if f.honeypot: score += 30; reasons.append("Honeypot suspicion")
    if f.blacklist: score += 10; reasons.append("Blacklist control")
    if f.pausable: score += 5; reasons.append("Pausable contract")
    if f.upgradeable: score += 5; reasons.append("Upgradeable/proxy")
    if f.mint: score += 10; reasons.append("Mint capability")
    if (f.maxTx or 0) and f.maxTx < 0.01: score += 5; reasons.append("Very low maxTx")
    if (f.maxWallet or 0) and f.maxWallet < 0.02: score += 5; reasons.append("Very low maxWallet")
    taxes_buy = (f.taxes or {}).get("buy", 0.0)
    taxes_sell = (f.taxes or {}).get("sell", 0.0)
    if taxes_buy > 5 or taxes_sell > 5: score += 6; reasons.append("High taxes")

    # Liquidity (25 pts)
    if f.liq_usd is not None and f.fdv:
        ratio = f.liq_usd / max(f.fdv, 1)
        if ratio < 0.002: score += 15; reasons.append("Very thin liquidity vs FDV")
        elif ratio < 0.005: score += 10; reasons.append("Thin liquidity vs FDV")
    if (f.vol24h or 0) < 50000: score += 3; reasons.append("Low 24h volume")

    # Trading params (15 pts)
    if (f.delta24h or 0) < -30: score += 8; reasons.append("Severe 24h drop")
    if (f.delta24h or 0) > 300: score += 6; reasons.append("Extreme pump risk")

    # Web footprint (10 pts)
    if f.ssl_ok is False: score += 3; reasons.append("No/invalid SSL")
    if f.whois_created is None: score += 2; reasons.append("Unknown domain age")
    if f.wayback_first is None: score += 2; reasons.append("No Wayback snapshots")

    level = _level(min(score, 100))
    return Verdict(score=min(score,100), level=level, reasons=reasons[:8])  # cap reasons
