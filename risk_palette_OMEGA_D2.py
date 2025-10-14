# Metridex OMEGA-713K — D2 Risk Palette
# Ensures score==20 maps to yellow (medium). Standalone, no external deps.

from typing import Tuple

__all__ = [
    "risk_bucket",
    "risk_color_for_score",
    "get_risk_emoji",
    "get_risk_badge",
]

# Thresholds (inclusive ranges).
# D2 requirement: score 20 must map to "yellow" (medium risk).
_THRESHOLDS = [
    (0, 19, "low", "green", "🟢"),
    (20, 39, "medium", "yellow", "🟡"),
    (40, 59, "elevated", "orange", "🟠"),
    (60, 79, "high", "red", "🔴"),
    (80, 100, "critical", "red", "⛔"),
]


def _clamp_score(score: int) -> int:
    try:
        s = int(score)
    except Exception:
        s = 0
    if s < 0:
        return 0
    if s > 100:
        return 100
    return s


def risk_bucket(score: int) -> str:
    """Return bucket for 0..100 score: low/medium/elevated/high/critical.
    D2: ensure 20 -> 'medium' (yellow)."""
    s = _clamp_score(score)
    for lo, hi, bucket, _, _ in _THRESHOLDS:
        if lo <= s <= hi:
            return bucket
    return "low"


def risk_color_for_score(score: int) -> str:
    """Return color name for UI: 'green'|'yellow'|'orange'|'red'. D2: 20 -> 'yellow'."""
    s = _clamp_score(score)
    for lo, hi, _, color, _ in _THRESHOLDS:
        if lo <= s <= hi:
            return color
    return "green"


def get_risk_emoji(score: int) -> str:
    """Return an emoji badge for the score bucket."""
    s = _clamp_score(score)
    for lo, hi, _, _, emoji in _THRESHOLDS:
        if lo <= s <= hi:
            return emoji
    return "🟢"


def get_risk_badge(score: int) -> Tuple[str, str]:
    """Return (emoji, bucket_name). Example: get_risk_badge(20) -> ('🟡', 'medium')."""
    return get_risk_emoji(score), risk_bucket(score)
