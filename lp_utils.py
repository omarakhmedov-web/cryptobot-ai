"""
lp_utils.py — LP-lite helpers
-----------------------------
• Compute LP status from burned/locked percentages.
• Provide explorer labels/URLs per chain for LP token holders links.
"""

from typing import Optional, Tuple

EXPLORERS = {
    "eth":  ("Etherscan",   "https://etherscan.io"),
    "ethereum": ("Etherscan", "https://etherscan.io"),
    "bsc":  ("BscScan",     "https://bscscan.com"),
    "bnb":  ("BscScan",     "https://bscscan.com"),
    "polygon": ("Polygonscan", "https://polygonscan.com"),
    "matic": ("Polygonscan", "https://polygonscan.com"),
}

def explorer_for_chain(chain: str) -> Tuple[str, str]:
    chain = (chain or "").lower()
    return EXPLORERS.get(chain, ("Explorer", ""))

def lp_status(burned_pct: Optional[float], locked_pct: Optional[float]) -> str:
    b = burned_pct or 0.0
    l = locked_pct or 0.0
    # Priority: locked-majority > burned-majority > locked-partial > burned-partial > unknown
    if l >= 50.0:
        return "locked-majority"
    if b >= 50.0:
        return "burned-majority"
    if 0.0 < l < 50.0:
        return "locked-partial"
    if 0.0 < b < 50.0:
        return "burned-partial"
    return "unknown"
