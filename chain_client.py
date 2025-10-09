import os
from typing import Dict, Any, Optional
from common import chain_from_hint

# Minimal safe stubs; extend with Web3 for deep checks
def fetch_onchain_factors(address: Optional[str], chain_hint: str = "ethereum") -> Dict[str, Any]:
    """
    Returns a factors dict for risk engine. Stubs default to neutral values.
    Keys: honeypot, blacklist, pausable, upgradeable, mint, maxTx, maxWallet, taxes{buy,sell}
    """
    return {
        "honeypot": False,
        "blacklist": False,
        "pausable": False,
        "upgradeable": False,
        "mint": False,
        "maxTx": None,
        "maxWallet": None,
        "taxes": {"buy": 0.0, "sell": 0.0},
        "owner": None,
    }
