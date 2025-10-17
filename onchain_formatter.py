# onchain_formatter.py — thin wrapper to keep legacy imports working
from typing import Optional, Dict, Any
from renderers_onchain_v2 import render_onchain_v2
from onchain_v2 import check_contract_v2

def format_onchain_text(chain: str, token_addr: str, info: Optional[Dict[str, Any]] = None) -> str:
    """Render the On-chain block text. Safe and side-effect free."""
    data = info or check_contract_v2(chain, token_addr)
    return render_onchain_v2(chain, token_addr, data)
