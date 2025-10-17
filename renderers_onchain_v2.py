# MDX_PATCH_2025_10_17 v4 — output style tuned
# renderers_onchain_v2.py — text formatter for On-chain block
from __future__ import annotations
from typing import Dict, Any, Optional
from onchain_v2 import check_contract_v2

def _fmt_bool(x: Optional[bool]) -> str:
    return "True" if x is True else ("False" if x is False else "—")

def _fmt_field(v: Optional[str]) -> str:
    return v if v not in (None, "", "—") else "—"

def render_onchain_v2(chain: str, token_addr: str, info: Optional[Dict[str,Any]] = None) -> str:
    data = info or check_contract_v2(chain, token_addr)
    lines = []
    lines.append("On-chain")
    # Presence + token meta
    lines.append(f"Contract code: {'present' if data.get('codePresent') else 'absent'}")
    name = data.get("name") or "—"
    symbol = data.get("symbol") or "—"
    dec = data.get("decimals")
    tsd = data.get("totalDisplay") or "—"
    lines.append(f"Token: {name} ({symbol})")
    lines.append(f"Decimals: {dec if dec is not None else '—'}")
    lines.append(f"Total supply: {tsd}")
    # Ownership / security
    owner = data.get("owner") or "—"
    ren = data.get("renounced")
    lines.append(f"Owner: {owner}")
    lines.append(f"Renounced: {_fmt_bool(ren)}")
    lines.append(f"Paused: {_fmt_bool(data.get('paused'))}  Upgradeable: {_fmt_bool(data.get('upgradeable'))}")
    # Optional extensions (left as — for MVP)
    lines.append("MaxTx: —  MaxWallet: —")
    return "\n".join(lines)
