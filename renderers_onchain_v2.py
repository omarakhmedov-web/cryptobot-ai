# renderers_onchain_v2.py — On-chain text renderer (v0.2.1-SAFE)
# Friendly formatting, ZERO_ADDRESS -> "renounced (0x00…00)", show available limits.
from __future__ import annotations
from typing import Dict, Any, Optional
try:
    # Optional: if available in runtime, can self-fetch
    from onchain_v2 import check_contract_v2
except Exception:  # pragma: no cover
    check_contract_v2 = None  # type: ignore

ZERO = "0x0000000000000000000000000000000000000000"

def _fmt_bool(x: Optional[bool]) -> str:
    return "True" if x is True else ("False" if x is False else "—")

def _fmt_present(x: Optional[bool]) -> str:
    return "present" if x is True else ("absent" if x is False else "—")

def _dash(v):
    return "—" if v in (None, "", []) else v

def _short(addr: str) -> str:
    try:
        a = addr.lower().strip()
        return a[:8] + "…" + a[-4:] if a.startswith("0x") and len(a) == 42 else addr
    except Exception:
        return addr

def render_onchain_v2(chain: str, token_addr: str, info: Optional[Dict[str, Any]] = None) -> str:
    d = info or (check_contract_v2(chain, token_addr) if callable(check_contract_v2) else {}) or {}

    name = d.get("name")
    symbol = d.get("symbol")
    dec = d.get("decimals")
    total = d.get("totalDisplay") or d.get("totalSupply")

    code_present = d.get("codePresent")
    owner = (d.get("owner") or "").strip().lower() or None
    renounced = d.get("renounced")
    paused = d.get("paused")
    upgradeable = d.get("upgradeable")
    max_tx = d.get("maxTx")
    max_wallet = d.get("maxWallet")

    # Normalize renounced/owner
    owner_line = "—"
    if owner:
        if owner == ZERO:
            owner_line = f"renounced ({_short(ZERO)})"
            renounced = True if renounced is None else bool(renounced)
        else:
            owner_line = _short(owner)

    lines = [
        "On-chain",
        f"Contract code: {_fmt_present(code_present)}",
        f"Token: {_dash(name)} ({_dash(symbol)})",
        f"Decimals: {_dash(dec)}",
        f"Total supply: {_dash(total)}",
        f"Owner: {owner_line}",
        f"Renounced: {_fmt_bool(renounced)}",
        f"Paused: {_dash(paused)}  Upgradeable: {_fmt_bool(upgradeable)}",
        f"MaxTx: {_dash(max_tx)}  MaxWallet: {_dash(max_wallet)}",
    ]
    return "\n".join(lines)
