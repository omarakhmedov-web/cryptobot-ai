
# renderers_onchain_v2.py — Metridex compact renderer (v0.2)
# Formats the dict returned by onchain_v2.check_contract_v2(...) or onchain_inspector.inspect_token(...)
from typing import Dict, Any

def _fmt_bool(v):
    if v is True: return "True"
    if v is False: return "False"
    return "—"

def _fmt_present(v):
    if v is True: return "present"
    if v is False: return "absent"
    return "—"

def _dash(v):
    return "—" if v in (None, "", []) else v

def render_onchain_v2(chain: str, token: str, info: Dict[str, Any]) -> str:
    d = info or {}
    name = d.get("name")
    symbol = d.get("symbol")
    dec = d.get("decimals")
    total = d.get("totalDisplay") or d.get("totalSupply")
    code = d.get("codePresent")
    owner = d.get("owner")
    renounced = d.get("renounced")
    paused = d.get("paused")
    upg = d.get("upgradeable")
    max_tx = d.get("maxTx")
    max_wallet = d.get("maxWallet")

    head = "On-chain"
    lines = [
        f"{head}",
        f"Contract code: {_fmt_present(code)}",
        f"Token: {_dash(name)} ({_dash(symbol)})",
        f"Decimals: {_dash(dec)}",
        f"Total supply: {_dash(total)}",
        f"Owner: {_dash(owner)}",
        f"Renounced: {_fmt_bool(renounced)}",
        f"Paused: {_dash(paused)}  Upgradeable: {_fmt_bool(upg)}",
        f"MaxTx: {_dash(max_tx)}  MaxWallet: {_dash(max_wallet)}",
    ]
    return "\n".join(lines)
