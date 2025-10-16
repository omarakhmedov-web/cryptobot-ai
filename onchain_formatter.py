
def _s(x):
    return "—" if x in (None, "", [], {}) else str(x)

def format_onchain_text(oc: dict, mkt: dict) -> str:
    oc = oc or {}
    mkt = mkt or {}

    # Contract code presence
    cc = oc.get("contractCodePresent")
    if cc is True:
        cc_line = "Contract code: present"
    elif cc is False:
        cc_line = "Contract code: absent"
    else:
        cc_line = "Contract code: —"

    token_line = "token: " + _s(oc.get("token") or mkt.get("pairSymbol") or mkt.get("tokenAddress"))

    owner_raw = oc.get("owner")
    renounced = oc.get("renounced")
    owner_line = "owner: " + _s(owner_raw)
    if renounced not in (None, "—"):
        owner_line += "  renounced: " + _s(renounced)

    paused = _s(oc.get("paused"))
    upgradeable = _s(oc.get("upgradeable"))
    state_line = f"paused: {paused}  upgradeable: {upgradeable}"

    maxTx = _s(oc.get("maxTx"))
    maxWallet = _s(oc.get("maxWallet"))
    limits_line = f"maxTx: {maxTx}  maxWallet: {maxWallet}"

    taxes = oc.get("taxes") or {}
    tb = taxes.get("buy")
    ts = taxes.get("sell")
    tax_line = None
    if (tb is not None) or (ts is not None):
        tbx = "—" if tb is None else f"{tb}%"
        tsx = "—" if ts is None else f"{ts}%"
        tax_line = f"Taxes: buy={tbx} | sell={tsx}"

    parts = ["On-chain", cc_line, token_line, owner_line, state_line, limits_line]
    if tax_line:
        parts.append(tax_line)

    return "\n".join(parts)
