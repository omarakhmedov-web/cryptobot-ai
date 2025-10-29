def _lp_status_from_oc(oc: dict) -> str:
    try:
        if oc.get("lp_v3") is True:
            return "v3-NFT (locks not applicable)"
        lp = oc.get("lp_lock_lite") or {}
        burned = lp.get("burned_pct"); lockers = lp.get("lockers") or {}
        anyval = burned not in (None, 0) or any((v or 0) > 0 for v in lockers.values())
        return "unlocked" if not anyval else "locked-partial"
    except Exception:
        return "unknown"

import re
import unicodedata
from decimal import Decimal, getcontext

_ABBREV_FORCE_UPPER = {
    "AI","NFT","DAO","DEX","CEX","LP","TVL","FDV","MC","USD",
    "USDT","USDC","BTC","ETH","BNB","SOL","ARB","OP","BSC"
}
_VERSION_RE = re.compile(r"^(?:v\d+(?:\.\d+)*)|(?:\d+(?:\.\d+)+)|(?:\d{2,})$", re.IGNORECASE)

def _s(x):
    return "—" if x in (None, "", [], {}) else str(x)

def _strip_invisibles(s: str) -> str:
    if not isinstance(s, str):
        return s
    cleaned = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc", "Cs"):
            continue
        cleaned.append(ch)
    out = "".join(cleaned)
    out = re.sub(r"\s+", " ", out).strip()
    return out

def _smart_title(name: str) -> str:
    if not isinstance(name, str):
        return name
    name = _strip_invisibles(name)
    if name.isupper() or name.istitle():
        return name
    def cap_word(w: str) -> str:
        if not w:
            return w
        w_clean = _strip_invisibles(w)
        if _VERSION_RE.match(w_clean):
            return w
        if w_clean.upper() in _ABBREV_FORCE_UPPER:
            return w_clean.upper()
        if len(w_clean) <= 3 and w_clean.isalpha():
            return w_clean.upper()
        return w_clean[:1].upper() + w_clean[1:].lower()
    parts = re.split(r"(\s+|-)", name)
    parts = [cap_word(p) if (i % 2 == 0) else p for i, p in enumerate(parts)]
    return "".join(parts)

def _parse_token_label(raw: str):
    if not isinstance(raw, str):
        return None, None, None
    txt = _strip_invisibles(raw)
    m = re.match(r"^(.+?)\s*\(\s*([^\)]+)\s*\)\s*(?:·\s*Decimals:\s*(\d+))?\s*$", txt)
    if m:
        name, sym, dec = m.group(1), m.group(2), m.group(3)
        return name, sym, dec
    return None, None, None


def _normalize_owner_display(owner: str) -> str:
    if not isinstance(owner, str):
        return owner
    try:
        low = owner.lower()
        # pattern: 0x + 24 zeros + 40-hex tail
        if low.startswith("0x000000000000000000000000") and len(low) == 66:
            tail = low[-40:]
            return "0x" + tail
    except Exception:
        pass
    return owner
def _short_addr(addr: str, head: int = 6, tail: int = 6) -> str:
    if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42:
        return str(addr)
    return addr[:2+head] + "…" + addr[-tail:]


def _as_map(x):
    """
    Normalize arbitrary value to a dict:
    - if dict -> return as is
    - if tuple/list and first element is dict -> return that
    - else -> {}
    """
    if isinstance(x, dict):
        return x
    if isinstance(x, (list, tuple)) and x:
        if isinstance(x[0], dict):
            return x[0]
    return {}

def format_onchain_text(oc: dict, mkt: dict, hide_empty_honeypot: bool = True) -> str:
    # Normalize honeypot structure to dict to avoid AttributeError on tuple/list
    hp_raw = oc.get('honeypot')
    if isinstance(hp_raw, dict):
        hp = hp_raw
    elif isinstance(hp_raw, (list, tuple)) and len(hp_raw) and isinstance(hp_raw[0], dict):
        hp = hp_raw[0]
    else:
        hp = {}
    oc = oc or {}
    mkt = mkt or {}

    # Contract code
    cc = oc.get("contractCodePresent") if oc.get("contractCodePresent") is not None else oc.get("codePresent")
    if cc is True:
        cc_line = "Contract code: present"
    elif cc is False:
        cc_line = "Contract code: absent"
    else:
        cc_line = "Contract code: —"

    # Token line normalization
    name = oc.get("name"); symbol = oc.get("symbol")
    if not (name and symbol):
        n2, s2, _ = _parse_token_label(oc.get("token") or "")
        name = name or n2; symbol = symbol or s2
    if name: name = _smart_title(name)
    if symbol: symbol = _strip_invisibles(symbol).upper()

    if not (name and symbol):
        pair_sym = mkt.get("pairSymbol") or ""
        if not symbol and "/" in str(pair_sym):
            symbol = str(pair_sym).split("/", 1)[0].strip().upper()
        if not name and symbol:
            name = symbol

    if name and symbol:
        token_line = f"token: {name} ({symbol})"
    elif oc.get("token"):
        token_line = "token: " + _strip_invisibles(str(oc.get("token")))
    else:
        token_line = "token: " + _s(mkt.get("pairSymbol") or mkt.get("tokenAddress"))

    dec = oc.get("decimals")
    if isinstance(dec, int):
        token_line += f" · Decimals: {dec}"

    # Total supply
    supply_line = None
    ts = oc.get("totalSupply")
    if isinstance(ts, int) and isinstance(dec, int) and dec >= 0:
        try:
            getcontext().prec = 40
            human = (Decimal(ts) / (Decimal(10) ** dec)).quantize(Decimal("0.001"))
            supply_line = f"Total supply: ~{human:,}"
        except Exception:
            pass

    # Honeypot line (with reason/meta)
    hp = _as_map(oc.get("honeypot"))
    hp_meta = oc.get("honeypot_meta") or {}
    hp_line = None
    if hp:
        sim = hp.get("simulation") or "—"
        risk = hp.get("risk") or "—"
        lvl = hp.get("level")
        reason = hp_meta.get("reason")
        suffix_lvl = f" | level={lvl}" if lvl not in (None, "—") else ""
        suffix_reason = f" ({reason})" if reason and sim == "—" and risk == "—" else ""
        hp_line = f"Honeypot.is: simulation={sim} | risk={risk}{suffix_lvl}{suffix_reason}"
    if hide_empty_honeypot and hp_line and ("simulation=—" in hp_line and "risk=—" in hp_line):
        hp_line = None
    if hide_empty_honeypot and (not hp or ((hp.get("simulation") in (None, '—')) and (hp.get("risk") in (None, '—')) and not hp.get("level"))):
        hp_line = None

    # LP lite
    lp = oc.get("lp_lock_lite") or {}
    lp_line = None
    if lp:
        burned = lp.get("burned_pct"); u = (lp.get("lockers") or {}).get("UNCX"); tf = (lp.get("lockers") or {}).get("TeamFinance")
        top_lab = lp.get("top_holder_label"); top_pct = lp.get("top_holder_pct")
        def _fmt(v):
            return "—" if v in (None, "") else (f"{v:.2f}%" if isinstance(v, (int,float)) else str(v))
        core = f"burned={_fmt(burned)} | UNCX={_fmt(u)} | TeamFinance={_fmt(tf)}"
        if top_lab and top_pct:
            core += f" | topHolder={top_lab}:{_fmt(top_pct)}"
        lp_line = "LP: " + core

    # Owner and state
    owner_raw = oc.get("owner")
    owner_line = "owner: " + _s(_short_addr(_normalize_owner_display(owner_raw)) if isinstance(owner_raw, str) else owner_raw)
    renounced = oc.get("renounced")
    if renounced not in (None, "—"):
        owner_line += "  renounced: " + _s(renounced)

    paused = _s(oc.get("paused"))
    upgradeable = _s(oc.get("upgradeable"))
    # Normalize paused display
    if paused == "—":
        paused = "n/a"

    state_line = f"paused: {paused}  upgradeable: {upgradeable}"

    maxTx = _s(oc.get("maxTx"))
    maxWallet = _s(oc.get("maxWallet"))
    limits_line = f"maxTx: {maxTx}  maxWallet: {maxWallet}"

    # Taxes (show buy/sell/transfer if available)
    taxes = oc.get("taxes") or {}
    tb = taxes.get("buy"); tsell = taxes.get("sell"); ttr = taxes.get("transfer")
    tax_line = None
    if (tb is not None) or (tsell is not None) or (ttr is not None):
        tbx = "—" if tb is None else f"{tb}%"
        tsx = "—" if tsell is None else f"{tsell}%"
        ttx = "—" if ttr is None else f"{ttr}%"
        tax_line = f"Taxes: buy={tbx} | sell={tsx} | transfer={ttx}"

    # Assemble (keep Total supply before Honeypot as обсуждали)
    parts = ["On-chain", cc_line, token_line]
    if supply_line: parts.append(supply_line)
    if hp_line: parts.append(hp_line)
    if lp_line: parts.append(lp_line)
    parts += [owner_line, state_line]
    if not (maxTx == "—" and maxWallet == "—"):
        parts.append(limits_line)
    if tax_line: parts.append(tax_line)

    return "\n".join(parts)
