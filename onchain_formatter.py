import re
import unicodedata

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
    # If already well-cased, keep
    if name.isupper() or name.istitle():
        return name

    def cap_word(w: str) -> str:
        if not w:
            return w
        w_clean = _strip_invisibles(w)
        # Keep versions like v2, v3.1, 2.0, 2025 as-is
        if _VERSION_RE.match(w_clean):
            return w
        # Force-Upper for known abbreviations (regardless of original case)
        if w_clean.upper() in _ABBREV_FORCE_UPPER:
            return w_clean.upper()
        # Short alpha tokens (<=3 chars) stay upper (AI, VPN→VPN etc.)
        if len(w_clean) <= 3 and w_clean.isalpha():
            return w_clean.upper()
        # Default Title case (keep other chars intact)
        return w_clean[:1].upper() + w_clean[1:].lower()

    # Preserve separators (spaces and hyphens)
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

def format_onchain_text(oc: dict, mkt: dict) -> str:
    oc = oc or {}
    mkt = mkt or {}

    cc = oc.get("contractCodePresent")
    if cc is True:
        cc_line = "Contract code: present"
    elif cc is False:
        cc_line = "Contract code: absent"
    else:
        cc_line = "Contract code: —"

    # Prefer raw inspector fields; fallback to parsed token label; then market hints
    name = oc.get("name")
    symbol = oc.get("symbol")
    if not (name and symbol):
        n2, s2, _ = _parse_token_label(oc.get("token") or "")
        name = name or n2
        symbol = symbol or s2

    # Normalize
    if name:
        name = _smart_title(name)
    if symbol:
        symbol = _strip_invisibles(symbol).upper()

    if not (name and symbol):
        token_addr = mkt.get("tokenAddress") or oc.get("token") or ""
        pair_sym = mkt.get("pairSymbol") or ""
        if not symbol and "/" in str(pair_sym):
            symbol = str(pair_sym).split("/", 1)[0].strip().upper()
        if not name and symbol:
            name = symbol

    # Compose token line
    if name and symbol:
        token_line = f"token: {name} ({symbol})"
    elif oc.get("token"):
        token_line = "token: " + _strip_invisibles(str(oc.get("token")))
    else:
        token_line = "token: " + _s(mkt.get("pairSymbol") or mkt.get("tokenAddress"))

    # Append decimals
    dec = oc.get("decimals")
    if isinstance(dec, int):
        token_line += f" · Decimals: {dec}"

    # Owner / renounced
    owner_raw = _strip_invisibles(str(oc.get("owner") or "")) if oc.get("owner") else oc.get("owner")
    owner_line = "owner: " + _s(_short_addr(owner_raw) if isinstance(owner_raw, str) else owner_raw)
    renounced = oc.get("renounced")
    if renounced not in (None, "—"):
        owner_line += "  renounced: " + _s(renounced)

    # State
    paused = _s(oc.get("paused"))
    upgradeable = _s(oc.get("upgradeable"))
    state_line = f"paused: {paused}  upgradeable: {upgradeable}"

    # Limits
    maxTx = _s(oc.get("maxTx"))
    maxWallet = _s(oc.get("maxWallet"))
    limits_line = f"maxTx: {maxTx}  maxWallet: {maxWallet}"

    # Taxes
    taxes = oc.get("taxes") or {}
    tb = taxes.get("buy"); ts = taxes.get("sell")
    tax_line = None
    if (tb is not None) or (ts is not None):
        tbx = "—" if tb is None else f"{tb}%"
        tsx = "—" if ts is None else f"{ts}%"
        tax_line = f"Taxes: buy={tbx} | sell={tsx}"

    # Total supply
    supply_line = None
    ts = oc.get("totalSupply")
    dec = oc.get("decimals")
    if isinstance(ts, int) and isinstance(dec, int) and dec >= 0:
        try:
            from decimal import Decimal, getcontext
            getcontext().prec = 40
            human = (Decimal(ts) / (Decimal(10) ** dec)).quantize(Decimal("0.001"))
            supply_line = f"Total supply: ~{human:,}"
        except Exception:
            pass
    # Honeypot (best-effort)
    hp = oc.get("honeypot") or {}
    hp_line = None
    if hp:
        sim = hp.get("simulation") or "—"
        risk = hp.get("risk") or "—"
        lvl = hp.get("level")
        suffix = f" | level={lvl}" if lvl not in (None, "—") else ""
        hp_line = f"Honeypot.is: simulation={sim} | risk={risk}{suffix}"
    parts = ["On-chain", cc_line, token_line]
    if hp_line:
        parts.append(hp_line)
    if supply_line:
        parts.append(supply_line)
    # LP lock (lite)
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
    if lp_line:
        parts.append(lp_line)
    parts += [owner_line, state_line, limits_line]
    if tax_line:
        parts.append(tax_line)

    return "\n".join(parts)


def _short_addr(addr: str, head: int = 6, tail: int = 6) -> str:
    if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42:
        return str(addr)
    return addr[:2+head] + "…" + addr[-tail:]
