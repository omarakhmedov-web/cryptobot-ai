# onchain_formatter.py — PRODUCTIVE rev (2025-10-29, dynamic-lockers)
# Renders any lockers present in lp_lock_lite["lockers"] dynamically, sorted by %.

import re, unicodedata
from decimal import Decimal, getcontext

_ABBREV_FORCE_UPPER = {
    "AI","NFT","DAO","DEX","CEX","LP","TVL","FDV","MC","USD",
    "USDT","USDC","BTC","ETH","BNB","SOL","ARB","OP","BSC","V3"
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
        if low.startswith("0x000000000000000000000000") and len(low) == 42:
            return "0x" + low[-40:]
        if len(low) == 66 and low.startswith("0x000000000000000000000000"):
            return "0x" + low[-40:]
    except Exception:
        pass
    return owner

def _short_addr(addr: str, head: int = 6, tail: int = 6) -> str:
    if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) < 42:
        return str(addr)
    return addr[:2+head] + "…" + addr[-tail:]

def _as_map(x):
    if isinstance(x, dict):
        return x
    if isinstance(x, (list, tuple)) and x and isinstance(x[0], dict):
        return x[0]
    return {}

def format_onchain_text(oc: dict, mkt: dict, hide_empty_honeypot: bool = True) -> str:
    oc = oc or {}; mkt = mkt or {}

    # Contract code
    cc = oc.get("contractCodePresent")
    if cc is None:
        cc = oc.get("codePresent")
    cc_line = "Contract code: present" if cc is True else ("Contract code: absent" if cc is False else "Contract code: —")

    # Token
    name = oc.get("name"); symbol = oc.get("symbol")
    if not (name and symbol):
        n2, s2, _ = _parse_token_label(oc.get("token") or "")
        name = name or n2; symbol = symbol or s2
    if name: name = _smart_title(name)
    if symbol: symbol = _strip_invisibles(symbol).upper()
    pair_sym = mkt.get("pairSymbol") or ""
    if not (name and symbol) and "/" in str(pair_sym):
        symbol = symbol or str(pair_sym).split("/",1)[0].strip().upper()
        name = name or symbol
    token_line = f"token: {name} ({symbol})" if (name and symbol) else "token: " + _strip_invisibles(str(mkt.get("tokenAddress") or pair_sym or "—"))
    if isinstance(oc.get("decimals"), int):
        token_line += f" · Decimals: {oc['decimals']}"

    # Total supply
    supply_line = None
    ts = oc.get("totalSupply"); dec = oc.get("decimals")
    if isinstance(ts, int) and isinstance(dec, int) and dec >= 0:
        try:
            getcontext().prec = 40
            human = (Decimal(ts) / (Decimal(10) ** dec)).quantize(Decimal("0.001"))
            supply_line = f"Total supply: ~{human:,}"
        except Exception:
            pass

    # Honeypot
    hp = _as_map(oc.get("honeypot"))
    hp_meta = oc.get("honeypot_meta") or {}
    hp_line = None
    if hp:
        sim = hp.get("simulation","—"); risk = hp.get("risk","—"); lvl = hp.get("level")
        reason = hp_meta.get("reason")
        suffix_lvl = f" | level={lvl}" if lvl not in (None, "—") else ""
        suffix_reason = f" ({reason})" if reason and sim == "—" and risk == "—" else ""
        hp_line = f"Honeypot.is: simulation={sim} | risk={risk}{suffix_lvl}{suffix_reason}"
    if hide_empty_honeypot and hp_line and ("simulation=—" in hp_line and "risk=—" in hp_line):
        hp_line = None

    # LP section
    lp_line = None
    if oc.get("lp_v3") is True:
        lp_line = "LP: v3-NFT (no LP token supply; locks not applicable)"
    else:
        lp = _as_map(oc.get("lp_lock_lite"))
        if lp:
            def fmt_pct(v): 
                try:
                    return "—" if v in (None, "") else f"{float(v):.2f}%"
                except Exception:
                    return str(v)
            burned = fmt_pct(lp.get("burned_pct"))
            # dynamic lockers render, sorted by percentage desc
            lockers = lp.get("lockers") or {}
            items = []
            for name, val in lockers.items():
                try:
                    items.append((name, float(val or 0.0)))
                except Exception:
                    items.append((name, 0.0))
            items.sort(key=lambda x: x[1], reverse=True)
            locker_txt = " | ".join([f"{k}={fmt_pct(v)}" for k, v in items]) if items else ""
            core = f"burned={burned}" + ((" | " + locker_txt) if locker_txt else "")
            top_lab, top_pct = lp.get("top_holder_label"), lp.get("top_holder_pct")
            if top_lab and top_pct not in (None, 0, "—"):
                core += f" | topHolder={top_lab}:{fmt_pct(top_pct)}"
            lp_line = "LP: " + core

    # Owner / state
    owner = oc.get("owner")
    owner_line = "owner: " + _s(_short_addr(_normalize_owner_display(owner)) if isinstance(owner, str) else owner)
    renounced = oc.get("renounced")
    if renounced not in (None, "—"):
        owner_line += "  renounced: " + _s(renounced)
    paused = oc.get("paused"); upgradeable = oc.get("upgradeable")
    paused_line = "n/a" if paused in (None, "—") else str(paused)
    state_line = f"paused: {paused_line}  upgradeable: {_s(upgradeable)}"

    # Limits and taxes
    maxTx = _s(oc.get("maxTx")); maxWallet = _s(oc.get("maxWallet"))
    limits_line = None if (maxTx == "—" and maxWallet == "—") else f"maxTx: {maxTx}  maxWallet: {maxWallet}"
    taxes = oc.get("taxes") or {}
    tb = taxes.get("buy"); tsell = taxes.get("sell"); ttr = taxes.get("transfer")
    tax_line = None
    if (tb is not None) or (tsell is not None) or (ttr is not None):
        tbx = "—" if tb is None else f"{tb}%"
        tsx = "—" if tsell is None else f"{tsell}%"
        ttx = "—" if ttr is None else f"{ttr}%"
        tax_line = f"Taxes: buy={tbx} | sell={tsx} | transfer={ttx}"

    parts = ["On-chain", cc_line, token_line]
    if supply_line: parts.append(supply_line)
    if hp_line: parts.append(hp_line)
    if lp_line: parts.append(lp_line)
    parts += [owner_line, state_line]
    if limits_line: parts.append(limits_line)
    if tax_line: parts.append(tax_line)
    return "\n".join(parts)
