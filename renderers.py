from __future__ import annotations
from typing import Any, Dict, List, Tuple, Optional

# ---------- helpers ----------
def _abbr_usd(v: Optional[float]) -> str:
    if v is None: return "—"
    try:
        n = float(v)
    except Exception:
        return str(v)
    t = abs(n)
    if t >= 1_000_000_000_000: s = f"${n/1_000_000_000_000:.2f}T"
    elif t >= 1_000_000_000:   s = f"${n/1_000_000_000:.2f}B"
    elif t >= 1_000_000:       s = f"${n/1_000_000:.2f}M"
    elif t >= 1_000:           s = f"${n/1_000:.2f}K"
    else:                      s = f"${n:.6f}" if t < 1 else f"${n:.2f}"
    # strip trailing zeros
    s = s.replace("000000", "")
    while len(s) > 2 and s[-1] == "0" and s[-2] != ".":
        s = s[:-1]
    if s.endswith("."): s = s[:-1]
    return s

def _fmt_pct(v):
    if v is None or v == "—": return "—"
    try:
        return f"{float(v):+.2f}%"
    except Exception:
        return str(v)

def _age_days(age):
    if not age: return "—"
    try:
        d = float(age)
        return f"{d:.1f}d"
    except Exception:
        return str(age)

def _level_from_score(score: Optional[float]) -> str:
    if score is None: return "LOW"
    s = float(score)
    if s <= 24: return "LOW"
    if s <= 49: return "MEDIUM"
    if s <= 74: return "HIGH"
    return "CRITICAL"

def _emoji(level: Optional[str], score: Optional[float]) -> str:
    lvl = (level or _level_from_score(score)).upper()
    return {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(lvl,"🟢")

def _safe(s):
    return "—" if s in (None, "", 0, "0") else s

# ---------- WHY reasons synthesis ----------
def _synth_reasons(verdict: Any, market: Dict[str, Any]) -> List[str]:
    \"\"\"Build minimal, copyable reasons if verdict.reasons is empty.\"\"\"
    rs: List[str] = []
    score = getattr(verdict, "score", None)
    level = getattr(verdict, "level", None)
    lvl = (level or _level_from_score(score)).upper()

    liq = market.get("liq")
    vol = market.get("vol24h")
    fdv = market.get("fdv") or market.get("mc")
    age = market.get("ageDays") or market.get("age")  # if you store it
    pc = market.get("priceChanges") or {}
    m5, h1, h24 = pc.get("m5"), pc.get("h1"), pc.get("h24")

    # Liquidity
    if isinstance(liq, (int, float)) and liq > 0:
        if isinstance(fdv, (int, float)) and fdv > 0 and (liq/fdv) >= 0.01:
            rs.append(f"LP depth {_abbr_usd(liq)} is healthy vs FDV {_abbr_usd(fdv)}")
        else:
            rs.append(f"LP depth {_abbr_usd(liq)} — check slippage on large orders")
    else:
        rs.append("LP depth unknown — verify slippage before size")

    # Volume / activity
    if isinstance(vol, (int, float)):
        if vol >= 500_000:
            rs.append(f"24h volume {_abbr_usd(vol)} — active market")
        elif vol > 0:
            rs.append(f"24h volume {_abbr_usd(vol)} — thin liquidity regime")

    # Momentum
    if m5 is not None: rs.append(f"Δ5m {_fmt_pct(m5)}")
    if h1 is not None: rs.append(f"Δ1h {_fmt_pct(h1)}")
    if h24 is not None: rs.append(f"Δ24h {_fmt_pct(h24)}")

    # Age
    if isinstance(age, (int, float)):
        if age >= 180: rs.append(f"Age {age:.0f}d — seasoned")
        elif age <= 7: rs.append(f"Age {age:.0f}d — very new")

    # On-chain disclaimer
    rs.append("Taxes/owner functions not verified yet — run On-chain")
    # Verdict recap
    if score is not None:
        rs.append(f"Verdict: {_level_from_score(score)} (score {int(score)})")

    # de-dup, keep order
    seen = set(); out = []
    for r in rs:
        if r not in seen:
            out.append(r); seen.add(r)
    return out[:8]  # keep concise

# ---------- Renderers ----------
def render_quick(verdict: Any, market: Dict[str, Any], opts: Dict[str, Any], lang: str) -> str:
    pair = market.get("pairSymbol") or "—"
    chain = market.get("chain") or "—"
    price = _abbr_usd(market.get("price"))
    fdv = _abbr_usd(market.get("fdv"))
    mc  = _abbr_usd(market.get("mc"))
    liq = _abbr_usd(market.get("liq"))
    vol = _abbr_usd(market.get("vol24h"))
    pc = market.get("priceChanges") or {}
    m5, h1, h24 = _fmt_pct(pc.get("m5")), _fmt_pct(pc.get("h1")), _fmt_pct(pc.get("h24"))
    age = _age_days(market.get("ageDays") or market.get("age"))
    source = market.get("source") or "DexScreener"

    score = getattr(verdict, "score", None)
    level = getattr(verdict, "level", None)
    emj = _emoji(level, score)
    sc  = int(score) if isinstance(score, (int, float)) else "—"

    # No link row in text; navigation is in buttons
    lines = [
        f"*Metridex QuickScan — {pair}* {emj} ({sc})",
        f"`{chain}`  •  Price: *{price}*",
        f"FDV: {fdv}  •  MC: {mc}  •  Liq: {liq}",
        f"Vol 24h: {vol}  •  Δ5m {m5}  •  Δ1h {h1}  •  Δ24h {h24}",
        f"Age: {age}  •  Source: {source}",
    ]
    return \"\n\".join(lines).strip()

def render_details(verdict: Any, market: Dict[str, Any], opts: Dict[str, Any], lang: str) -> str:
    # Minimal details; can be extended later
    pair = market.get("pairSymbol") or "—"
    chain = market.get("chain") or "—"
    score = getattr(verdict, "score", None)
    level = _level_from_score(score)
    emj = _emoji(level, score)
    lines = [
        f\"*Details — {pair}* {emj} ({int(score) if isinstance(score,(int,float)) else '—'})\",
        f\"Chain: `{chain}`\",
        f\"Token: `{market.get('tokenAddress') or '—'}`\",
        f\"Pair: `{market.get('pairAddress') or '—'}`\",
    ]
    site = (market.get(\"links\") or {}).get(\"site\")
    if site:
        lines.append(f\"Site: {site}\")
    return \"\n\".join(lines).strip()

def render_why(verdict: Any, market: Dict[str, Any], lang: str) -> str:
    reasons = list(getattr(verdict, \"reasons\", []) or [])
    if not reasons:
        reasons = _synth_reasons(verdict, market)
    # keep 4-6 concise bullets
    bullets = reasons[:6]
    out = [\"*Why?*\"]
    for r in bullets:
        out.append(f\"• {r}\")
    return \"\n\".join(out)

def render_whypp(verdict: Any, market: Dict[str, Any], lang: str) -> str:
    score = getattr(verdict, \"score\", None)
    level = getattr(verdict, \"level\", None) or _level_from_score(score)
    reasons = list(getattr(verdict, \"reasons\", []) or [])
    if not reasons:
        reasons = _synth_reasons(verdict, market)
    out = [
        \"*Why++ — detailed factors*\",\n        f\"Score: {int(score) if isinstance(score,(int,float)) else '—'}  •  Level: {level}\",\n        \"\",\n        \"*Factors considered:*\",\n    ]
    for i, r in enumerate(reasons, 1):
        out.append(f\"{i}. {r}\")
    return \"\n\".join(out)

def render_lp(lp: Dict[str, Any], lang: str) -> str:
    if not lp:
        return \"LP lock: no data\"
    prov = lp.get(\"provider\") or \"—\"
    addr = lp.get(\"lpAddress\") or \"—\"
    until = lp.get(\"until\") or \"—\"
    return f\"LP lock\nProvider: {prov}\nLP: `{addr}`\nUntil: {until}\"
