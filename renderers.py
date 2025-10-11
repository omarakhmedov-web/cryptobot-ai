from __future__ import annotations
import datetime as _dt
from typing import Any, Dict, Optional

# ---- helpers ----
def _fmt_num(v: Optional[float], prefix: str = "", none="—") -> str:
    if v is None: return none
    try:
        n = float(v)
    except Exception:
        return none
    absn = abs(n)
    if absn >= 1_000_000_000:
        s = f"{n/1_000_000_000:.2f}B"
    elif absn >= 1_000_000:
        s = f"{n/1_000_000:.2f}M"
    elif absn >= 1_000:
        s = f"{n/1_000:.2f}K"
    else:
        s = f"{n:.6f}" if absn < 1 else f"{n:.2f}"
    return prefix + s

def _fmt_pct(v: Optional[float], none="—") -> str:
    if v is None: return none
    try:
        n = float(v)
    except Exception:
        return none
    arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
    return f"{arrow} {n:+.2f}%"

def _get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict): return default
        cur = cur.get(k)
    return cur if cur is not None else default

def _fmt_chain(chain: Optional[str]) -> str:
    return (chain or "—")

def _fmt_age_days(v: Optional[float]) -> str:
    if v is None:
        return "—"
    try:
        n = float(v)
    except Exception:
        return "—"
    if n < 1/24:
        return f"{round(n*24*60)} min"
    if n < 1:
        return f"{round(n*24)} h"
    return f"{n:.1f} d"

def _fmt_time(ts_ms: Optional[int]) -> str:
    if not ts_ms: return "—"
    try:
        dt = _dt.datetime.utcfromtimestamp(int(ts_ms)/1000.0)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return "—"

def _score(verdict) -> str:
    try:
        return f"{getattr(verdict, 'score', None) or _get(verdict, 'score', default='—')}"
    except Exception:
        return f"{_get(verdict, 'score', default='—')}"

def _level(verdict) -> str:
    try:
        return f"{getattr(verdict, 'level', None) or _get(verdict, 'level', default='—')}"
    except Exception:
        return f"{_get(verdict, 'level', default='—')}"

# ---- renderers ----
def render_quick(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
    pair = _get(market, "pairSymbol", default="—")
    chain = _fmt_chain(_get(market, "chain"))
    price = _fmt_num(_get(market, "price"), prefix="$" )
    fdv = _fmt_num(_get(market, "fdv"), prefix="$" )
    mc  = _fmt_num(_get(market, "mc" ), prefix="$" )
    liq = _fmt_num(_get(market, "liq"), prefix="$" )
    vol = _fmt_num(_get(market, "vol24h"), prefix="$" )
    chg5 = _fmt_pct(_get(market, "priceChanges", "m5"))
    chg1 = _fmt_pct(_get(market, "priceChanges", "h1"))
    chg24= _fmt_pct(_get(market, "priceChanges", "h24"))
    age  = _fmt_age_days(_get(market, "ageDays"))
    src  = _get(market, "source", default="DexScreener")

    return (
        f"*Metridex QuickScan — {pair}* 🟢 ({_score(verdict)})\n"
        f"`{chain}`  •  Price: *{price}*\n"
        f"FDV: {fdv}  •  MC: {mc}  •  Liq: {liq}\n"
        f"Vol 24h: {vol}  •  Δ5m {chg5}  •  Δ1h {chg1}  •  Δ24h {chg24}\n"
        f"Age: {age}  •  Source: {src}"
    ).replace("\\n", "\n")  # safety
    # Note: upstream server escapes Markdown; we ensure real newlines.

def render_details(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
    pair = _get(market, "pairSymbol", default="—")
    chain = _fmt_chain(_get(market, "chain"))
    token = _get(market, "tokenAddress", default="—")
    pair_addr = _get(market, "pairAddress", default="—")

    price = _fmt_num(_get(market, "price"), prefix="$" )
    fdv = _fmt_num(_get(market, "fdv"), prefix="$" )
    mc  = _fmt_num(_get(market, "mc" ), prefix="$" )
    liq = _fmt_num(_get(market, "liq"), prefix="$" )
    vol = _fmt_num(_get(market, "vol24h"), prefix="$" )

    chg5 = _fmt_pct(_get(market, "priceChanges", "m5"))
    chg1 = _fmt_pct(_get(market, "priceChanges", "h1"))
    chg24= _fmt_pct(_get(market, "priceChanges", "h24"))
    age  = _fmt_age_days(_get(market, "ageDays"))
    src  = _get(market, "source", default="DexScreener")
    asof = _fmt_time(_get(market, "asof"))

    links = _get(market, "links") or {}
    l_dex  = (links or {}).get("dex") or "—"
    l_scan = (links or {}).get("scan") or "—"
    l_site = (links or {}).get("site") or "—"

    parts = []
    parts.append(f"*Details — {pair}* 🟢 ({_score(verdict)})")
    parts.append(f"*Snapshot*\n• Price: {price}  ({chg5}, {chg1}, {chg24})\n• FDV: {fdv}  • MC: {mc}\n• Liquidity: {liq}  • 24h Volume: {vol}\n• Age: {age}  • Source: {src}\n• As of: {asof}")
    parts.append(f"*Token*\n• Chain: `{chain}`\n• Address: `{token}`")
    parts.append(f"*Pair*\n• Address: `{pair_addr}`\n• Symbol: {pair}")
    parts.append(f"*Links*\n• DEX: {l_dex}\n• Scan: {l_scan}\n• Site: {l_site}")
    return "\n\n".join(parts).replace("\\n", "\n")  # safety

def render_why(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    reasons = []
    try:
        reasons = list(getattr(verdict, "reasons", []) or [])
    except Exception:
        reasons = list((verdict or {}).get("reasons") or [])
    if not reasons:
        return "*Why?*\n• No specific risk factors detected".replace("\\n", "\n")
    header = "*Why?*"
    lines = [f"• {r}" for r in reasons]
    return "\n".join([header] + lines).replace("\\n", "\n")

def render_whypp(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    try:
        score = getattr(verdict, "score", None)
        level = getattr(verdict, "level", None)
    except Exception:
        score = (verdict or {}).get("score")
        level = (verdict or {}).get("level")
    header = f"*Why++ — detailed factors*\nScore: {score if score is not None else '—'}  •  Level: {level if level is not None else '—'}"
    reasons = []
    try:
        reasons = list(getattr(verdict, "reasons", []) or [])
    except Exception:
        reasons = list((verdict or {}).get("reasons") or [])
    if not reasons:
        return (header + "\n\n(no details)").replace("\\n", "\n")
    lines = ["", "*Factors considered:*"]
    for i, r in enumerate(reasons, start=1):
        lines.append(f"{i}. {r}")
    return "\n".join([header] + lines).replace("\\n", "\n")

def render_lp(info: Dict[str, Any], lang: str = "en") -> str:
    provider = (info or {}).get("provider") or "—"
    lp = (info or {}).get("lpAddress") or "—"
    until = (info or {}).get("until") or "—"
    return f"LP lock\nProvider: {provider}\nLP: `{lp}`\nUntil: {until}".replace("\\n", "\n")
