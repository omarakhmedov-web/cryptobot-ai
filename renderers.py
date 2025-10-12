from __future__ import annotations
import datetime as _dt
from typing import Any, Dict, Optional, List

# ---- helpers ----
def _fmt_num(v: Optional[float], prefix: str = "", none: str = "—") -> str:
    if v is None:
        return none
    try:
        n = float(v)
    except Exception:
        return none
    a = abs(n)
    if a >= 1_000_000_000:
        s = f"{n/1_000_000_000:.2f}B"
    elif a >= 1_000_000:
        s = f"{n/1_000_000:.2f}M"
    elif a >= 1_000:
        s = f"{n/1_000:.2f}K"
    else:
        s = f"{n:.6f}" if a < 1 else f"{n:.2f}"
    return prefix + s

def _fmt_pct(v: Optional[float], none: str = "—") -> str:
    if v is None:
        return none
    try:
        n = float(v)
    except Exception:
        return none
    arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
    return f"{arrow} {n:+.2f}%"

def _get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return default if cur is None else cur

def _fmt_chain(chain: Optional[str]) -> str:
    m = (chain or "—").strip().lower()
    if m in ("eth","ethereum"): return "Ethereum"
    if m in ("bsc","binance smart chain","bnb"): return "BSC"
    if m in ("polygon","matic"): return "Polygon"
    if m in ("arbitrum","arb"): return "Arbitrum"
    if m in ("optimism","op"): return "Optimism"
    if m in ("base",): return "Base"
    if m in ("avalanche","avax"): return "Avalanche"
    if m in ("fantom","ftm"): return "Fantom"
    if m in ("solana","sol"): return "Solana"
    return m.capitalize() if m and m != "—" else "—"

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
    if ts_ms is None:
        return "—"
    try:
        ts = int(ts_ms)
        if ts < 10**12:  # seconds -> ms
            ts *= 1000
        dt = _dt.datetime.utcfromtimestamp(ts/1000.0)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return "—"

def _score(verdict) -> str:
    try:
        v = getattr(verdict, "score", None) or _get(verdict, "score", default=None)
    except Exception:
        v = _get(verdict, "score", default=None)
    if v in (None, "—", ""):
        lvl = (_level(verdict) or "").lower()
        if lvl.startswith("low"): return "15"
        if lvl.startswith("med"): return "50"
        if lvl.startswith("high"): return "85"
        return "—"
    return f"{v}"

def _level(verdict) -> str:
    try:
        return f"{getattr(verdict, 'level', None) or _get(verdict, 'level', default='—')}"
    except Exception:
        return f"{_get(verdict, 'level', default='—')}"

def _pick_color(verdict, market):
    m = market or {}
    liq = _get(m, "liq") or _get(m, "liquidityUSD") or 0
    vol = _get(m, "vol24h") or _get(m, "volume24hUSD") or 0
    fdv = _get(m, "fdv")
    mc  = _get(m, "mc")
    if (not liq) and (not vol) and (fdv is None and mc is None):
        return "⚪"
    lvl = None
    try:
        lvl = getattr(verdict, "level", None)
    except Exception:
        lvl = (verdict or {}).get("level")
    lvl = (lvl or "").upper()
    if lvl.startswith("HIGH"): return "🔴"
    if lvl.startswith("MED"):  return "🟡"
    if lvl.startswith("LOW"):  return "🟢"
    return "🟡"

# ---- renderers ----
def render_quick(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
    pair = _get(market, "pairSymbol", default="—")
    chain = _fmt_chain(_get(market, "chain"))
    price = _fmt_num(_get(market, "price"), prefix="$")
    fdv = _fmt_num(_get(market, "fdv"), prefix="$")
    mc  = _fmt_num(_get(market, "mc" ), prefix="$")
    liq = _fmt_num(_get(market, "liq"), prefix="$")
    vol = _fmt_num(_get(market, "vol24h"), prefix="$")
    chg5 = _fmt_pct(_get(market, "priceChanges", "m5"))
    chg1 = _fmt_pct(_get(market, "priceChanges", "h1"))
    chg24= _fmt_pct(_get(market, "priceChanges", "h24"))
    age  = _fmt_age_days(_get(market, "ageDays"))
    asof = _fmt_time(_get(market, "asof"))
    src  = _get(market, "source", default="DexScreener")
    sources = _get(market, "sources") or ([src] if src else [])
    src_line = ", ".join([str(s) for s in sources if s]) or str(src)

    return (
        f"*Metridex QuickScan — {pair}* {_pick_color(verdict, market)} ({_score(verdict)})\n"
        f"`{chain}`  •  Price: *{price}*\n"
        f"FDV: {fdv}  •  MC: {mc}  •  Liq: {liq}\n"
        f"Vol 24h: {vol}  •  Δ5m {chg5}  •  Δ1h {chg1}  •  Δ24h {chg24}\n"
        f"Age: {age}  •  Source: {src_line}  •  as of {asof}"
    ).replace("\\n", "\n")


def render_details(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
    pair = _get(market, "pairSymbol", default="—")
    chain = _fmt_chain(_get(market, "chain"))
    token = _get(market, "tokenAddress", default="—")
    pair_addr = _get(market, "pairAddress", default="—")

    price = _fmt_num(_get(market, "price"), prefix="$")
    fdv = _fmt_num(_get(market, "fdv"), prefix="$")
    mc  = _fmt_num(_get(market, "mc" ), prefix="$")
    liq = _fmt_num(_get(market, "liq"), prefix="$")
    vol = _fmt_num(_get(market, "vol24h"), prefix="$")

    chg5 = _fmt_pct(_get(market, "priceChanges", "m5"))
    chg1 = _fmt_pct(_get(market, "priceChanges", "h1"))
    chg24= _fmt_pct(_get(market, "priceChanges", "h24"))
    age  = _fmt_age_days(_get(market, "ageDays"))
    src_  = _get(market, "source", default="DexScreener")
    asof = _fmt_time(_get(market, "asof"))

    links = _get(market, "links") or {}
    l_dex  = (links or {}).get("dex") or "—"
    l_scan = (links or {}).get("scan") or "—"
    l_site = (links or {}).get("site") or "—"

    parts = []
    parts.append(f"*Details — {pair}* {_pick_color(verdict, market)} ({_score(verdict)})")
    parts.append(f"*Snapshot*\n• Price: {price}  ({chg5}, {chg1}, {chg24})\n• FDV: {fdv}  • MC: {mc}\n• Liquidity: {liq}  • 24h Volume: {vol}\n• Age: {age}  • Source: {src_}\n• As of: {asof}")
    parts.append(f"*Token*\n• Chain: `{chain}`\n• Address: `{token}`")
    parts.append(f"*Pair*\n• Address: `{pair_addr}`\n• Symbol: {pair}")
    ll = ["*Links*"]
    if l_dex and l_dex != "—": ll.append(f"• DEX: {l_dex}")
    if (links or {}).get("dexscreener"): ll.append(f"• DexScreener: {(links or {}).get('dexscreener')}")
    if l_scan and l_scan != "—": ll.append(f"• Scan: {l_scan}")
    if l_site and l_site != "—": ll.append(f"• Site: {l_site}")
    parts.append("\n".join(ll))
    # Web intel summary if provided via ctx['webintel']
    web = (ctx or {}).get('webintel') or {}
    if web:
        who = web.get('whois') or {}
        ssl = web.get('ssl') or {}
        way = web.get('wayback') or {}
        parts.append("*Website intel*" + f"\n• WHOIS: created {who.get('created') or 'n/a'}, registrar {who.get('registrar') or 'n/a'}" + f"\n• SSL: ok={ssl.get('ok') if ssl.get('ok') is not None else 'n/a'}, expires {ssl.get('expires') or 'n/a'}" + f"\n• Wayback first: {way.get('first') or 'n/a'}")
    return "\n".join(parts).replace("\\n", "\n")

def render_why(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    # Take up to 3 key reasons, deduplicated
    reasons: List[str] = []
    try:
        reasons = list(getattr(verdict, "reasons", []) or [])
    except Exception:
        reasons = list((verdict or {}).get("reasons") or [])
    seen = set()
    uniq = []
    for r in reasons:
        if not r: continue
        if r in seen: continue
        seen.add(r)
        uniq.append(r)
        if len(uniq) >= 3:
            break
    if not uniq:
        return "*Why?*\n• No specific risk factors detected"
    header = "*Why?*"
    lines = [f"• {r}" for r in uniq]
    return "\n".join([header] + lines).replace("\\n", "\n")

def render_whypp(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    # Weighted Top-3 positives and Top-3 risks
    m = market or {}
    pos: List[tuple[str,int]] = []
    risk: List[tuple[str,int]] = []

    def add_pos(label:str, w:int): pos.append((label,w))
    def add_risk(label:str, w:int): risk.append((label,w))

    liq = _get(m, "liq")
    vol = _get(m, "vol24h")
    ch24 = _get(m, "priceChanges","h24")
    age = _get(m, "ageDays")
    fdv = _get(m, "fdv"); mc = _get(m, "mc")

    try:
        if isinstance(liq,(int,float)) and liq >= 25000: add_pos(f"Healthy liquidity (${liq:,.0f})", 3)
        if isinstance(vol,(int,float)) and vol >= 50000: add_pos(f"Active 24h volume (${vol:,.0f})", 2)
        if isinstance(age,(int,float)) and age >= 7: add_pos(f"Established >1 week (~{age:.1f}d)", 2)
        if isinstance(ch24,(int,float)) and -30 < ch24 < 80: add_pos(f"Moderate 24h move ({ch24:+.0f}%)", 1)
    except Exception:
        pass

    try:
        if liq is None: add_risk("Liquidity unknown", 2)
        elif isinstance(liq,(int,float)) and liq < 10000: add_risk(f"Low liquidity (${liq:,.0f})", 3)
        if vol is None: add_risk("24h volume unknown", 1)
        elif isinstance(vol,(int,float)) and vol < 5000: add_risk(f"Thin 24h volume (${vol:,.0f})", 2)
        if isinstance(ch24,(int,float)) and (ch24 > 100 or ch24 < -70): add_risk(f"Extreme 24h move ({ch24:+.0f}%)", 2)
        if age is None: add_risk("Pair age unknown", 2)
        elif isinstance(age,(int,float)) and age < 1: add_risk("Newly created pair (<1d)", 3)
        if isinstance(fdv,(int,float)) and isinstance(mc,(int,float)) and mc>0 and fdv/mc>5:
            add_risk(f"FDV/MC high (~{fdv/mc:.1f}x)", 1)
    except Exception:
        pass

    pos = sorted(pos, key=lambda x: (-x[1], x[0]))[:3]
    risk = sorted(risk, key=lambda x: (-x[1], x[0]))[:3]

    lines = ["*Why++*"]
    if pos:
        lines.append("_Top positives_")
        for label, w in pos:
            lines.append(f"• {label} (w={w})")
    if risk:
        lines.append("_Top risks_")
        for label, w in risk:
            lines.append(f"• {label} (w={w})")
    return "\n".join(lines).replace("\\n", "\n")

def render_lp(info: Dict[str, Any], lang: str = "en") -> str:
    p = info or {}
    burned = bool(p.get("burned")) or (str(p.get("status") or "").lower() == "burned")
    until = p.get("until") or "—"
    if burned:
        return "*LP lock (lite)*\n• Burned (LP to 0x…dead)"
    if until not in ("—", None, ""):
        return "*LP lock (lite)*\n• Until: " + str(until)
    return "*LP lock (lite)*\n• Unknown / Not detected"
