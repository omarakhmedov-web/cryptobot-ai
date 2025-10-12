from __future__ import annotations
import os
import datetime as _dt
from typing import Any, Dict, Optional, List
import re as _re

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
    if ("SCAM" in lvl) or ("MALICIOUS" in lvl) or ("RUG" in lvl) or ("FRAUD" in lvl): return "🔴"
    if lvl.startswith("HIGH"): return "🔴"
    if lvl.startswith("MED"):  return "🟡"
    if lvl.startswith("LOW"):  return "🟢"
    return "🟡"

# --- chain-aware tiers for Why++ (align with risk_engine) ---
def _short_chain(market: Dict[str, Any]) -> str:
    ch = (market or {}).get("chain") or ""
    ch = str(ch).strip().lower()
    mp = {"ethereum":"eth","eth":"eth","bsc":"bsc","binance smart chain":"bsc","polygon":"polygon","matic":"polygon",
          "arbitrum":"arb","arb":"arb","optimism":"op","op":"op","base":"base","avalanche":"avax","avax":"avax",
          "fantom":"ftm","ftm":"ftm","sol":"sol","solana":"sol"}
    return mp.get(ch, ch)

def _env_num(key: str, default: int) -> int:
    try:
        v = os.getenv(key)
        if v is None or v == "":
            return default
        return int(float(v))
    except Exception:
        return default

BASE = {
    "eth":     {"LIQ_POSITIVE": 1_000_000, "LIQ_LOW": 200_000, "VOL_ACTIVE": 2_000_000, "VOL_THIN": 25_000},
    "bsc":     {"LIQ_POSITIVE":   300_000, "LIQ_LOW":  60_000, "VOL_ACTIVE":   600_000, "VOL_THIN": 12_000},
    "polygon": {"LIQ_POSITIVE":   200_000, "LIQ_LOW":  40_000, "VOL_ACTIVE":   400_000, "VOL_THIN":  8_000},
}
FALLBACK = {"LIQ_POSITIVE": 25_000, "LIQ_LOW": 10_000, "VOL_ACTIVE": 50_000, "VOL_THIN": 5_000}

def _tiers(market: Dict[str, Any]) -> Dict[str, int]:
    short = _short_chain(market)
    t = dict(FALLBACK)
    t.update(BASE.get(short, {}))
    for k in ("LIQ_POSITIVE","LIQ_LOW","VOL_ACTIVE","VOL_THIN"):
        t[k] = _env_num(f"{k}_{short.upper()}", _env_num(k, t[k]))
    return t

def _human_status(s: str) -> str:
    if not isinstance(s, str):
        return str(s)
    s = s.replace("_", " ").replace("-", " ")
    s = _re.sub(r'(?<!^)([A-Z])', r' \1', s)
    return s.lower()

# RDAP country placeholder flag (default ON):
# Set env RDAP_COUNTRY_PLACEHOLDER=0 to disable showing "Country: —" when country is missing.
_RDAP_COUNTRY_PLACEHOLDER = (os.getenv("RDAP_COUNTRY_PLACEHOLDER", "1") not in ("0", "false", "False", ""))

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

    header = f"*Metridex QuickScan — {pair}* {_pick_color(verdict, market)} ({_score(verdict)})"
    lines = [
        header,
        f"`{chain}`  •  Price: *{price}*",
        f"FDV: {fdv}  •  MC: {mc}  •  Liq: {liq}",
        f"Vol 24h: {vol}  •  Δ5m {chg5}  •  Δ1h {chg1}  •  Δ24h {chg24}",
        f"Age: {age}  •  Source: {src_line}  •  as of {asof}",
    ]
    return "\n".join(lines)

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

    chg5  = _fmt_pct(_get(market, "priceChanges", "m5"))
    chg1  = _fmt_pct(_get(market, "priceChanges", "h1"))
    chg24 = _fmt_pct(_get(market, "priceChanges", "h24"))
    age   = _fmt_age_days(_get(market, "ageDays"))
    src_  = _get(market, "source", default="DexScreener")
    asof  = _fmt_time(_get(market, "asof"))

    links = _get(market, "links") or {}
    l_dex  = (links or {}).get("dex") or "—"
    l_scan = (links or {}).get("scan") or "—"
    l_site = (links or {}).get("site") or "—"
    if isinstance(l_site, dict):
        l_site = l_site.get("url") or l_site.get("label") or "—"

    parts: List[str] = []
    parts.append(f"*Details — {pair}* {_pick_color(verdict, market)} ({_score(verdict)})")

    snapshot_lines = [
        "*Snapshot*",
        f"• Price: {price}  ({chg5}, {chg1}, {chg24})",
        f"• FDV: {fdv}  • MC: {mc}",
        f"• Liquidity: {liq}  • 24h Volume: {vol}",
        f"• Age: {age}  • Source: {src_}",
        f"• As of: {asof}",
    ]
    parts.append("\n".join(snapshot_lines))

    parts.append(f"*Token*\n• Chain: `{chain}`\n• Address: `{token}`")
    parts.append(f"*Pair*\n• Address: `{pair_addr}`\n• Symbol: {pair}")

    # RDAP / WHOIS (optional)
    import os as _os
    try:
        _enable_rdap = _os.getenv("ENABLE_RDAP", "1").lower() in ("1","true","yes")
    except Exception:
        _enable_rdap = True
    if _enable_rdap and l_site and l_site != "—":
        try:
            from rdap_client import lookup as _rdap_lookup
        except Exception:
            _rdap_lookup = None
        if _rdap_lookup:
            try:
                _rd = _rdap_lookup(l_site)
            except Exception:
                _rd = None
            if _rd:
                _rd_lines = ["*WHOIS/RDAP*"]
                if _rd.get("domain"):    _rd_lines.append(f"• Domain: {_rd['domain']}")
                if _rd.get("registrar"): _rd_lines.append(f"• Registrar: {_rd['registrar']}")
                if _rd.get("registrar_id"): _rd_lines.append(f"• Registrar IANA ID: {_rd['registrar_id']}")
                if _rd.get("created"):   _rd_lines.append(f"• Created: {_rd['created']}")
                if _rd.get("expires"):   _rd_lines.append(f"• Expires: {_rd['expires']}")
                if _rd.get("age_days") is not None: _rd_lines.append(f"• Domain age: {_rd['age_days']} d")
                if _rd.get("country"):
                    _rd_lines.append(f"• Country: {_rd['country']}")
                elif _RDAP_COUNTRY_PLACEHOLDER:
                    _rd_lines.append("• Country: —")
                if _rd.get("status"):
                    try:
                        _st = list(_rd["status"])[:4]
                        if _st:
                            _rd_lines.append("• Status: " + ", ".join(_human_status(x) for x in _st))
                    except Exception:
                        pass
                if _rd.get("flags"):     _rd_lines.append("• RDAP flags: " + ", ".join(_rd["flags"]))
                parts.append("\n".join(_rd_lines))

    # Links (text) — hidden by default, we have buttons
    _show_links = _os.getenv("SHOW_LINKS_IN_DETAILS", "0").lower() in ("1","true","yes")
    if _show_links:
        ll = ["*Links*"]
        if l_dex and l_dex != "—": ll.append(f"• DEX: {l_dex}")
        if (links or {}).get("dexscreener"): ll.append(f"• DexScreener: {(links or {}).get('dexscreener')}")
        if l_scan and l_scan != "—": ll.append(f"• Scan: {l_scan}")
        if l_site and l_site != "—": ll.append(f"• Site: {l_site}")
        parts.append("\n".join(ll))

    # Website intel (if provided via ctx)
    web = (ctx or {}).get("webintel") or {}
    if web:
        who = web.get("whois") or {}
        ssl = web.get("ssl") or {}
        way = web.get("wayback") or {}
        parts.append(
            "*Website intel*"
            + f"\n• WHOIS: created {who.get('created') or 'n/a'}, registrar {who.get('registrar') or 'n/a'}"
            + f"\n• SSL: ok={ssl.get('ok') if ssl.get('ok') is not None else 'n/a'}, expires {ssl.get('expires') or 'n/a'}"
            + f"\n• Wayback first: {way.get('first') or 'n/a'}"
        )

    return "\n".join(parts)




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
    return "\n".join([header] + lines).replace("\n", "\n")

def render_whypp(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    # Weighted Top-3 positives and Top-3 risks (chain-aware)
    m = market or {}
    pos: List[tuple[str,int]] = []
    risk: List[tuple[str,int]] = []

    def add_pos(label:str, w:int): pos.append((label,w))
    def add_risk(label:str, w:int): risk.append((label,w))

    t = _tiers(m)

    liq = _get(m, "liq")
    vol = _get(m, "vol24h")
    ch24 = _get(m, "priceChanges","h24")
    age = _get(m, "ageDays")
    fdv = _get(m, "fdv"); mc = _get(m, "mc")

    try:
        if isinstance(liq,(int,float)) and liq >= t["LIQ_POSITIVE"]: add_pos(f"Healthy liquidity (${liq:,.0f})", 3)
        if isinstance(vol,(int,float)) and vol >= t["VOL_ACTIVE"]:   add_pos(f"Active 24h volume (${vol:,.0f})", 2)
        if isinstance(age,(int,float)) and age >= 7:                 add_pos(f"Established >1 week (~{age:.1f}d)", 2)
        if isinstance(ch24,(int,float)) and -30 < ch24 < 80:         add_pos(f"Moderate 24h move ({ch24:+.0f}%)", 1)
    except Exception:
        pass

    try:
        if liq is None: add_risk("Liquidity unknown", 2)
        elif isinstance(liq,(int,float)) and liq < t["LIQ_LOW"]: add_risk(f"Low liquidity (${liq:,.0f})", 3)
        if vol is None: add_risk("24h volume unknown", 1)
        elif isinstance(vol,(int,float)) and vol < t["VOL_THIN"]: add_risk(f"Thin 24h volume (${vol:,.0f})", 2)
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
    return "\n".join(lines).replace("\n", "\n")

def render_lp(info: Dict[str, Any], lang: str = "en") -> str:
    p = info or {}
    status_raw = str(p.get("status") or "").lower()
    burned_flag = bool(p.get("burned")) or status_raw in ("burned","fully-burned")
    burned_pct = p.get("burnedPct")
    locked_pct = p.get("lockedPct")
    lockers = p.get("lockers") or []
    until = p.get("until") or "—"
    addr = p.get("lpAddress") or "—"

    def fmt_pct(v):
        try:
            return f"{float(v):.2f}%"
        except Exception:
            return "—"

    lines = ["*LP lock (lite)*"]
    if burned_flag or (isinstance(burned_pct,(int,float)) and burned_pct >= 95):
        bp = fmt_pct(burned_pct) if burned_pct is not None else "≥95%"
        lines.append(f"• Burned: {bp} (LP → 0x…dead)")
    elif isinstance(burned_pct,(int,float)):
        if burned_pct >= 50:
            lines.append(f"• Mostly burned: {fmt_pct(burned_pct)}")
        elif burned_pct >= 5:
            lines.append(f"• Partially burned: {fmt_pct(burned_pct)}")
        else:
            lines.append(f"• Burned: {fmt_pct(burned_pct)}")
    else:
        lines.append("• Burned: —")

    if isinstance(locked_pct,(int,float)) and locked_pct > 0:
        lines.append(f"• Locked via lockers: {fmt_pct(locked_pct)}")

    if lockers:
        for lk in lockers[:5]:
            addr_short = (lk.get("locker","") or "—")
            bal = lk.get("balance")
            pct = lk.get("pct")
            try:
                bal_s = f"{int(bal):,}" if isinstance(bal,int) else str(bal)
            except Exception:
                bal_s = str(bal)
            lines.append(f"  · {addr_short} — {bal_s} ({fmt_pct(pct)})")
    if until not in ("—", None, ""):
        lines.append(f"• Unlocks: {until}")
    lines.append(f"• LP token: `{addr}`")
    return "\n".join(lines)
