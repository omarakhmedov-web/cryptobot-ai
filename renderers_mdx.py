from __future__ import annotations
import os, time, datetime as _dt, re as _re
from typing import Any, Dict, Optional, List
import requests as _rq

# Network + TLS
import socket as _socket, ssl as _ssl

# =============================
# Helpers
# =============================

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

# =============================
# Domain + Web intel
# =============================

_RDAP_COUNTRY_PLACEHOLDER = (os.getenv("RDAP_COUNTRY_PLACEHOLDER", "1") not in ("0", "false", "False", ""))
_WAYBACK_SUMMARY = (os.getenv("WAYBACK_SUMMARY", "1") not in ("0","false","False",""))
_WAYBACK_TIMEOUT_S = float(os.getenv("WAYBACK_TIMEOUT_S", "2.5"))

_WEB_HEAD_CHECK = (os.getenv("WEB_HEAD_CHECK", "1") not in ("0","false","False",""))
_WEB_TIMEOUT_S = float(os.getenv("WEB_TIMEOUT_S", "2.0"))
_WEB_SHOW_HSTS = (os.getenv("WEB_SHOW_HSTS", "1") not in ("0","false","False",""))

_CACHE_TTL = int(os.getenv("WEB_CACHE_TTL", "1800"))
_wb_cache: Dict[str, Any] = {}
_web_cache: Dict[str, Any] = {}

def _cache_get(cache: Dict[str, Any], key: str):
    item = cache.get(key)
    if not item: return None
    ts, val = item
    if time.time() - ts > _CACHE_TTL:
        cache.pop(key, None)
        return None
    return val

def _cache_put(cache: Dict[str, Any], key: str, val: Any):
    cache[key] = (time.time(), val)
    return val

def _resolve_domain(_rd: dict, market: dict, ctx: dict) -> str | None:
    """Find a domain to probe, from ctx, market links, or RDAP."""
    def _host_from_url(u: str):
        try:
            from urllib.parse import urlparse
            p = urlparse(u.strip())
            host = p.netloc or p.path  # tolerate "example.com" without scheme
            host = host.strip().lstrip("*.").split("/")[0]
            if host.lower().startswith("www."):
                host = host[4:]
            return host or None
        except Exception:
            return None
    # ctx.domain
    try:
        cdom = (ctx or {}).get("domain")
        if isinstance(cdom, str) and cdom:
            h = _host_from_url(cdom)
            if h: return h
    except Exception:
        pass
    # market.links.site
    try:
        site = ((market or {}).get("links") or {}).get("site") or (market or {}).get("site")
        if isinstance(site, str):
            h = _host_from_url(site)
            if h: return h
        elif isinstance(site, dict):
            u = site.get("url") or site.get("label")
            if isinstance(u, str):
                h = _host_from_url(u)
                if h: return h
    except Exception:
        pass
    # RDAP
    for k in ("ldhName","unicodeName","domain","name","handle"):
        v = (_rd or {}).get(k)
        if isinstance(v, str) and v and "." in v and "/" not in v:
            return v.lstrip("*.")
    # fallback: scan strings
    try:
        pat = _re.compile(r"(?i)\b([a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,}\b")
        def scan(obj):
            out = []
            if isinstance(obj, dict):
                for vv in obj.values():
                    out.extend(scan(vv))
            elif isinstance(obj, list):
                for vv in obj:
                    out.extend(scan(vv))
            elif isinstance(obj, str):
                for m in pat.finditer(obj):
                    out.append(m.group(0))
            return out
        cand = scan(_rd or {})
        if cand:
            return cand[0].lstrip("*.")
    except Exception:
        pass
    return None

def _http_get(url: str, allow_redirects: bool=True):
    try:
        return _rq.get(url, timeout=_WEB_TIMEOUT_S, allow_redirects=allow_redirects, headers={
            "User-Agent": "MetridexBot/1.0 (+https://metridex.com)"
        })
    except Exception:
        return None

def _web_probe(domain: str) -> Dict[str, Any]:
    """Lightweight website probe via HTTP(S) and headers."""
    if not _WEB_HEAD_CHECK: return {}
    key = f"web:{domain}"
    cached = _cache_get(_web_cache, key)
    if cached is not None: return cached

    info: Dict[str, Any] = {"https_enforced": None, "server": None, "hsts": None}
    try:
        r = _http_get(f"http://{domain}", allow_redirects=True)
        final = r.url if r is not None else None
        if r is not None:
            chain = [h.url for h in r.history] + ([r.url] if r.url else [])
            if chain:
                try:
                    from urllib.parse import urlparse
                    info["https_enforced"] = any(urlparse(u).scheme == "https" for u in chain[-2:] + [chain[-1]])
                except Exception:
                    info["https_enforced"] = final and final.startswith("https://")
        r2 = _http_get(f"https://{domain}", allow_redirects=True)
        if r2 is not None:
            info["server"] = r2.headers.get("Server")
            if _WEB_SHOW_HSTS:
                info["hsts"] = r2.headers.get("Strict-Transport-Security")
    except Exception:
        pass
    return _cache_put(_web_cache, key, info)

def _tls_probe(domain: str) -> Dict[str, Any]:
    """Direct TLS handshake to read certificate expiry; very fast (<2s) with timeouts."""
    try:
        ctx = _ssl.create_default_context()
        with _socket.create_connection((domain, 443), timeout=_WEB_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp_raw = cert.get("notAfter")
        exp_fmt = None
        if exp_raw:
            try:
                # Example: 'Dec 16 14:26:31 2025 GMT'
                dt = _dt.datetime.strptime(exp_raw, "%b %d %H:%M:%S %Y %Z")
                exp_fmt = dt.strftime("%Y-%m-%d")
            except Exception:
                pass
        return {"ok": True, "expires": exp_fmt}
    except Exception:
        # could be blocked or site without TLS
        return {"ok": None, "expires": None}

def _wayback_summary(domain: str):
    if not _WAYBACK_SUMMARY or not isinstance(domain, str): 
        return None
    key = f"wb:{domain}"
    cached = _cache_get(_wb_cache, key)
    if cached is not None: 
        return cached
    out = {"ok": False, "first": None, "last": None, "url": f"https://web.archive.org/web/*/{domain}"}
    try:
        base = "https://web.archive.org/cdx/search/cdx"
        params_first = {"url": domain, "output": "json", "fl": "timestamp", "filter": "statuscode:200", "limit": "1", "from": "19960101", "to": "99991231", "sort": "ascending"}
        r1 = _rq.get(base, params=params_first, timeout=2.2)
        if r1.ok:
            j1 = r1.json()
            if isinstance(j1, list) and len(j1) >= 2 and isinstance(j1[1], list) and j1[1]:
                ts1 = j1[1][0]
                out["first"] = f"{ts1[0:4]}-{ts1[4:6]}-{ts1[6:8]}"
        params_last = dict(params_first); params_last["sort"] = "descending"
        r2 = _rq.get(base, params=params_last, timeout=2.2)
        if r2.ok:
            j2 = r2.json()
            if isinstance(j2, list) and len(j2) >= 2 and isinstance(j2[1], list) and j2[1]:
                ts2 = j2[1][0]
                out["last"] = f"{ts2[0:4]}-{ts2[4:6]}-{ts2[6:8]}"
        out["ok"] = bool(out["first"] or out["last"])
    except Exception:
        pass
    return _cache_put(_wb_cache, key, out)

# =============================
# Renderers
# =============================

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

    # Snapshot
    snapshot_lines = [
        "*Snapshot*",
        f"• Price: {price}  ({chg5}, {chg1}, {chg24})",
        f"• FDV: {fdv}  • MC: {mc}",
        f"• Liquidity: {liq}  • 24h Volume: {vol}",
        f"• Age: {age}  • Source: {src_}",
        f"• As of: {asof}",
    ]
    parts.append("\n".join(snapshot_lines))

    # Token/Pair
    parts.append(f"*Token*\n• Chain: `{chain}`\n• Address: `{token}`")
    parts.append(f"*Pair*\n• Address: `{pair_addr}`\n• Symbol: {pair}")

    # RDAP (if server provided via ctx)
    _rd = (ctx or {}).get("rdap") or {}
    if isinstance(_rd, dict) and _rd:
        _rd_lines = ["*WHOIS/RDAP*"]
        if _rd.get("domain"):    _rd_lines.append(f"• Domain: {_rd['domain']}")
        if _rd.get("registrar"): _rd_lines.append(f"• Registrar: {_rd['registrar']}")
        if _rd.get("registrar_id"): _rd_lines.append(f"• Registrar IANA ID: {_rd['registrar_id']}")
        if _rd.get("created"):   _rd_lines.append(f"• Created: {_rd['created']}")
        if _rd.get("expires"):   _rd_lines.append(f"• Expires: {_rd['expires']}")
        if _rd.get("age_days") is not None: _rd_lines.append(f"• Domain age: {_rd['age_days']} d")
        parts.append("\n".join(_rd_lines))

    # =============================
    # Website intel — ACTIVE PROBES (fix n/a)
    # =============================
    web = (ctx or {}).get("webintel") or {"whois": {}, "ssl": {}, "wayback": {}}
    who = (web.get("whois") or {}) if isinstance(web, dict) else {}
    ssl = (web.get("ssl") or {}) if isinstance(web, dict) else {}
    way = (web.get("wayback") or {}) if isinstance(web, dict) else {}

    # Resolve domain to probe
    domain = _resolve_domain(_rd, market, ctx) or None

    # If SSL data missing — probe via TLS handshake
    if domain and (ssl.get("ok") is None or ssl.get("expires") in (None, "", "—", "n/a")):
        tls = _tls_probe(domain)
        if ssl.get("ok") is None and tls.get("ok") is not None:
            ssl["ok"] = tls["ok"]
        if not ssl.get("expires") and tls.get("expires"):
            ssl["expires"] = tls["expires"]

    # If Wayback missing — query CDX API
    if domain and not way.get("first"):
        wb = _wayback_summary(domain)
        if isinstance(wb, dict):
            if wb.get("first"): way["first"] = wb["first"]
            if wb.get("last"):  way["last"]  = wb["last"]

    # Fallback WHOIS (created/registrar) from RDAP if missing
    if domain:
        if not who.get("created") and isinstance(_rd, dict):
            if _rd.get("created"): who["created"] = _rd["created"]
        if not who.get("registrar") and isinstance(_rd, dict):
            if _rd.get("registrar"): who["registrar"] = _rd["registrar"]

    parts.append(
        "*Website intel*"
        + f"\n• WHOIS: created {who.get('created') or 'n/a'}, registrar {who.get('registrar') or 'n/a'}"
        + f"\n• SSL: ok={(ssl.get('ok') if ssl.get('ok') is not None else 'n/a')}, expires {ssl.get('expires') or 'n/a'}"
        + f"\n• Wayback first: {way.get('first') or 'n/a'}"
    )

    return "\n".join(parts)


def render_why(verdict, market: Dict[str, Any], lang: str = "en") -> str:
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
    return "\n".join([header] + lines)

def render_whypp(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    m = market or {}
    pos: List[tuple[str,int]] = []
    risk: List[tuple[str,int]] = []

    def add_pos(label:str, w:int): pos.append((label,w))
    def add_risk(label:str, w:int): risk.append((label,w))

    # Simplified thresholds
    LIQ_POS = 1_000_000 if _get(m,"chain","") in ("eth","ethereum","Ethereum") else 200_000
    VOL_ACT = 2_000_000 if _get(m,"chain","") in ("eth","ethereum","Ethereum") else 400_000
    VOL_THN = 25_000 if _get(m,"chain","") in ("eth","ethereum","Ethereum") else 8_000

    liq = _get(m, "liq"); vol = _get(m, "vol24h")
    ch24 = _get(m, "priceChanges","h24"); age = _get(m, "ageDays")
    fdv = _get(m,"fdv"); mc = _get(m,"mc")

    try:
        if isinstance(liq,(int,float)) and liq >= LIQ_POS: add_pos(f"Healthy liquidity (${liq:,.0f})", 3)
        if isinstance(vol,(int,float)) and vol >= VOL_ACT: add_pos(f"Active 24h volume (${vol:,.0f})", 2)
        if isinstance(age,(int,float)) and age >= 7:       add_pos(f"Established >1 week (~{age:.1f}d)", 2)
        if isinstance(ch24,(int,float)) and -30 < ch24 < 80: add_pos(f"Moderate 24h move ({ch24:+.0f}%)", 1)
    except Exception:
        pass

    try:
        if liq is None: add_risk("Liquidity unknown", 2)
        elif isinstance(liq,(int,float)) and liq < (LIQ_POS/5): add_risk(f"Low liquidity (${liq:,.0f})", 3)
        if vol is None: add_risk("24h volume unknown", 1)
        elif isinstance(vol,(int,float)) and vol < VOL_THN: add_risk(f"Thin 24h volume (${vol:,.0f})", 2)
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
    return "\n".join(lines)

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
