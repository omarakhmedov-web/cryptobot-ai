from __future__ import annotations
import os
import requests as _rq
import time
import datetime as _dt
from typing import Any, Dict, Optional, List
import re as _re
import socket as _socket, ssl as _ssl
import copy as _copy

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

_RDAP_COUNTRY_PLACEHOLDER = (os.getenv("RDAP_COUNTRY_PLACEHOLDER", "1") not in ("0", "false", "False", ""))

_WAYBACK_SUMMARY = (os.getenv("WAYBACK_SUMMARY", "1") not in ("0","false","False",""))
_WAYBACK_TIMEOUT_S = float(os.getenv("WAYBACK_TIMEOUT_S", "3.5"))
_wb_cache: Dict[str, Any] = {}

_WEB_HEAD_CHECK = (os.getenv("WEB_HEAD_CHECK", "1") not in ("0","false","False",""))
_WEB_TIMEOUT_S = float(os.getenv("WEB_TIMEOUT_S", "4.0"))
_WEB_SHOW_HSTS = (os.getenv("WEB_SHOW_HSTS", "1") not in ("0","false","False",""))

_CACHE_TTL = int(os.getenv("WEB_CACHE_TTL", "1800"))
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

def _http_head_or_get(url: str, allow_redirects: bool=True):
    try:
        r = _rq.get(url, timeout=_WEB_TIMEOUT_S, allow_redirects=allow_redirects, headers={
            "User-Agent": "MetridexBot/1.0 (+https://metridex.com)"
        })
        return r
    except Exception:
        return None

def _web_probe(domain: str) -> Dict[str, Any]:
    if not _WEB_HEAD_CHECK: return {}
    key = f"web:{domain}"
    cached = _cache_get(_web_cache, key)
    if cached is not None: return cached

    info: Dict[str, Any] = {"https_enforced": None, "server": None, "hsts": None}
    try:
        r = _http_head_or_get(f"http://{domain}", allow_redirects=True)
        final_url = r.url if r is not None else None
        if r is not None:
            info["https_enforced"] = bool(final_url and final_url.startswith("https://"))
        r2 = _http_head_or_get(f"https://{domain}", allow_redirects=True)
        if r2 is not None:
            info["server"] = r2.headers.get("Server")
            if _WEB_SHOW_HSTS:
                info["hsts"] = r2.headers.get("Strict-Transport-Security")
    except Exception:
        pass
    return _cache_put(_web_cache, key, info)

def _tls_probe(domain: str) -> Dict[str, Any]:
    try:
        ctx = _ssl.create_default_context()
        with _socket.create_connection((domain, 443), timeout=_WEB_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp_raw = cert.get('notAfter')
        exp_fmt = None
        if exp_raw:
            try:
                dt = _dt.datetime.strptime(exp_raw, '%b %d %H:%M:%S %Y %Z')
                exp_fmt = dt.strftime('%Y-%m-%d')
            except Exception:
                pass
        return {'ok': True, 'expires': exp_fmt}
    except Exception:
        return {'ok': None, 'expires': None}

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
        r1 = _rq.get(base, params=params_first, timeout=_WAYBACK_TIMEOUT_S)
        if r1.ok:
            j1 = r1.json()
            if isinstance(j1, list) and len(j1) >= 2 and isinstance(j1[1], list) and j1[1]:
                ts1 = j1[1][0]
                out["first"] = f"{ts1[0:4]}-{ts1[4:6]}-{ts1[6:8]}"
        params_last = dict(params_first); params_last["sort"] = "descending"
        r2 = _rq.get(base, params=params_last, timeout=_WAYBACK_TIMEOUT_S)
        if r2.ok:
            j2 = r2.json()
            if isinstance(j2, list) and len(j2) >= 2 and isinstance(j2[1], list) and j2[1]:
                ts2 = j2[1][0]
                out["last"] = f"{ts2[0:4]}-{ts2[4:6]}-{ts2[6:8]}"
        out["ok"] = bool(out["first"] or out["last"])
    except Exception:
        pass
    return _cache_put(_wb_cache, key, out)

def _resolve_domain(_rd: dict, market: dict, ctx: dict) -> str | None:
    """Find a domain to probe, from RDAP, ctx, or market links.
    Returns bare hostname like "pepe.vip" without scheme/path.
    """
    def _host_from_url(u: str):
        try:
            from urllib.parse import urlparse
            p = urlparse(u.strip())
            host = p.netloc or p.path
            host = host.strip().lstrip("*.").split("/")[0]
            if host.lower().startswith("www."):
                host = host[4:]
            return host or None
        except Exception:
            return None
    dom = None
    try:
        cdom = ctx.get("domain") if isinstance(ctx, dict) else None
        if isinstance(cdom, str) and cdom:
            dom = _host_from_url(cdom) or cdom
    except Exception:
        pass
    if not dom and isinstance(market, dict):
        try:
            site = ((market.get("links") or {}).get("site")) or market.get("site")
            if isinstance(site, str):
                dom = _host_from_url(site) or dom
        except Exception:
            pass
    if not dom and isinstance(_rd, dict):
        for k in ("ldhName","unicodeName","domain","name","handle"):
            v = _rd.get(k)
            if isinstance(v, str) and v:
                candidate = v.strip().lstrip("*.")
                if "." in candidate and "/" not in candidate and " " not in candidate:
                    dom = candidate
                    break
    if not dom and isinstance(_rd, dict):
        pat = _re.compile(r"(?i)\b([a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,}\b")
        try:
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
            cand = scan(_rd)
            for x in cand:
                if x:
                    dom = x.lstrip("*.")
                    break
        except Exception:
            pass
    return dom

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

    # Website intel — robust + isolated (no ctx mutation)
    web = _copy.deepcopy((ctx or {}).get("webintel") or {"whois": {}, "ssl": {}, "wayback": {}})
    who = dict(web.get("whois") or {})
    ssl = dict(web.get("ssl") or {})
    way = dict(web.get("wayback") or {})

    # Accept flattened keys from server (if any)
    try:
        if not who.get("created") and isinstance(web, dict):
            wc = web.get("whois_created") or web.get("created")
            if wc: who["created"] = wc
        if not who.get("registrar") and isinstance(web, dict):
            wr = web.get("whois_registrar") or web.get("registrar")
            if wr: who["registrar"] = wr
        if (ssl.get("ok") is None) and isinstance(web, dict):
            so = web.get("ssl_ok")
            if so is not None: ssl["ok"] = so
        if not ssl.get("expires") and isinstance(web, dict):
            se = web.get("ssl_expires")
            if se: ssl["expires"] = se
        if not way.get("first") and isinstance(web, dict):
            wf = web.get("wayback_first")
            if wf: way["first"] = wf
    except Exception:
        pass

    dom_block = (market or {}).get("domain") or {}

    # RDAP from ctx (if present) to help with domain resolution and WHOIS
    _ctx_rdap = (ctx or {}).get("rdap") or {}
    _rd_local = _ctx_rdap if isinstance(_ctx_rdap, dict) else {}

    _domain_to_probe = _resolve_domain(_rd_local or {}, market, ctx)
    prev_dom = web.get('__domain')
    cur_dom = _domain_to_probe
    if isinstance(prev_dom, str) and isinstance(cur_dom, str):
        pd, cd = prev_dom.lower(), cur_dom.lower()
        if not (pd == cd or pd.endswith('.' + cd) or cd.endswith('.' + pd)):
            who, ssl, way = {}, {}, {}
    if isinstance(cur_dom, str):
        web['__domain'] = cur_dom

    # Guard market['domain'] WHOIS with domain match
    try:
        _dom_block_name = (dom_block.get("domain") or dom_block.get("name") or dom_block.get("ldhName") or "").lstrip("*.")
    except Exception:
        _dom_block_name = ""
    _dom_match = False
    try:
        if _domain_to_probe and _dom_block_name:
            dl = str(_domain_to_probe).lower()
            bl = str(_dom_block_name).lower()
            _dom_match = (dl == bl) or dl.endswith("." + bl) or bl.endswith("." + dl)
    except Exception:
        _dom_match = False
    if _dom_match:
        who_created = who.get("created") or dom_block.get("created") or dom_block.get("creationDate") or dom_block.get("createdAt") or dom_block.get("registered") or dom_block.get("registeredAt")
        who_registrar = who.get("registrar") or dom_block.get("registrar") or dom_block.get("registrarName") or dom_block.get("registrar_url") or dom_block.get("registrarUrl")
    else:
        who_created, who_registrar = who.get("created"), who.get("registrar")

    # If still missing, reuse RDAP from ctx (scoped) — also gated by domain
    if isinstance(_rd_local, dict):
        _rd_dom = (_rd_local.get("domain") or _rd_local.get("ldhName") or "").lstrip("*.").lower()
        _dm = (cur_dom or "").lower()
        _match_rdap = bool(_rd_dom and _dm and (_rd_dom == _dm or _rd_dom.endswith("." + _dm) or _dm.endswith("." + _rd_dom)))
        if _match_rdap:
            if not who_created:   who_created = _rd_local.get("created")
            if not who_registrar: who_registrar = _rd_local.get("registrar")

    # Additional fallback: ctx['whois'] (if API supplies it separately)
    _ctx_whois = (ctx or {}).get("whois") or {}
    if isinstance(_ctx_whois, dict):
        if not who_created:
            who_created = _ctx_whois.get("created") or _ctx_whois.get("creationDate") or _ctx_whois.get("createdAt")
        if not who_registrar:
            who_registrar = _ctx_whois.get("registrar") or _ctx_whois.get("registrarName")

    if who_created or who_registrar:
        who["created"] = who_created
        who["registrar"] = who_registrar

    # Active probes if data is missing
    if _domain_to_probe:
        if (ssl.get('ok') is None) or (not ssl.get('expires')):
            _tls = _tls_probe(_domain_to_probe)
            if ssl.get('ok') is None and (_tls.get('ok') is not None):
                ssl['ok'] = _tls['ok']
            if (not ssl.get('expires')) and _tls.get('expires'):
                ssl['expires'] = _tls['expires']
        if _domain_to_probe and (ssl.get('ok') is None or not ssl.get('expires')):
            _tls2 = _tls_probe('www.' + _domain_to_probe)
            if ssl.get('ok') is None and (_tls2.get('ok') is not None):
                ssl['ok'] = _tls2['ok']
            if (not ssl.get('expires')) and _tls2.get('expires'):
                ssl['expires'] = _tls2['expires']
        if _domain_to_probe and (ssl.get('ok') is None):
            _wp = _web_probe(_domain_to_probe)
            if isinstance(_wp, dict) and _wp.get('https_enforced') is True:
                ssl['ok'] = True
        if not way.get('first'):
            _wb = _wayback_summary(_domain_to_probe)
            if isinstance(_wb, dict) and _wb.get('first'):
                way['first'] = _wb['first']
            if not way.get('first'):
                _wb2 = _wayback_summary('www.' + _domain_to_probe)
                if isinstance(_wb2, dict) and _wb2.get('first'):
                    way['first'] = _wb2['first']

    parts.append(
        "*Website intel*"
        + f"\\n• WHOIS: created {who.get('created') or 'n/a'}, registrar {who.get('registrar') or 'n/a'}"
        + f"\\n• SSL: ok={(ssl.get('ok') if ssl.get('ok') is not None else 'n/a')}, expires {ssl.get('expires') or 'n/a'}"
        + f"\\n• Wayback first: {way.get('first') or 'n/a'}"
    )

    return "\\n".join(parts)

def render_why(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
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
        return "*Why?*\\n• No specific risk factors detected"
    header = "*Why?*"
    lines = [f"• {r}" for r in uniq]
    return "\\n".join([header] + lines).replace("\\n", "\\n")

def render_whypp(verdict, market: Dict[str, Any], lang: str = "en") -> str:
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
    return "\\n".join(lines).replace("\\n", "\\n")

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
    return "\\n".join(lines)
