from __future__ import annotations
import os

# --- OMEGA-713K D2 risk palette integration (20 -> yellow) ---
try:
    from risk_palette_OMEGA_D2 import risk_color_for_score as _risk_color_for_score, get_risk_emoji as _get_risk_emoji
except Exception:
    def _risk_color_for_score(score: int) -> str:
        try:
            s = int(score)
        except Exception:
            s = 0
        if s < 0: s = 0
        if s > 100: s = 100
        if s <= 19: return "green"
        if s <= 39: return "yellow"  # D2: 20 -> yellow
        if s <= 59: return "orange"
        return "red"
    def _get_risk_emoji(score: int) -> str:
        c = _risk_color_for_score(score)
        return {"green":"🟢","yellow":"🟡","orange":"🟠","red":"🔴"}.get(c, "🟢")
# --- /OMEGA-713K D2 ---
import requests as _rq
import time
import datetime as _dt
from typing import Any, Dict, Optional, List
from lp_lite_v2 import check_lp_lock_v2

# === Metridex: Age bucket & Δ24h helpers (SAFE) ===
def _age_bucket_label(age_days: float) -> str:
    try:
        d = float(age_days)
    except Exception:
        return "Established"
    if d >= 1095: label = "Long-standing (>3 years)"
    elif d >= 730: label = "Long-standing (>2 years)"
    elif d >= 365: label = "Established >1 year"
    elif d >= 180: label = "Established >6 months"
    elif d >= 90:  label = "Established >3 months"
    elif d >= 30:  label = "Established >1 month"
    elif d >= 7:   label = "Established >1 week"
    else:          label = "Newly created"
    approx = (f"~{d/365.0:.1f}y" if d >= 365 else f"~{d:.0f}d")
    return f"{label} ({approx})"

def _delta24h_positive_label(ch24: float):
    try:
        v = float(ch24)
    except Exception:
        return None
    if abs(v) <= 6.0:
        return "Stable day (|Δ24h| ≤ 6%)"
    return None

def _normalize_reason_text(line: str) -> str:
    import re as _re
    try:
        s = str(line)
    except Exception:
        return line
    m = _re.search(r"Moderate 24h move \(([+\-]?\d+)%\)", s)
    if m:
        try:
            val_abs = str(abs(int(m.group(1))))
        except Exception:
            val_abs = m.group(1).lstrip("+-")
        s = _re.sub(r"Moderate 24h move \(([+\-]?\d+)%\)", f"Contained daily move (|Δ24h| ≈ {val_abs}%)", s)
    m2 = _re.search(r"Established\s*>\s*1\s*week\s*\(~\s*([\d\.]+)\s*d\)", s, _re.I)
    if m2:
        try:
            days = float(m2.group(1))
            s = _re.sub(r"Established\s*>\s*1\s*week\s*\(~\s*([\d\.]+)\s*d\)", _age_bucket_label(days), s, flags=_re.I)
        except Exception:
            pass
    return s


# === Module-scope helper: pretty registrar name (used in RDAP & Website) ===
def _fmt_registrar__INNER_SHOULD_NOT_EXIST(val):

# Back-compat alias for registrar formatter
    s = (val or "").strip()
    if not s or s in ("—","n/a","N/A","NA"):
        return "n/a"
    import re as _re
    s = _re.sub(r"\s+", " ", s.replace(",", ", "))
    base = s.title()
    base = _re.sub(r"\bInc\b\.?", "Inc.", base)
    base = _re.sub(r"\bLlc\b\.?", "LLC", base)
    base = _re.sub(r"\bLtd\b\.?", "Ltd.", base)
    base = _re.sub(r"\bGmbh\b", "GmbH", base)
    base = _re.sub(r"\bAg\b", "AG", base)
    base = _re.sub(r"\bNv\b", "NV", base)
    base = _re.sub(r"\bBv\b", "BV", base)
    base = _re.sub(r"\bSa\b", "S.A.", base)
    base = _re.sub(r"\bSpa\b", "S.p.A.", base)
    base = _re.sub(r"(?i)Namecheap", "Namecheap", base)
    base = _re.sub(r"\s+,", ",", base)
    base = _re.sub(r",\s*", ", ", base)
    return base.strip()
_fmt_registrar = _fmt_registrar__INNER_SHOULD_NOT_EXIST  # back-compat alias

# Country inference helper (no new ENV; graceful fallback)
try:
    from webintel_country_fix_v1 import infer_country, country_label
except Exception:
    def infer_country(meta): 
        return None
    def country_label(country):
        return f"Country: {country}" if country else "Country: n/a"

import re as _re
import socket as _socket, ssl as _ssl

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
    # If absolutely no market signals, keep neutral
    if (not liq) and (not vol) and (fdv is None and mc is None):
        return "⚪"

    # Prefer score-based palette (D2)
    s = None
    try:
        s = getattr(verdict, "score", None)
    except Exception:
        s = None
    if s is None:
        try:
            s = (verdict or {}).get("score")
        except Exception:
            s = None
    try:
        if s is not None:
            s_int = int(float(s))
            return _get_risk_emoji(s_int)
    except Exception:
        pass

    # Fallback to level-based logic
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

# ---- domain coolness flags ----
_WAYBACK_SUMMARY = (os.getenv("WAYBACK_SUMMARY", "1") not in ("0","false","False",""))
_WAYBACK_TIMEOUT_S = float(os.getenv("WAYBACK_TIMEOUT_S", "3.5"))
_wb_cache: Dict[str, Any] = {}

_RDAP_SHOW_NS = (os.getenv("RDAP_SHOW_NS", "1") not in ("0","false","False",""))
_RDAP_DNSSEC_CHECK = (os.getenv("RDAP_DNSSEC_CHECK", "1") not in ("0","false","False",""))
_RDAP_SHOW_ABUSE = (os.getenv("RDAP_SHOW_ABUSE", "1") not in ("0","false","False",""))
_RDAP_STATUS_CASE = os.getenv("RDAP_STATUS_CASE", "title")   # "title" | "lower" | "raw"

_WEB_HEAD_CHECK = (os.getenv("WEB_HEAD_CHECK", "1") not in ("0","false","False",""))
_WEB_TIMEOUT_S = float(os.getenv("WEB_TIMEOUT_S", "4.0"))
_WEB_SHOW_HSTS = (os.getenv("WEB_SHOW_HSTS", "1") not in ("0","false","False",""))
_WEB_SHOW_ROBOTS = (os.getenv("WEB_SHOW_ROBOTS", "0") not in ("0","false","False",""))
_WEB_REDIRECTS_COMPACT = (os.getenv("WEB_REDIRECTS_COMPACT", "1") not in ("0","false","False",""))

_DNS_DMARC_CHECK = (os.getenv("DNS_DMARC_CHECK", "1") not in ("0","false","False",""))
_DNS_SPF_CHECK = (os.getenv("DNS_SPF_CHECK", "1") not in ("0","false","False",""))
_DOH_URL = os.getenv("DOH_URL", "https://dns.google/resolve")

_DETAILS_BADGES = (os.getenv("DETAILS_BADGES", "1") not in ("0","false","False",""))
_RISK_DOMAIN_WEIGHT = int(os.getenv("RISK_DOMAIN_WEIGHT", "3"))  # cap magnitude

REGISTRAR_URL_TRIM = (os.getenv("REGISTRAR_URL_TRIM", "1") not in ("0","false","False",""))
NAMESERVERS_LIMIT = int(os.getenv("NAMESERVERS_LIMIT", "2"))
HSTS_SHOW_MAXAGE_ONLY = (os.getenv("HSTS_SHOW_MAXAGE_ONLY", "1") not in ("0","false","False",""))
RDAP_DNSSEC_SHOW_UNSIGNED = (os.getenv("RDAP_DNSSEC_SHOW_UNSIGNED", "0") not in ("0","false","False",""))
BADGE_WAYBACK = (os.getenv("BADGE_WAYBACK", "1") not in ("0","false","False",""))
DOMAIN_EMOJI_BAR = (os.getenv("DOMAIN_EMOJI_BAR", "1") not in ("0","false","False",""))
RENDERER_BUILD_TAG = os.getenv("RENDERER_BUILD_TAG", "v9-stable")

# Simple in-process TTL caches for network checks
_CACHE_TTL = int(os.getenv("WEB_CACHE_TTL", "1800"))
_rdap_cache: Dict[str, Any] = {}
_web_cache: Dict[str, Any] = {}
_dns_cache: Dict[str, Any] = {}

def _status_case(s: str) -> str:
    t = _human_status(s)  # already splits/case lowers
    if _RDAP_STATUS_CASE == "title":
        return " ".join(w.capitalize() for w in t.split())
    elif _RDAP_STATUS_CASE == "lower":
        return t
    return s  # raw

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

    info: Dict[str, Any] = {"https_enforced": None, "redirects": [], "server": None, "x_powered_by": None, "hsts": None, "robots": None}
    try:
        r = _http_head_or_get(f"http://{domain}", allow_redirects=True)
        final_url = r.url if r is not None else None
        if r is not None:
            chain = [h.url for h in r.history] + ([r.url] if r.url else [])
            compact = []
            for u in chain[:4]:
                try:
                    from urllib.parse import urlparse
                    pu = urlparse(u)
                    compact.append(f"{pu.scheme}://{pu.netloc}")
                except Exception:
                    compact.append(u)
            info["redirects"] = compact
            info["https_enforced"] = bool(final_url and final_url.startswith("https://"))
        r2 = _http_head_or_get(f"https://{domain}", allow_redirects=True)
        if r2 is not None:
            info["server"] = r2.headers.get("Server")
            info["x_powered_by"] = r2.headers.get("X-Powered-By")
            if _WEB_SHOW_HSTS:
                hsts = r2.headers.get("Strict-Transport-Security")
                if hsts:
                    info["hsts"] = hsts
        if _WEB_SHOW_ROBOTS:
            try:
                r3 = _rq.get(f"https://{domain}/robots.txt", timeout=_WEB_TIMEOUT_S, allow_redirects=True)
                info["robots"] = (r3.status_code == 200, len(r3.text) if hasattr(r3, "text") else None)
            except Exception:
                info["robots"] = (False, None)
    except Exception:
        pass
    return _cache_put(_web_cache, key, info)

def _tls_probe(domain: str) -> Dict[str, Any]:
    # Direct TLS handshake to read certificate expiry; quick with timeouts.
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
        # site without TLS or blocked
        return {'ok': None, 'expires': None}


def _doh_txt(name: str):
    key = f"dns:{name}"
    cached = _cache_get(_dns_cache, key)
    if cached is not None: return cached
    out = []
    try:
        r = _rq.get(_DOH_URL, params={"name": name, "type": "TXT"}, timeout=_WEB_TIMEOUT_S)
        if r.ok:
            j = r.json()
            for ans in j.get("Answer", []) or []:
                data = ans.get("data")
                if not data: continue
                txt = data.strip('"').replace('" "', '')
                out.append(txt)
    except Exception:
        pass
    return _cache_put(_dns_cache, key, out)

def _check_dmarc(domain: str):
    if not _DNS_DMARC_CHECK: return None
    try:
        txts = _doh_txt(f"_dmarc.{domain}")
        policy = None
        for t in txts:
            if "v=DMARC1" in t:
                m = _re.search(r"\bp=([a-zA-Z]+)", t)
                if m:
                    policy = m.group(1).lower()
                    break
        return policy or "none"
    except Exception:
        return None

def _check_spf(domain: str):
    if not _DNS_SPF_CHECK: return None
    try:
        txts = _doh_txt(domain)
        for t in txts:
            if t.lower().startswith("v=spf1"):
                return True
        return False
    except Exception:
        return None

def _rdap_extract_extras(rdap: Dict[str, Any]):
    extras = {"registrar_url": None, "nameservers": [], "dnssec": None, "abuse": None}
    try:
        for link in (rdap.get("links") or []):
            rel = link.get("rel")
            href = link.get("href")
            if isinstance(href, str) and href.startswith("http"):
                if rel in ("related", "self"):
                    extras["registrar_url"] = href
                    break
        for ns in (rdap.get("nameservers") or [])[:3]:
            n = ns.get("ldhName") or ns.get("objectClassName")
            if n: extras["nameservers"].append(n.lower())
        sd = rdap.get("secureDNS") or {}
        if isinstance(sd, dict):
            if sd.get("delegationSigned") or sd.get("dsData"):
                extras["dnssec"] = "signed"
            else:
                extras["dnssec"] = "unsigned"
        abuse_email = None; abuse_phone = None
        for ent in (rdap.get("entities") or []):
            roles = [str(x).lower() for x in (ent.get("roles") or [])]
            if any("abuse" in r for r in roles):
                vcard = ent.get("vcardArray")
                try:
                    for item in (vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []):
                        if item and item[0] == "email" and len(item) > 3:
                            abuse_email = item[3]
                        if item and item[0] == "tel" and len(item) > 3:
                            abuse_phone = item[3]
                except Exception:
                    pass
        if abuse_email or abuse_phone:
            extras["abuse"] = (abuse_email, abuse_phone)
    except Exception:
        pass
    return extras

def _domain_badges(domain: str, rdap_extras, web, dmarc, spf):
    badges = []
    if web.get("https_enforced") is True: badges.append("HTTPS enforced")
    if web.get("hsts"): badges.append("HSTS")
    if rdap_extras.get("dnssec") == "signed": badges.append("DNSSEC")
    if dmarc in ("reject", "quarantine"): badges.append(f"DMARC {dmarc}")
    if spf is True: badges.append("SPF present")
    return badges[:6]

def _domain_subscore(rdap_extras, web, dmarc, spf):
    s = 0
    if web.get("https_enforced"): s += 1
    if web.get("hsts"): s += 1
    if rdap_extras.get("dnssec") == "signed": s += 1
    if dmarc == "reject": s += 1
    elif dmarc == "none": s -= 1
    if not web.get("https_enforced") and not web.get("hsts"): s -= 1
    if spf is True: s += 0
    # cap
    if s > _RISK_DOMAIN_WEIGHT: s = _RISK_DOMAIN_WEIGHT
    if s < -_RISK_DOMAIN_WEIGHT: s = -_RISK_DOMAIN_WEIGHT
    return s

# ---- renderers ----

def _resolve_domain(_rd: dict, market: dict, ctx: dict) -> str | None:
    """Find a domain to probe, from RDAP, ctx, or market links.
    Returns bare hostname like "pepe.vip" without scheme/path.
    """
    def _host_from_url(u: str):
        try:
            from urllib.parse import urlparse
            p = urlparse(u.strip())
            host = p.netloc or p.path  # tolerate "example.com" without scheme
            host = host.strip().lstrip("*.").split("/")[0]
            # remove leading "www."
            if host.lower().startswith("www."):
                host = host[4:]
            return host or None
        except Exception:
            return None
    # 1) explicit ctx
    dom = None
    try:
        cdom = ctx.get("domain") if isinstance(ctx, dict) else None
        if isinstance(cdom, str) and cdom:
            dom = _host_from_url(cdom) or cdom
    except Exception:
        pass
    # 2) market.links.site
    if not dom and isinstance(market, dict):
        try:
            site = ((market.get("links") or {}).get("site")) or market.get("site")
            if isinstance(site, str):
                dom = _host_from_url(site) or dom
        except Exception:
            pass
    # 3) common RDAP keys
    if not dom and isinstance(_rd, dict):
        for k in ("ldhName","unicodeName","domain","name","handle"):
            v = _rd.get(k)
            if isinstance(v, str) and v:
                candidate = v.strip().lstrip("*.")
                if "." in candidate and "/" not in candidate and " " not in candidate:
                    dom = candidate
                    break
    # 4) brute-force scan RDAP values for something that looks like a domain
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
            # fl=timestamp => rows are [["timestamp"], ["YYYYMMDDhhmmss"]]
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

def _render_details_impl(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
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
                if _rd.get("registrar"): _rd_lines.append(f"• Registrar: {_fmt_registrar(_rd['registrar'])}")
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
                            _rd_lines.append("• Status: " + ", ".join(_status_case(x) for x in _st))
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


    # Helper: pretty registrar name (Website block only)
    def _fmt_registrar__INNER_SHOULD_NOT_EXIST(val):
        s = (val or "").strip()
        if not s or s in ("—","n/a","N/A","NA"):
            return "n/a"
        import re as _re
        s = _re.sub(r"\s+", " ", s.replace(",", ", "))
        base = s.title()
        base = _re.sub(r"\bInc\b\.?", "Inc.", base)
        base = _re.sub(r"\bLlc\b\.?", "LLC", base)
        base = _re.sub(r"\bLtd\b\.?", "Ltd.", base)
        base = _re.sub(r"\bGmbh\b", "GmbH", base)
        base = _re.sub(r"\bAg\b", "AG", base)
        base = _re.sub(r"\bNv\b", "NV", base)
        base = _re.sub(r"\bBv\b", "BV", base)
        base = _re.sub(r"\bSa\b", "S.A.", base)
        base = _re.sub(r"\bSpa\b", "S.p.A.", base)
        base = _re.sub(r"(?i)Namecheap", "Namecheap", base)
        base = _re.sub(r"\s+,", ",", base)
        base = _re.sub(r",\s*", ", ", base)
        return base.strip()
    # Website intel (robust; tolerate empty/missing ctx keys) — FIXED INDENT
    web = (ctx or {}).get("webintel") or {"whois": {}, "ssl": {}, "wayback": {}}
    who = (web.get("whois") or {}) if isinstance(web, dict) else {}
    ssl = (web.get("ssl") or {}) if isinstance(web, dict) else {}
    way = (web.get("wayback") or {}) if isinstance(web, dict) else {}

    # Also accept flattened keys from server (if any)
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

    # Fallback WHOIS from market['domain'] with multiple common key variants
    def _pick(*vals):
        for v in vals:
            if v not in (None, "", "n/a", "N/A", "—"):
                return v
        return None

    dom_block = (market or {}).get("domain") or {}
    who_created = _pick(
        who.get("created"),
        dom_block.get("created"), dom_block.get("creationDate"), dom_block.get("createdAt"),
        dom_block.get("registered"), dom_block.get("registeredAt"),
        (ctx or {}).get("whois", {}).get("created"),
    )
    who_registrar = _pick(
        who.get("registrar"),
        dom_block.get("registrar"), dom_block.get("registrarName"),
        dom_block.get("registrar_url"), dom_block.get("registrarUrl"),
        (ctx or {}).get("whois", {}).get("registrar"),
    )

    # If still missing, reuse RDAP result from above (if present in this function scope)
    try:
        _rd_local = locals().get("_rd")
        if isinstance(_rd_local, dict):
            if not who_created:   who_created = _rd_local.get("created")
            if not who_registrar: who_registrar = _rd_local.get("registrar")
    except Exception:
        pass

    if who_created or who_registrar:
        who["created"] = who_created
        who["registrar"] = who_registrar
        web["whois"] = who

        # Active probes if data is missing
    try:
        _rd_local = locals().get('_rd')
    except Exception:
        _rd_local = None
    _domain_to_probe = _resolve_domain(_rd_local or {}, market, ctx)
    if _domain_to_probe:
        # SSL probe (TLS handshake) if missing
        if (ssl.get('ok') is None) or (not ssl.get('expires')):
            _tls = _tls_probe(_domain_to_probe)
            if ssl.get('ok') is None and (_tls.get('ok') is not None):
                ssl['ok'] = _tls['ok']
            if (not ssl.get('expires')) and _tls.get('expires'):
                ssl['expires'] = _tls['expires']
        # TLS WWW fallback
        if _domain_to_probe and (ssl.get('ok') is None or not ssl.get('expires')):
            _tls2 = _tls_probe('www.' + _domain_to_probe)
            if ssl.get('ok') is None and (_tls2.get('ok') is not None):
                ssl['ok'] = _tls2['ok']
            if (not ssl.get('expires')) and _tls2.get('expires'):
                ssl['expires'] = _tls2['expires']
        # HTTP(S) fallback: if TLS failed but HTTPS is enforced, consider SSL ok=True
        if _domain_to_probe and (ssl.get('ok') is None):
            _wp = _web_probe(_domain_to_probe)
            if isinstance(_wp, dict) and _wp.get('https_enforced') is True:
                ssl['ok'] = True
        # Wayback probe if missing
        if not way.get('first'):
            _wb = _wayback_summary(_domain_to_probe)
            if isinstance(_wb, dict) and _wb.get('first'):
                way['first'] = _wb['first']
            # Wayback WWW fallback
            if not way.get('first'):
                _wb2 = _wayback_summary('www.' + _domain_to_probe)
                if isinstance(_wb2, dict) and _wb2.get('first'):
                    way['first'] = _wb2['first']

        _rd_country = None
        try:
            _rd_local = locals().get("_rd")
            if isinstance(_rd_local, dict):
                _rd_country = _rd_local.get("country") or None
        except Exception:
            _rd_country = None
        try:
            _ci = infer_country(web)
        except Exception:
            _ci = None
        country_line = (None if _rd_country else (country_label(_ci) if _ci else None))
    w_lines = ["*Website intel*"]
    if country_line:
        w_lines.append(f"• {country_line}")
    w_lines.append(f"• WHOIS: created {who.get('created') or 'n/a'}, registrar {who.get('registrar') or 'n/a'}")
    ok_val = ssl.get('ok')
    ok_disp = (ok_val if ok_val is not None else 'n/a')
    w_lines.append(f"• SSL: ok={ok_disp}, expires {ssl.get('expires') or 'n/a'}")
    w_lines.append(f"• Wayback first: {way.get('first') or 'n/a'}")
    parts.append("\n".join(w_lines))





    return "\n".join(parts)



def render_why(verdict, market: Dict[str, Any], lang: str = "en") -> str:
    # Take up to 3 key reasons, deduplicated, with normalization (age/delta wording).
    reasons: List[str] = []
    try:
        reasons = list(getattr(verdict, "reasons", []) or [])
    except Exception:
        reasons = list((verdict or {}).get("reasons") or [])
    seen = set()
    uniq: List[str] = []
    for r in reasons:
        if not r: 
            continue
        if r in seen: 
            continue
        seen.add(r)
        uniq.append(_normalize_reason_text(r))
        if len(uniq) >= 3:
            break
    if not uniq:
        return "*Why?*\n• No specific risk factors detected"
    header = "*Why?*"
    lines = [f"• {r}" for r in uniq]
    return "\n".join([header] + lines)
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
        if isinstance(age,(int,float)) and age >= 7:                 add_pos(_age_bucket_label(age), 2)
        if isinstance(ch24,(int,float)):
            _lbl = _delta24h_positive_label(ch24)
            if _lbl: add_pos(_lbl, 1)
    except Exception:
        pass

    try:
        if liq is None: add_risk("Liquidity unknown", 2)
        elif isinstance(liq,(int,float)) and liq < t["LIQ_LOW"]: add_risk(f"Low liquidity (${liq:,.0f})", 3)
        if vol is None: add_risk("24h volume unknown", 1)
        elif isinstance(vol,(int,float)) and vol < t["VOL_THIN"]: add_risk(f"Thin 24h volume (${vol:,.0f})", 2)
        if isinstance(ch24,(int,float)):
            _abs = abs(ch24)
            if _abs >= 25:
                add_risk(f"High daily volatility (|Δ24h| ≈ {_abs:.0f}%)", 3)
            elif _abs >= 12:
                add_risk(f"Elevated daily volatility (|Δ24h| ≈ {_abs:.0f}%)", 2)
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


def render_lp(info: dict, lang: str = "en") -> str:
    """
    LP-lite v2 renderer (compact, serious, accurate).
    Back-compat: accepts the old "info" dict; if it contains chain + LP token, we compute on-chain.
    Otherwise, we will format whatever is present in "info" and mark unknowns.
    """
    p = info or {}
    chain = (p.get("chain") or p.get("network") or p.get("chainId") or "eth")
    lp_token = (p.get("lpAddress") or p.get("lpToken") or p.get("address") or p.get("token") or "—")
    def _looks_addr(a: str) -> bool:
        try:
            return isinstance(a, str) and a.startswith("0x") and len(a) >= 10
        except Exception:
            return False
    data = None
    if _looks_addr(lp_token):
        try:
            data = check_lp_lock_v2(chain, lp_token)
        except Exception:
            data = None
    lines = []
    def _cap(s: str) -> str:
        s = (s or "").lower()
        return {"eth":"Ethereum","bsc":"BSC","polygon":"Polygon"}.get(s, s.capitalize() if s else "—")
    lines.append(f"*LP lock (lite) — {_cap(chain)}*")
    status_map = {"burned":"burned","locked-partial":"locked-partial","v3-nft":"v3-NFT","unknown":"unknown"}
    if data and isinstance(data, dict):
        status = status_map.get(str(data.get("status")),"unknown")
        lines.append(f"• Status: {status}")
        if status == "v3-NFT":
            lines.append("• Burned: n/a (v3/NFT)")
            lines.append("• Locked: n/a (v3/NFT)")
        else:
            burned = data.get("burnedPct")
            locked = data.get("lockedPct")
            def _fmt_pct(x):
                try:
                    return f"{float(x):.2f}%"
                except Exception:
                    return "—"
            lines.append(f"• Burned: {_fmt_pct(burned)}  (0xdead + 0x0)")
            lk_by = data.get("lockedBy") or "—"
            lines.append(f"• Locked: {_fmt_pct(locked)} via {lk_by}")
        lp_disp = data.get("lpToken") or lp_token
        lines.append(f"• LP token: `{lp_disp}`")
        links = []
        if data.get("holdersUrl"): links.append("Holders (Etherscan)")
        if data.get("uncxUrl"): links.append("UNCX")
        if data.get("teamfinanceUrl"): links.append("TeamFinance")
        if links:
            lines.append("• Links: " + " | ".join(links))
        ds = data.get("dataSource") or "—"
        lines.append(f"• Data source: {ds}")
        return "\\n".join(lines)
    # Fallback legacy formatting without compute
    burned_pct = p.get("burnedPct")
    locked_pct = p.get("lockedPct")
    def _fmt_pct2(v):
        try: return f"{float(v):.2f}%"
        except Exception: return "—"
    status = "unknown"
    try:
        if burned_pct is not None and float(burned_pct) >= 95.0:
            status = "burned"
        elif locked_pct is not None and float(locked_pct) > 0:
            status = "locked-partial"
    except Exception:
        pass
    lines.append(f"• Status: {status}")
    if isinstance(burned_pct,(int,float)) or (isinstance(burned_pct,str) and burned_pct.replace('.','',1).isdigit()):
        lines.append(f"• Burned: {_fmt_pct2(burned_pct)}  (0xdead + 0x0)")
    else:
        lines.append("• Burned: —")
    if isinstance(locked_pct,(int,float)) or (isinstance(locked_pct,str) and locked_pct.replace('.','',1).isdigit()):
        lines.append(f"• Locked: {_fmt_pct2(locked_pct)} via —")
    else:
        lines.append("• Locked: —")
    lines.append(f"• LP token: `{lp_token}`")
    lines.append("• Links: UNCX | TeamFinance")
    lines.append("• Data source: —")
    return "\\n".join(lines)
def render_details(verdict, market: Dict[str, Any], ctx: Dict[str, Any], lang: str = "en") -> str:
    try:
        print("[MDX v2.6] render_details() called", flush=True)
        return _render_details_impl(verdict, market, ctx, lang)
    except Exception as _e:
        import traceback as _tb
        try:
            _tb.print_exc()
        except Exception:
            pass
        try:
            pair = (market or {}).get("pair") or "—"
            asof = (market or {}).get("asof") or "n/a"
        except Exception:
            pair, asof = "—", "n/a"
        print(f"[MDX v2.6] render_details FAILSAFE: {type(_e).__name__}: {_e}", flush=True)
        try:
            print(f"[MDX v2.6] ctx: pair={pair}, asof={asof}", flush=True)
        except Exception:
            pass
        try:
            _as = asof
            if isinstance(_as, (int,float)):
                ts = int(_as)
                # detect ms
                if ts > 10**12:
                    ts = ts // 1000
                asof_fmt = __import__("datetime").datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")
            else:
                asof_fmt = str(_as)
        except Exception:
            asof_fmt = str(asof)
        return f"*Details temporarily unavailable*\n• Pair: {pair}\n• As of: {asof_fmt}"


def render_lp_lite_v2(chain: str, lp_token: str) -> str:
    """Direct LPv2 render when you already know chain and LP token."""
    try:
        data = check_lp_lock_v2(chain, lp_token)
    except Exception:
        data = {"status":"unknown","burnedPct":None,"lockedPct":None,"lpToken":lp_token,
                "holdersUrl":"","uncxUrl":"https://app.unicrypt.network/","teamfinanceUrl":"https://app.team.finance/",
                "dataSource":"—"}
    # Reuse the main formatter via the info→compute path
    info = {"chain": chain, "lpAddress": lp_token}
    return render_lp(info)

