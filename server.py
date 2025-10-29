import hashlib
def _is_provisional_text(s: str | None) -> bool:
    if not isinstance(s, str): 
        return True
    ss = s.strip().lower()
    return (
        ss.startswith("*details will appear in a moment") or
        ss.startswith("*why?*") and "computing…" in ss or
        ss.startswith("*why++*") and "computing…" in ss or
        ss == "lp lock: pending" or
        ss == "lp lock: n/a" or
        ss == "n/a"
    )

import os
import traceback
try:
    import webintel_lite
except Exception:
    try:
        import webintel as webintel_lite
    except Exception:
        class _WebintelStub:
            @staticmethod
            def build_website_intel(market, known_domains):
                return ""
        webintel_lite = _WebintelStub()

import hmac
import os, json, re, traceback, requests
from onchain_formatter import format_onchain_text

try:
    from webintel import analyze_website, derive_domain
except Exception:
    # Fallback: minimal inline versions if import fails
    import requests as _rq
    from urllib.parse import urlparse as _urlparse

    def derive_domain(url):
        try:
            if not url:
                return None
            p = _urlparse(str(url).strip())
            host = (p.netloc or p.path).strip().lstrip("*.").split("/")[0]
            if host.lower().startswith("www."):
                host = host[4:]
            return host or None
        except Exception:
            return None

    def analyze_website(url):
        host = derive_domain(url)
        out = {"whois": {"created": None, "registrar": None},
               "ssl": {"ok": None, "expires": None, "issuer": None},
               "wayback": {"first": None}}
        if not host:
            return out
        try:
            r = _rq.get(f"https://rdap.org/domain/{host}", timeout=2.5)
            if r.ok:
                j = r.json()
                for ev in (j.get("events") or []):
                    act = str(ev.get("eventAction") or "").lower()
                    if act in ("registration","registered","creation"):
                        d = (ev.get("eventDate") or "")[:10]
                        if d:
                            out["whois"]["created"] = d
                            break
                for ent in (j.get("entities") or []):
                    roles = [str(x).lower() for x in (ent.get("roles") or [])]
                    if any("registrar" in rr for rr in roles):
                        try:
                            v = ent.get("vcardArray") or []
                            items = v[1] if isinstance(v, list) and len(v) > 1 else []
                            for it in items:
                                if it and it[0] == "fn" and len(it) > 3:
                                    out["whois"]["registrar"] = it[3]
                                    raise StopIteration
                        except StopIteration:
                            break
                        except Exception:
                            pass
        except Exception:
            pass

        # If some keys still missing, try compact _rdap_more
        try:
            more = _rdap_more(domain)
            for k in ("expires","registrarIANA","status","rdap_flags","country"):
                if more.get(k) and (who.get(k) in (None, "—")):
                    who[k] = more[k]
        except Exception:
            pass
        try:
            hr = _rq.head(f"https://{host}", timeout=2.0, allow_redirects=True)
            out["ssl"]["ok"] = bool(hr.ok) if hr is not None else None
        except Exception:
            pass
        try:
            rwb = _rq.get("https://web.archive.org/cdx/search/cdx",
                          params={"url": host, "output": "json", "fl": "timestamp",
                                  "filter": "statuscode:200", "limit": "1",
                                  "from":"19960101","to":"99991231","sort":"ascending"},
                          timeout=2.5)
            if rwb.ok:
                j = rwb.json()
                if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and j[1]:
                    ts = j[1][0]
                    out["wayback"]["first"] = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
        except Exception:
            pass
        return out

import time
import renderers_mdx as _mdx
import sys
sys.stderr.write(f"[BOOT] Using renderers module: {_mdx.__file__} | tag={getattr(_mdx, 'RENDERER_BUILD_TAG', None)}\n")

# --- Website intel helper (whois / ssl / wayback) ---
import socket, ssl as _ssl, datetime as _dt

_WE_TIMEOUT = float(os.getenv("WEBINTEL_TIMEOUT_S", "2.0"))

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

def _whois_info(host: str):
    try:
        import whois
        w = whois.whois(host)
        reg = w.registrar if getattr(w, "registrar", None) else None
        cd  = w.creation_date if getattr(w, "creation_date", None) else None
        # some tlds return list
        if isinstance(cd, (list, tuple)) and cd:
            cd = cd[0]
        if isinstance(cd, (_dt.date, _dt.datetime)):
            cd = cd.strftime("%Y-%m-%d")
        return {"created": cd, "registrar": reg}
    except Exception:
        return {"created": None, "registrar": None}

def _ssl_info(host: str):
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_WE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        exp = None
        if cert and "notAfter" in cert:
            try:
                import datetime as dt
                # already imported as _dt above, but keep robust
                exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
            except Exception:
                exp = cert.get("notAfter")
        return {"ok": True, "expires": exp, "issuer": None}
    except Exception:
        return {"ok": None, "expires": None, "issuer": None}



# --- Website intel helpers (RDAP WHOIS fallback, TLS + HTTP HEAD, Wayback) ---
import socket, ssl as _ssl, datetime as _dt, os as _os
import requests as _rq

_WE_TIMEOUT = float(_os.getenv("WEBINTEL_TIMEOUT_S", "2.5"))
_WE_HEAD_TIMEOUT = float(_os.getenv("WEBINTEL_HEAD_TIMEOUT_S", "2.0"))

def _rdap_whois(host: str):
    try:
        r = _rq.get(f"https://rdap.org/domain/{host}", timeout=_WE_TIMEOUT)
        if not r.ok:
            return {"created": None, "registrar": None}
        j = r.json()
        created = None
        registrar = None
        for ev in (j.get("events") or []):
            if isinstance(ev, dict) and str(ev.get("eventAction","")).lower().startswith("registration"):
                d = ev.get("eventDate")
                if isinstance(d, str) and len(d) >= 10:
                    created = d[:10]
                    break
        for ent in (j.get("entities") or []):
            roles = ent.get("roles") or []
            if any(str(r).lower() == "registrar" for r in roles):
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            registrar = item[3]
                            break
                if registrar:
                    break
        return {"created": created, "registrar": registrar}
    except Exception:
        return {"created": None, "registrar": None}

# (duplicate _ssl_info removed)

def analyze_website(site_url: str | None):
    host = _host_from_url(site_url) if site_url else None
    if not host:
        return {"whois": {"created": None, "registrar": None},
                "ssl": {"ok": None, "expires": None, "issuer": None},
                "wayback": {"first": None}}
    who = _whois_info(host)
    # RDAP fallback to fill missing fields
    if not (who.get("created") and who.get("registrar")):
        wr = _rdap_whois(host)
        who = {"created": who.get("created") or wr.get("created"),
               "registrar": who.get("registrar") or wr.get("registrar")}
    ssl = _ssl_info(host)
    wb  = _wayback_first(host)
    return {"whois": who, "ssl": ssl, "wayback": {"first": wb}, "host": host, "wayback_url": f"https://web.archive.org/web/*/{host}"}

from flask import Flask, request, jsonify

from limits import can_scan, register_scan

# --- Owner-bypass for limits (OMEGA-713K) ---
try:
    _can_scan_orig = can_scan  # keep original
except Exception:
    _can_scan_orig = None

def _owner_ids():
    ids = set()
    # Accept ADMIN_CHAT_ID / OWNER_CHAT_ID (single) and ALLOWED_CHAT_IDS (comma-separated)
    for name in ("ADMIN_CHAT_ID", "OWNER_CHAT_ID", "ALLOWED_CHAT_IDS"):
        raw = (os.getenv(name) or "").strip()
        if not raw:
            continue
        for tok in (t.strip() for t in raw.split(",") if t.strip()):
            try:
                ids.add(int(tok))
            except Exception:
                pass
    return ids

def can_scan(chat_id: int):
    """If chat_id belongs to owner list -> allow as Pro (owner), else delegate."""
    try:
        if int(chat_id) in _owner_ids():
            return True, "Pro (owner)"
    except Exception:
        pass
    if _can_scan_orig:
        return _can_scan_orig(chat_id)
    return False, "Free"
# --- /Owner-bypass ---

from state import store_bundle, load_bundle
from buttons import build_keyboard
from cache import cache_get, cache_set
try:
    from dex_client import fetch_market
except Exception as _e:
    try:
        import dex_client as _dex
        fetch_market = getattr(_dex, 'fetch_market')
    except Exception as _e2:
        _err = str(_e2)
        def fetch_market(*args, **kwargs):
            return {'ok': False, 'error': 'market_fetch_unavailable: ' + _err, 'sources': [], 'links': {}}

from risk_engine import compute_verdict


# --- Soft telemetry (LP/ONCHAIN), enable with env LOG_LP=1 ---
try:
    LOG_LP = int(os.getenv('LOG_LP', '0'))
except Exception:
    LOG_LP = 0
def _lpdbg(event: str, **fields):
    if not LOG_LP:
        return
    try:
        kv = ' '.join(f"{k}={repr(v)}" for k, v in fields.items() if v is not None)
        print(f"[LPDBG] {event} {kv}")
    except Exception:
        pass
import onchain_inspector

# === LP-lite helpers for inspector → renderer ===
def _short_addr(x):
    try:
        s = str(x)
        return s[:6] + '…' + s[-4:] if len(s) > 12 else s
    except Exception:
        return str(x)

def _norm_chain_short(x: str) -> str:
    v = (x or '').strip().lower()
    if v.isdigit():
        v = {'1':'eth','56':'bsc','137':'polygon'}.get(v, v)
    if v in ('matic','pol','poly'):
        v = 'polygon'
    return v or 'eth'

def _lp_info_from_inspector(oc: dict, chain_short: str, pair_addr: str):
    try:
        oc = oc or {}
        chain = _norm_chain_short(chain_short)
        cand = None
        for key in ('lp', 'lpLite', 'lp_lite', 'security', 'onchain', 'data'):
            v = oc.get(key) if isinstance(oc, dict) else None
            if isinstance(v, dict) and any(k in v for k in ('burned_pct','burnedPct','lockers','lockedPct')):
                cand = v; break
        if cand is None:
            cand = oc if isinstance(oc, dict) else {}
        burned = cand.get('burnedPct', cand.get('burned_pct'))
        lockers = cand.get('lockers') if isinstance(cand.get('lockers'), dict) else {}
        locked_pct = cand.get('lockedPct')
        if locked_pct is None and lockers:
            try:
                locked_pct = sum(float(x) for x in lockers.values() if x is not None)
            except Exception:
                locked_pct = None
        locked_by = cand.get('lockedBy')
        if not locked_by:
            names = [k for k,v in lockers.items() if (v or 0) > 0]
            if names:
                locked_by = '+'.join(sorted(set(names)))
        return {
            'provider': 'inspector-lp-lite',
            'chain': chain,
            'lpAddress': pair_addr,
            'data': {
                'burnedPct': burned,
                'lockedPct': locked_pct,
                'lockedBy': locked_by or '—',
            },
        }
    except Exception:
        return {'provider':'inspector-lp-lite','chain':_norm_chain_short(chain_short),'lpAddress':pair_addr,'data':{}}


from openai import OpenAI
__whypp_client = None
def _get_ai_client():
    global __whypp_client
    if __whypp_client is None:
        __whypp_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return __whypp_client

from renderers_mdx import render_quick, render_details, render_why, render_whypp, render_lp
from pair_resolver import resolve_pair
try:
    from lp_lite_enhanced import check_lp_lock_v2  # prefer enhanced helper
except Exception:
    try:
        from lp_lite import check_lp_lock_v2
    except Exception:
        def check_lp_lock_v2(chain, lp_addr):
            return {"provider": "lite-burn-check", "lpAddress": lp_addr or "—", "until": "—"}

try:
    from onchain_inspector import inspect_token
except Exception:
    inspect_token = None

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
WEBHOOK_PATH = f"/webhook/{BOT_WEBHOOK_SECRET}" if BOT_WEBHOOK_SECRET else "/webhook/secret-not-set"
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en")


def _rdap_more(domain: str):
    """Lightweight RDAP fields extractor (expires, registrar IANA ID, status list, country)."""
    try:
        import requests as _rq
        r = _rq.get(f"https://rdap.org/domain/{domain}", timeout=2.5)
        if not r.ok:
            return {}
        j = r.json() or {}
        out = {}
        # Expires from events
        try:
            for ev in (j.get("events") or []):
                act = str(ev.get("eventAction") or "").lower()
                if act in ("expiration","expiry","expire"):
                    d = ev.get("eventDate")
                    if isinstance(d, str) and len(d) >= 10:
                        out["expires"] = d[:10]
                        break
        except Exception:
            pass
        # Registrar IANA ID
        try:
            for ent in (j.get("entities") or []):
                roles = [str(x).lower() for x in (ent.get("roles") or [])]
                if any("registrar" in rr for rr in roles):
                    pids = ent.get("publicIds") or []
                    for pid in pids:
                        t = str(pid.get("type") or "").lower()
                        if "iana" in t and "registrar" in t:
                            out["registrarIANA"] = pid.get("identifier")
                            break
                    break
        except Exception:
            pass
        # Status list
        try:
            st = j.get("status")
            if isinstance(st, list) and st:
                out["status"] = ", ".join(str(x) for x in st if x)
        except Exception:
            pass
        # Country from registrant/admin/tech entity vCard 'adr'
        try:
            for ent in (j.get("entities") or []):
                roles = [str(x).lower() for x in (ent.get("roles") or [])]
                if any(rr in roles for rr in ("registrant","administrative","technical")):
                    v = ent.get("vcardArray") or []
                    items = v[1] if isinstance(v, list) and len(v) > 1 else []
                    for it in items:
                        # ADR structure: ["adr", params, "text", ["", "", street, city, region, code, country]]
                        if it and it[0] == "adr" and len(it) > 3 and isinstance(it[3], list) and it[3]:
                            country = it[3][-1]
                            if isinstance(country, str) and country.strip():
                                out["country"] = country.strip()
                                raise StopIteration
        except StopIteration:
            pass
        except Exception:
            pass
        # Flags
        flags = []
        if out.get("expires"): flags.append("has_expiry")
        if flags:
            out["rdap_flags"] = ", ".join(flags)
        return out
    except Exception:
        return {}
def _tls_expires_quick(domain: str):
    def _one(host):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            if cert and "notAfter" in cert:
                try:
                    return dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    # Fallback keep as string; try common ISO
                    try:
                        return dt.datetime.fromisoformat(cert["notAfter"][:19])
                    except Exception:
                        return None
        except Exception:
            return None
        return None
    # Try bare domain, then www.domain
    best = _one(domain)
    if best is None and not domain.lower().startswith("www."):
        best = _one("www." + domain)
    if isinstance(best, dt.datetime):
        return best.strftime("%Y-%m-%d")
    return None
    return None

def build_webintel_ctx(market: dict) -> dict:
    try:
        links = (market.get("links") or {})
    except Exception:
        links = {}
    try:
        site_url = links.get("site") or os.getenv("WEBINTEL_SITE_OVERRIDE")
    except Exception:
        site_url = os.getenv("WEBINTEL_SITE_OVERRIDE")
    # defaults
    web = {
        "whois": {"created": None, "registrar": None},
        "ssl": {"ok": None, "expires": None, "issuer": None},
        "wayback": {"first": None}
    }
    try:
        if site_url:
            web = analyze_website(site_url)
    except Exception:
        pass
    try:
        dom = derive_domain(site_url)
    except Exception:
        dom = None
    try:
        web = _enrich_webintel_fallback(dom, web)
    except Exception:
        pass
    return {"webintel": web, "domain": dom}


def _enrich_webintel_fallback(domain: str, web: dict) -> dict:
    try:
        import requests as _rq
    except Exception:
        return web or {}
    web = web or {}
    who = web.setdefault("whois", {"created": None, "registrar": None})
    ssl = web.setdefault("ssl", {"ok": None, "expires": None, "issuer": None})
    way = web.setdefault("wayback", {"first": None})
    if domain:
        # RDAP (extend fields)
        try:
            r = _rq.get(f"https://rdap.org/domain/{domain}", timeout=2.5)
            if r.ok:
                j = r.json()
                # created
                if (who.get("created") in (None, "—")):
                    for ev in (j.get("events") or []):
                        act = str(ev.get("eventAction") or "").lower()
                        if act in ("registration","registered","creation"):
                            d = (ev.get("eventDate") or "")[:10]
                            if d:
                                who["created"] = d
                                break
                # registrar name
                if (who.get("registrar") in (None, "—")):
                    for ent in (j.get("entities") or []):
                        roles = [str(x).lower() for x in (ent.get("roles") or [])]
                        if any("registrar" in rr for rr in roles):
                            try:
                                v = ent.get("vcardArray") or []
                                items = v[1] if isinstance(v, list) and len(v) > 1 else []
                                for it in items:
                                    if it and it[0] == "fn" and len(it) > 3:
                                        who["registrar"] = it[3]
                                        break
                            except Exception:
                                pass
                            break
                # IANA ID
                try:
                    for ent in (j.get("entities") or []):
                        roles = [str(x).lower() for x in (ent.get("roles") or [])]
                        if any("registrar" in rr for rr in roles):
                            for pid in (ent.get("publicIds") or []):
                                t = str(pid.get("type") or "").lower()
                                if "iana" in t and "registrar" in t:
                                    who["registrarIANA"] = pid.get("identifier")
                                    raise StopIteration
                except StopIteration:
                    pass
                except Exception:
                    pass
                # Expires
                try:
                    for ev in (j.get("events") or []):
                        act = str(ev.get("eventAction") or "").lower()
                        if act in ("expiration","expiry","expire"):
                            d = ev.get("eventDate")
                            if isinstance(d, str) and len(d) >= 10:
                                who["expires"] = d[:10]
                                break
                except Exception:
                    pass
                # Status
                try:
                    st = j.get("status")
                    if isinstance(st, list) and st:
                        who["status"] = ", ".join(str(x) for x in st if x)
                except Exception:
                    pass
                # RDAP flags
                try:
                    flags = []
                    if who.get("expires"): flags.append("has_expiry")
                    if flags:
                        who["rdap_flags"] = ", ".join(flags)
                except Exception:
                    pass
        except Exception:
            pass
        # SSL
        try:
            hr = _rq.head(f"https://{domain}", timeout=2.0, allow_redirects=True)
            if ssl.get("ok") in (None, "—"):
                ssl["ok"] = bool(hr.ok) if hr is not None else None
        except Exception:
            pass
        # TLS expiry fallback
        try:
            if not ssl.get("expires"):
                _exp = _tls_expires_quick(domain)
                if _exp:
                    ssl["expires"] = _exp
        except Exception:
            pass
        # Wayback
        try:
            rwb = _rq.get("https://web.archive.org/cdx/search/cdx",
                          params={"url": domain, "output":"json", "fl":"timestamp",
                                  "filter":"statuscode:200", "limit":"1",
                                  "from":"19960101","to":"99991231","sort":"ascending"},
                          timeout=2.5)
            if rwb.ok and (way.get("first") in (None, "—")):
                j = rwb.json()
                if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and j[1]:
                    ts = j[1][0]
                    way["first"] = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
        except Exception:
            pass
    return web

HELP_URL = os.getenv("HELP_URL", "https://metridex.com/help")
DEEP_REPORT_URL = os.getenv("DEEP_REPORT_URL", "https://metridex.com/upgrade/deep-report")
DAY_PASS_URL = os.getenv("DAY_PASS_URL", "https://metridex.com/upgrade/day-pass")
PRO_URL = os.getenv("PRO_URL", "https://metridex.com/upgrade/pro")
TEAMS_URL = os.getenv("TEAMS_URL", "https://metridex.com/upgrade/teams")
FREE_DAILY_SCANS = int(os.getenv("FREE_DAILY_SCANS", "2"))
HINT_CLICKABLE_LINKS = os.getenv("HINT_CLICKABLE_LINKS", "0") == "1"

CALLBACK_DEDUP_TTL_SEC = int(os.getenv("CALLBACK_DEDUP_TTL_SEC", "30"))

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

# === NOWPayments: lock low-ticket to Polygon (maticmainnet) ===================
import requests as _rq_np
from flask import redirect as _redirect

def _plan_defaults(plan: str):
    p = (plan or "").strip().lower()
    if p.startswith("deep"):
        return {"amount": 3, "label": os.getenv("CRYPTO_LABEL_DEEP") or "Deep report — $3", "days": 0}
    if p.startswith("day"):
        return {"amount": 9, "label": os.getenv("CRYPTO_LABEL_DAYPASS") or "Day Pass — $9", "days": 1}
    if p.startswith("team"):
        return {"amount": 99, "label": os.getenv("CRYPTO_LABEL_TEAMS") or "Teams — from $99", "days": 30}
    return {"amount": 29, "label": os.getenv("CRYPTO_LABEL_PRO") or "Pro — $29", "days": 30}

def _resolve_chat_id_from_query(args):
    for k in ("u","uid","chat","chat_id","tg","user","user_id"):
        v = args.get(k)
        if v is None:
            continue
        try:
            return int(str(v).strip())
        except Exception:
            pass
    return None

def _build_order_id(chat_id, plan):
    import uuid, time as _t
    return f"tg:{chat_id}:{plan}:{int(_t.time())}:{uuid.uuid4().hex[:8]}"

def _np_create_invoice_legacy(amount_usd: float, order_id: str, order_desc: str, success_url: str, cancel_url: str, ipn_url: str, plan_key: str):
    api_key = (os.getenv("NOWPAYMENTS_API_KEY") or "").strip()
    if not api_key:
        return {"ok": False, "error": "NOWPAYMENTS_API_KEY is not set"}

    plan_key = (plan_key or "").lower().strip()
    low_ticket = (plan_key.startswith("deep") or plan_key.startswith("day") or float(amount_usd) < 15.0)

    # Policy:
    #  - Low-ticket ($3/$9): floating rate + Polygon native coin to minimize min amount
    #  - High-ticket (>= $15): fixed rate ON by default, currency from env or fallback BSC native
    if low_ticket:
        is_fixed_rate = False
        pay_currency = "maticmainnet"   # Polygon native (MetaMask-friendly, low min)
    else:
        is_fixed_rate = True if os.getenv("NOWPAYMENTS_FIXED_RATE") is None else bool(int(os.getenv("NOWPAYMENTS_FIXED_RATE","1")))
        pay_currency = (os.getenv("NOWPAYMENTS_PAY_CURRENCY_HIGH") or os.getenv("NOWPAYMENTS_PAY_CURRENCY") or "bnbbsc").strip().lower()

    payload = {
        "price_amount": float(amount_usd),
        "price_currency": "usd",
        "order_id": order_id,
        "order_description": order_desc,
        "is_fixed_rate": is_fixed_rate,
        "is_fee_paid_by_user": bool(int(os.getenv("NOWPAYMENTS_FEE_PAID_BY_USER", "1"))),
        "ipn_callback_url": ipn_url,
        "pay_currency": pay_currency,
    }
    if success_url: payload["success_url"] = success_url
    if cancel_url:  payload["cancel_url"]  = cancel_url

    r = _rq_np.post("https://api.nowpayments.io/v1/invoice", json=payload, timeout=12, headers={"x-api-key": api_key})
    ct = r.headers.get("content-type","")
    j = r.json() if ct.startswith("application/json") else {"error": r.text}
    if r.ok and isinstance(j, dict) and (j.get("invoice_id") or j.get("id")):
        return {"ok": True, "json": j}
    return {"ok": False, "status": r.status_code, "json": j}

# Remove any previous definitions of this route to avoid duplicates
try:
    view_funcs = list(app.view_functions.keys())
    if "now_create_invoice" in view_funcs:
        # Flask doesn't support removing rules easily; we just redefine with a new function
        pass
except Exception:
    pass

@app.get("/api/now/invoice")
def now_create_invoice():
    plan_raw = request.args.get("plan","pro")
    p = _plan_defaults(plan_raw)
    amount = float(request.args.get("amount", p["amount"]))
    base = (os.getenv("PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")
    ipn_secret = (os.getenv("CRYPTO_WEBHOOK_SECRET") or "generic").strip()
    ipn_url = f"{base}/crypto_webhook/{ipn_secret}" if base else None
    success_url = os.getenv("NOWPAYMENTS_SUCCESS_URL", "") or (f"{base}/health" if base else None)
    cancel_url  = os.getenv("NOWPAYMENTS_CANCEL_URL",  "") or (f"{base}/health" if base else None)
    chat_id = _resolve_chat_id_from_query(request.args)
    order_id = _build_order_id(chat_id or "anon", (plan_raw or "pro"))
    desc = p["label"]
    res = _np_create_invoice_smart(amount, order_id, desc, success_url, cancel_url, ipn_url, plan_raw)
    if not res.get("ok"):
        return jsonify({"ok": False, "error": res}), 502
    j = res["json"]
    invoice_url = j.get("invoice_url") or ""
    return _redirect(invoice_url, code=302)
# === /NOWPayments: lock to Polygon ===========================================

# === NOWPayments integration (invoices + IPN) ================================
import requests as _rq_np
from flask import redirect as _redirect, Response as _Response

# Entitlements (simple JSON file) — minimal, non-invasive
_PRO_DB_PATH = os.getenv("PRO_USERS_DB_PATH", "./pro_users.json")

def _load_pro_db():
    try:
        with open(_PRO_DB_PATH, "r", encoding="utf-8") as f:
            j = json.load(f)
            return j if isinstance(j, dict) else {}
    except Exception:
        return {}

def _save_pro_db(db: dict):
    try:
        with open(_PRO_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db or {}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _grant_plan(chat_id: int, plan: str, days: int):
    db = _load_pro_db()
    now = int(time.time())
    # Store expiry as unix seconds
    cur = db.get(str(chat_id), {})
    exp_old = int(cur.get("expires", 0))
    exp_base = max(exp_old, now)
    expires = exp_base + days*24*3600
    db[str(chat_id)] = {"plan": plan, "granted_at": now, "expires": expires}
    _save_pro_db(db)
    return expires

def _plan_defaults(plan: str):
    plan = (plan or "").strip().lower()
    if plan in ("day","daypass","day-pass","pass"):
        return {"amount": 9, "label": os.getenv("CRYPTO_LABEL_DAYPASS") or "Day Pass — $9", "days": 1}
    if plan in ("deep","report","deep-report","deep_report"):
        return {"amount": 3, "label": os.getenv("CRYPTO_LABEL_DEEP") or "Deep report — $3", "days": 0}
    if plan in ("teams","team"):
        return {"amount": 99, "label": os.getenv("CRYPTO_LABEL_TEAMS") or "Teams — from $99", "days": 30}
    # default: pro
    return {"amount": 29, "label": os.getenv("CRYPTO_LABEL_PRO") or "Pro — $29", "days": 30}

def _resolve_chat_id_from_query(args):
    for k in ("u","uid","chat","chat_id","tg","user","user_id"):
        v = args.get(k)
        if v is None: continue
        try:
            return int(str(v).strip())
        except Exception:
            pass
    return None

def _build_order_id(chat_id, plan):
    ts = int(time.time())
    rand = uuid.uuid4().hex[:8]
    return f"tg:{chat_id}:{plan}:{ts}:{rand}"

def _now_invoice_url_from_base(base_link: str, invoice_id: str) -> str:
    base_link = (base_link or "").strip()
    if not base_link:
        return None
    # If base already includes ?iid= or endswith '=' — append; else assume it's a template needing invoice_id concatenation
    if "iid=" in base_link or base_link.endswith("="):
        return f"{base_link}{invoice_id}"
    # Otherwise, if it's a canonical invoice_url already, just return it
    return base_link

def _np_create_invoice_legacy(amount_usd: float, order_id: str, order_desc: str, success_url: str, cancel_url: str, ipn_url: str):
    api_key = (os.getenv("NOWPAYMENTS_API_KEY") or "").strip()
    if not api_key:
        return {"ok": False, "error": "NOWPAYMENTS_API_KEY is not set"}
    payload = {
        "price_amount": float(amount_usd),
        "price_currency": "usd",
        "order_id": order_id,
        "order_description": order_desc,
        "is_fixed_rate": True,
        "is_fee_paid_by_user": True,
        "ipn_callback_url": ipn_url,
    }
    if success_url: payload["success_url"] = success_url
    if cancel_url:  payload["cancel_url"]  = cancel_url
    try:
        r = _rq_np.post("https://api.nowpayments.io/v1/invoice", json=payload, timeout=12, headers={"x-api-key": api_key})
        j = r.json() if r.headers.get("content-type","").startswith("application/json") else {"error": r.text}
        if r.ok and isinstance(j, dict) and (j.get("invoice_id") or j.get("id")):
            return {"ok": True, "json": j}
        return {"ok": False, "status": r.status_code, "json": j}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/crypto_webhook/<secret>")
def np_ipn(secret):
    expected_secret = (os.getenv("CRYPTO_WEBHOOK_SECRET") or "").strip()
    if expected_secret and secret != expected_secret:
        return jsonify({"ok": False, "error": "bad secret"}), 403
    try:
        raw = request.get_data()  # bytes
    except Exception:
        raw = b""
    sig = request.headers.get("x-nowpayments-sig","").strip().lower()
    calc = hmac.new((os.getenv("CRYPTO_WEBHOOK_HMAC") or "").encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not sig or sig != calc.lower():
        return jsonify({"ok": False, "error": "bad signature"}), 400
    data = request.get_json(force=True, silent=True) or {}
    status = (data.get("payment_status") or data.get("paymentStatus") or "").lower()
    order_id = str(data.get("order_id") or data.get("orderId") or "")
    invoice_id = str(data.get("invoice_id") or data.get("invoiceId") or "")
    if status not in ("finished","confirmed","confirming","partially_paid"):
        return jsonify({"ok": True, "ignored": status})
    # Parse chat_id and plan from order_id: tg:<chat_id>:<plan>:...
    chat_id = None; plan = "pro"
    try:
        parts = order_id.split(":")
        if len(parts) >= 3 and parts[0] == "tg":
            chat_id = int(parts[1]); plan = parts[2]
    except Exception:
        pass
    if not chat_id:
        # We can't identify the user; acknowledge but do nothing
        return jsonify({"ok": True, "no_user": True})
    # Activate entitlement on finished/confirmed
    if status in ("finished","confirmed"):
        days = _plan_defaults(plan).get("days", 30)
        exp = _grant_plan(chat_id, plan, days)
        try:
            exp_dt = dt.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            exp_dt = str(exp)
        send_message(chat_id, f"✅ *{plan.capitalize()}* activated. Expires: {exp_dt}")
    return jsonify({"ok": True, "chat_id": chat_id, "status": status, "invoice_id": invoice_id})
# === /NOWPayments integration ================================================


# --- OMEGA-713K: known domains override (website hints) ---
def _load_known_domains(path: str = "known_domains.json"):
    """Try to load a JSON map {token_address_lower: {"site": "https://..."}}, fallback to built-ins for well-known tokens."""
    import json as _json, os as _os
    _builtin = {
        "0x6982508145454ce325ddbe47a25d4ec3d2311933": {"site": "https://www.pepe.vip/"},
        "0x831753dd7087cac61ab5644b308642cc1c33dc13": {"site": "https://quickswap.exchange/"},
        "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82": {"site": "https://pancakeswap.finance/"},
    }
    try:
        if _os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                j = _json.load(f) or {}
                if isinstance(j, dict):
                    _builtin.update({k.lower(): v for k, v in j.items()})
    except Exception:
        pass
    return _builtin
# --- /OMEGA-713K ---




def _discover_site_via_ds(chain: str | None, pair_addr: str | None, token_addr: str | None, timeout=6) -> str | None:
    """Try to fetch project website from DexScreener API if links['site'] is absent."""
    import requests as _rq
    chain = (chain or "").strip().lower()
    pair  = (pair_addr or "").strip().lower()
    tok   = (token_addr or "").strip().lower()
    try:
        if chain and pair:
            r = _rq.get(f"https://api.dexscreener.com/latest/dex/pairs/{chain}/{pair}", timeout=timeout)
            if r.ok:
                j = r.json() or {}
                pairs = j.get("pairs") or []
                if isinstance(pairs, list) and pairs:
                    info = (pairs[0].get("info") or {})
                    w    = info.get("websites") or info.get("website") or []
                    if isinstance(w, list) and w:
                        u = (w[0].get("url") if isinstance(w[0], dict) else str(w[0]))
                        if isinstance(u, str) and u.startswith("http"): return u
                    u = info.get("url")
                    if isinstance(u, str) and u.startswith("http"): return u
        if tok:
            r2 = _rq.get(f"https://api.dexscreener.com/latest/dex/tokens/{tok}", timeout=timeout)
            if r2.ok:
                j2 = r2.json() or {}
                pairs = j2.get("pairs") or []
                if isinstance(pairs, list) and pairs:
                    info = (pairs[0].get("info") or {})
                    w    = info.get("websites") or info.get("website") or []
                    if isinstance(w, list) and w:
                        u = (w[0].get("url") if isinstance(w[0], dict) else str(w[0]))
                        if isinstance(u, str) and u.startswith("http"): return u
                    u = info.get("url")
                    if isinstance(u, str) and u.startswith("http"): return u
    except Exception:
        return None
    return None



# --- Health endpoints (OMEGA-713K, GET only) ---
@app.route('/healthz', methods=['GET','HEAD'])
def _healthz_get():
    try:
        return jsonify({"ok": True, "status": "ok", "ts": int(time.time())}), 200
    except Exception:
        return jsonify({"ok": True}), 200

@app.get("/health")
def _health_get():
    return jsonify({"ok": True, "status": "ok", "ts": int(time.time())}), 200
# --- /Health endpoints ---


_MD2_SPECIALS = r'_[]()~>#+-=|{}.!*`'
_MD2_PATTERN = re.compile('[' + re.escape(_MD2_SPECIALS) + ']')
def mdv2_escape(text: str) -> str:
    if text is None: return ""
    return _MD2_PATTERN.sub(lambda m: '\\' + m.group(0), str(text))


def _is_contract_address(s: str) -> bool:
    try:
        return bool(re.match(r"^0x[0-9a-fA-F]{40}$", s or ""))
    except Exception:
        return False


def tg(method, payload=None, files=None, timeout=12):
    payload = payload or {}
    try:
        r = requests.post(f"{TELEGRAM_API}/{method}", data=payload, files=files, timeout=timeout)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# === QUICKFIX: token address derivation for ONCHAIN ===
def _derive_token_address_quickfix(mkt: dict, links: dict) -> str | None:
    if not isinstance(mkt, dict):
        return None
    t = (mkt.get("tokenAddress") or "").strip()
    if t.startswith("0x") and len(t) == 42:
        return t
    for k in ("address","token","token0Address","baseTokenAddress","token1Address","baseToken"):
        v = mkt.get(k)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            return v
        if isinstance(v, dict):
            a = (v.get("address") or "").strip()
            if a.startswith("0x") and len(a) == 42:
                return a
    if isinstance(links, dict):
        val = f"{links.get('scan') or ''} {links.get('dex') or ''} {links.get('holders') or ''}"
        m = re.search(r"(?:token|address|inputCurrency|outputCurrency)=?0x([0-9a-fA-F]{40})", val)
        if m:
            return "0x" + m.group(1)
    return None
# === /QUICKFIX ===
def send_message(chat_id, text, reply_markup=None, parse_mode='Markdown', disable_web_page_preview=None):
    data = {"chat_id": chat_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

def send_message_raw(chat_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "text": str(text)}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)


# === WATCHLITE (non-invasive Watchlist + Alerts) =============================
import os, sys, importlib, importlib.util, pathlib
def _load_watchlite():
    # 1) Try module names (new → old → generic)
    for name in ("watchlite_0_1_3", "watchlite_0_1_0", "watchlite"):
        try:
            return importlib.import_module(name)
        except Exception:
            pass
    # 2) Try local files relative to this server file
    base = pathlib.Path(__file__).parent
    for fname in ("watchlite_0_1_3.py", "watchlite_0_1_0.py", "watchlite.py"):
        f = base / fname
        if f.exists():
            spec = importlib.util.spec_from_file_location("watchlite", str(f))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["watchlite"] = mod
            spec.loader.exec_module(mod)
            return mod
    # 3) Optional explicit path via env
    fpath = os.getenv("WATCHLITE_PATH")
    if fpath and os.path.exists(fpath):
        spec = importlib.util.spec_from_file_location("watchlite", fpath)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["watchlite"] = mod
        spec.loader.exec_module(mod)
        return mod
    raise ModuleNotFoundError("watchlite module not found")
watchlite = _load_watchlite()
try:
    WATCH_DB_PATH = os.getenv("WATCH_DB_PATH", "./watch_db.json")
    WATCH_STATE_PATH = os.getenv("WATCH_STATE_PATH", "./watch_state.json")
    WATCHLIST_LIMIT = int(os.getenv("WATCHLIST_LIMIT", "200"))
except Exception:
    WATCH_DB_PATH, WATCH_STATE_PATH, WATCHLIST_LIMIT = "./watch_db.json", "./watch_state.json", 200

# Initialize once (starts background ticker thread)
try:
    watchlite.init(
        paths={"db": WATCH_DB_PATH, "state": WATCH_STATE_PATH},
        limit=WATCHLIST_LIMIT,
        send_message_fn=send_message,
        send_message_raw=send_message_raw if 'send_message_raw' in globals() else None,
        tg_fn=tg,
        escape_fn=mdv2_escape if 'mdv2_escape' in globals() else None,
        fetch_market_fn=fetch_market if 'fetch_market' in globals() else None,
        build_keyboard_fn=build_keyboard if 'build_keyboard' in globals() else None,
        answer_callback_fn=answer_callback_query if 'answer_callback_query' in globals() else None,
    )
except Exception as _e_watch_init:
    try:
        print("WATCHLITE init failed:", _e_watch_init)
    except Exception:
        pass
# === /WATCHLITE ==============================================================



def answer_callback_query(cb_id, text, show_alert=False):
    return tg("answerCallbackQuery", {"callback_query_id": cb_id, "text": str(text), "show_alert": bool(show_alert)})

def send_document(chat_id: int, filename: str, content_bytes: bytes, caption: str | None = None, content_type: str = "application/json"):
    files = { "document": (filename, content_bytes, content_type) }
    payload = {"chat_id": chat_id}
    if caption: payload["caption"] = caption
    return tg("sendDocument", payload, files=files)

def parse_cb(data: str):
    m = re.match(r"^v1:(\w+):(\-?\d+):(\-?\d+)$", data or "")
    if not m: return None
    return m.group(1), int(m.group(2)), int(m.group(3))

def _pricing_links():
    """
    Returns pricing/upgrade links. Prefers CRYPTO_* env (NOWPayments) if present.
    Fallbacks:
      - If CRYPTO_LINK_* provided: use them
      - Else: point to internal invoice endpoint /api/now/invoice?plan=...
      - Else: use static *URL envs (DEEP_REPORT_URL, PRO_URL, ...)
    """
    import os as _os, urllib.parse as _up
    base = (_os.getenv("PUBLIC_URL") or _os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")
    # NOWPayments-style link bases (may be like https://nowpayments.io/payment/?iid=)
    cl_deep  = (_os.getenv("CRYPTO_LINK_DEEP") or "").strip()
    cl_day   = (_os.getenv("CRYPTO_LINK_DAYPASS") or "").strip()
    cl_pro   = (_os.getenv("CRYPTO_LINK_PRO") or "").strip()
    cl_teams = (_os.getenv("CRYPTO_LINK_TEAMS") or "").strip()

    def _pref(link_base, plan):
        # If set -> use as-is; else if server has public URL -> internal invoice; else -> fallback static URL
        if link_base:
            return link_base
        if base:
            return f"{base}/api/now/invoice?plan={_up.quote(plan)}"
        # Final fallback: previous static URLs
        if plan == "deep":   return DEEP_REPORT_URL
        if plan == "day":    return DAY_PASS_URL
        if plan == "pro":    return PRO_URL
        if plan == "teams":  return TEAMS_URL
        return HELP_URL

    return {
        "deep_report": _pref(cl_deep, "deep"),
        "day_pass":    _pref(cl_day, "day"),
        "pro":         _pref(cl_pro, "pro"),
        "teams":       _pref(cl_teams, "teams"),
        "help":        HELP_URL,
    }

def build_hint_quickscan(clickable: bool) -> str:
    pair_example = "https://dexscreener.com/ethereum/0x..." if clickable else "dexscreener[.]com/ethereum/0x…"
    return (
        "Paste a *token address*, *TX hash* or *URL* to scan.\n"
        "Examples:\n"
        "`0x6982508145454ce325ddbe47a25d4ec3d2311933`  — ERC-20\n"
        f"{pair_example} — pair\n\n"
        "Then tap *More details* / *Why?* / *On-chain* for deeper info."
    )

WELCOME = (
    "Welcome to Metridex.\n"
    "Send a token address, TX hash, or a link — I'll run a QuickScan.\n\n"
    "Commands: /quickscan, /upgrade, /limits\n"
    f"Help: {HELP_URL}"
)
UPGRADE_TEXT = (
    "Metridex Pro — full QuickScan access\n"
    "• Pro $29/mo — fast lane, Deep reports, export\n"
    "• Teams $99/mo — for teams/channels\n"
    "• Day-Pass $9 — 24h of Pro\n"
    "• Deep Report $3 — one detailed report\n\n"
    f"Choose your access below. How it works: {HELP_URL}"
)

def safe_render_why(verdict, market, lang):
    try:
        return render_why(verdict, market, lang)
    except TypeError:
        try:
            return render_why(verdict, lang)
        except TypeError:
            return render_why(verdict)

def safe_render_whypp(verdict, market, lang):
    try:
        return render_whypp(verdict, market, lang)
    except TypeError:
        try:
            return render_whypp(verdict, lang)
        except TypeError:
            return render_whypp(verdict)

@app.get(WEBHOOK_PATH)
def _webhook_probe_get():
    return jsonify({'ok': True, 'method': 'GET', 'ts': int(time.time())}), 200

@app.post(WEBHOOK_PATH)
def webhook():
    # Webhook header guard (optional, accepts WEBHOOK_HEADER_SECRET or BOT_WEBHOOK_SECRET)
    try:
        hdr = request.headers.get('X-Telegram-Bot-Api-Secret-Token')
    except Exception:
        hdr = None
    expected = os.getenv('WEBHOOK_HEADER_SECRET','').strip() or (BOT_WEBHOOK_SECRET or '')
    if expected and hdr != expected:
        return jsonify({'ok': False, 'err': 'bad secret header'}), 403
    try:
        upd = request.get_json(force=True, silent=True) or {}
        if "message" in upd: return on_message(upd["message"])
        if "edited_message" in upd: return on_message(upd["edited_message"])
        if "callback_query" in upd: return on_callback(upd["callback_query"])
        return jsonify({"ok": True})
    except Exception as e:
        print("WEBHOOK ERROR", e, traceback.format_exc())
        return jsonify({"ok": True})



def _generate_whypp_ai_enriched(market: dict, why_text: str, webintel: dict, onchain: dict | None) -> str | None:
    try:
        import os
        if os.getenv('WHYPP_ENABLED','0') != '1':
            return None
        key = os.getenv("OPENAI_API_KEY") or ""
        if not key:
            return None
        client = _get_ai_client()
        model = os.getenv("WHYPP_MODEL", "gpt-4o-mini")

        pair = market.get("pairSymbol") or market.get("symbol") or "Token"
        chain = (market.get("chain") or market.get("chainId") or "—")
        ch = market.get("priceChanges") or {}
        age = market.get("age") or market.get("ageDays") or ""
        liq = market.get("liquidity") or market.get("liquidityUSD") or market.get("liquidityUsd") or ""
        vol24 = market.get("volume24h") or market.get("volumeUSD") or market.get("vol24h") or ""
        dom = "-"; wb = "-"; ssl = "-"; rdap_flags = []; country = "-"
        if isinstance(webintel, dict):
            dom = (webintel.get("domain") or webintel.get("url") or "-")
            country = webintel.get("country") or "-"
            if webintel.get("wayback_first"): wb = str(webintel.get("wayback_first"))
            if isinstance(webintel.get("ssl"), dict):
                ssl_obj = webintel["ssl"]; ssl = f"ok={ssl_obj.get('ok')} exp={ssl_obj.get('expires')}"
            flags = webintel.get("flags") or webintel.get("rdap_flags") or {}
            if isinstance(flags, dict): rdap_flags = [k for k,v in flags.items() if v]

        oc_lines = []
        if isinstance(onchain, dict):
            if "honeypot" in onchain: oc_lines.append(f"honeypot={bool(onchain.get('honeypot'))}")
            taxes = onchain.get("taxes") or {}
            if taxes: oc_lines.append(f"taxes: buy {taxes.get('buy',0)}% / sell {taxes.get('sell',0)}%")
            owner = onchain.get("owner");  oc_lines.append(f"owner={owner}") if owner else None
            lp = onchain.get("lp_lock") or {}
            if lp:
                status = lp.get('status') or 'unknown'; until = lp.get('until') or '—'
                oc_lines.append(f"lp_lock={status}, until={until}")
        oc_summary = " | ".join(oc_lines) if oc_lines else "n/a"

        sys_prompt = (
            "You are a senior DeFi risk analyst writing compact Telegram bot summaries. "
            "Use strict facts provided, avoid assumptions, keep bullets ≤15 words, "
            "separate positives, risks, and context. Output MarkdownV2 safe content."
        )
        user_prompt = f"""PAIR: {pair} | CHAIN: {chain}
AGE(d): {age} | LIQ: {liq} | VOL24h: {vol24}
DELTAS: {ch}
DOMAIN: {dom} | COUNTRY: {country} | SSL: {ssl} | WAYBACK_FIRST: {wb} | RDAP_FLAGS: {','.join(rdap_flags) or '-'}
ONCHAIN: {oc_summary}

BASE WHY:
{why_text}

Write **Why++** with 8–12 bullets:
- 3–4 positives first (with figures when present)
- 3–5 key risks (LP lock, ownership, taxes, honeypot, volatility)
- 2–3 neutral context items (age, volume, domain intel)
- No promises or advice; concise; MarkdownV2 compatible."""

        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role":"system","content":sys_prompt},
                {"role":"user","content":user_prompt}
            ],
            temperature=0.2,
            max_tokens=int(os.getenv("WHYPP_MAX_TOKENS","640")),
        )
        out = (resp.choices[0].message.content or "").strip()
        if out and not out.lower().startswith("**why++**"):
            out = "**Why++**\n" + out
        return out or None
    except Exception as _e_ai:
        try: print("WHYPP AI error:", _e_ai)
        except Exception: pass
        return None
# ---- LP renderer compatibility wrapper ----

def _render_lp_compat(info, market=None, lang=None):
    # Back-compat: allow call signature (info, lang)
    if isinstance(market, str) and lang is None:
        lang, market = market, None
    """Compatibility wrapper that builds a minimal LP-lite info dict and delegates
    to renderers_mdx.render_lp(info, lang) without any extra RPC calls.

    - `info`: dict that may already contain keys like lpAddress/lpToken, burnedPct, lockedPct, lockedBy, chain.
    - `market`: optional market dict used only to *fill gaps* (chain/pairAddress).
    - `lang`: language code; defaults to env DEFAULT_LANG or 'en'.
    """
    try:
        if lang is None:
            try:
                lang = DEFAULT_LANG  # provided at module level
            except Exception:
                lang = "en"
        p = dict(info or {})
        # Safe helpers
        def _looks_addr(a):
            return isinstance(a, str) and a.startswith("0x") and len(a) >= 10
        def _chain_norm(x):
            v = (str(x) if x is not None else "").strip().lower()
            mp = {"1":"eth","eth":"eth","ethereum":"eth","56":"bsc","bsc":"bsc","bnb":"bsc","137":"polygon","matic":"polygon","polygon":"polygon"}
            return mp.get(v, v or "eth")
        # Fill from market if missing
        if isinstance(market, dict):
            ch = p.get("chain") or p.get("network") or p.get("chainId")
            if not ch:
                ch = market.get("chain") or market.get("network") or market.get("chainId")
            if ch:
                p["chain"] = _chain_norm(ch)
            lp = p.get("lpAddress") or p.get("lpToken") or p.get("address")
            if not _looks_addr(lp):
                cand = (market.get("pairAddress") or market.get("pair") or market.get("lpAddress"))
                if _looks_addr(cand):
                    p["lpAddress"] = cand
        # Minimal provider tag for downstream renderer
        p.setdefault("provider", p.get("provider") or "lp-lite")
        # Ensure we don't accidentally pass complex nested objects that could cause renderer issues
        # Keep only expected primitive fields if present
        safe = {}
        for k in ("provider","chain","lpAddress","lpToken","address","burnedPct","burned_pct","lockedPct","lockedBy"):
            if k in p:
                safe[k] = p[k]
        # Keep nested 'data' (from inspector) but only with allowed keys
        if isinstance(p.get("data"), dict):
            d = p["data"]
            safe["data"] = {kk: d.get(kk) for kk in ("burnedPct","burned_pct","lockedPct","lockedBy") if kk in d}
        # Prefer lpAddress over lpToken in output
        if not _looks_addr(safe.get("lpAddress")) and _looks_addr(safe.get("lpToken")):
            safe["lpAddress"] = safe["lpToken"]
        # Delegate to MDX renderer (2-arg signature)
        from renderers_mdx import render_lp as _render_lp_mdx
        return _render_lp_mdx(safe, lang)
    except Exception as _e:
        try:
            print("[LP] compat error:", _e)
        except Exception:
            pass
        # Fail gracefully with a compact fallback text
        lp_addr = None
        try:
            lp_addr = info.get("lpAddress") or info.get("lpToken") or (market.get("pairAddress") if isinstance(market, dict) else None)
        except Exception:
            pass
        return "\n".join([
            "LP lock (lite)",
            f"Status: unknown",
            f"Burned: —",
            f"Locked: —",
            f"LP token: {lp_addr or '—'}",
            "Data source: —",
        ])

def on_message(msg):
    lp = {}
    details = None
    why = None
    whypp = None
    web = None
    # SAFE DEFAULTS to avoid UnboundLocalError on failed branches
    quick = quick if 'quick' in locals() else ''
    details = details if 'details' in locals() else ''
    why = why if 'why' in locals() else ''
    whypp = whypp if 'whypp' in locals() else ''
    lp = lp if 'lp' in locals() else ''
    web = web if 'web' in locals() else {}
    # ---- WATCHLITE: early intercept of new commands (/watch, /unwatch, /watchlist, /alerts*) ----
    try:
        _wl_text = (msg.get("text") or msg.get("caption") or "")
        _wl_chat = ((msg.get("chat") or {}).get("id") or (msg.get("from") or {}).get("id"))
        if _wl_chat and isinstance(_wl_text, str):
            if watchlite.handle_message_commands(_wl_chat, _wl_text, None, msg):
                return jsonify({"ok": True})
    except Exception as _e_wl_early:
        try:
            print("WATCHLITE early intercept error:", _e_wl_early)
        except Exception:
            pass
    # ---- /WATCHLITE early intercept ----

    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    import re as _re
    # --- A) Normalize watch/unwatch forms before anything else ---
    text = (msg.get("text") or "").strip()
    print(f"[PARSE] raw={repr(text)}")
    if _re.match(r"^(watch|unwatch)(/|\s)+", text, flags=_re.I):
        text = _re.sub(r"^(watch|unwatch)(/|\s)+", lambda m: f"/{m.group(1).lower()} ", text, flags=_re.I).strip()
        msg["text"] = text
        print(f"[PARSE] normalized to={repr(text)}")
    low = text.lower()

    # --- WATCHLITE intercept: commands (/watch, /unwatch, /watchlist, /alerts*) ---
    try:
        if watchlite.handle_message_commands(chat_id, text, load_bundle, msg):
            return jsonify({"ok": True})
    except Exception as _e_wl_msg:
        try:
            print("WATCHLITE handle_message_commands error:", _e_wl_msg)
        except Exception:
            pass
    # --- /WATCHLITE intercept ---

    if low.startswith("/start"):  # D0: start hook — personalized greeting + trust badge 'Scanned 1M+ tokens'
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/upgrade"):
        send_message(chat_id, UPGRADE_TEXT, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/quickscan"):
        send_message(chat_id, build_hint_quickscan(HINT_CLICKABLE_LINKS), reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/limits"):
        try:
            ok, tier = can_scan(chat_id)
            plan = (tier or "Free")
            allowed = "✅ allowed now" if ok else "⛔ not allowed now"
        except Exception:
            plan, allowed = "Free", "—"
        msg_txt = (
            f"*Plan:* {plan}\n"
            f"*Free quota:* {FREE_DAILY_SCANS}/day\n"
            f"*Now:* {allowed}\n\n"
            "Upgrade for unlimited scans: /upgrade"
        )
        send_message(chat_id, msg_txt, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    if low.startswith("/diag"):
        _handle_diag_command(chat_id)
        return jsonify({"ok": True})

    
    # Guard: don't show welcome for watch-related commands; delegate to watchlite
    try:
        if re.match(r'^/(watch|unwatch|watchlist|alerts[\w_]*)', low):
            if watchlite.handle_message_commands(chat_id, text, load_bundle, msg):
                return jsonify({"ok": True})
            # Even if not handled, avoid falling through to generic welcome for these commands
            send_message(chat_id, "Usage: `/watch 0x...`, `/unwatch 0x...`, `/watchlist`, `/alerts_on|/alerts_off|/alerts`")
            return jsonify({"ok": True})
    except Exception as _e_wl_guard:
        try:
            print("WATCHLITE guard error:", _e_wl_guard)
        except Exception:
            pass
    # Guard: avoid falling through after command handling
    if re.match(r'^/(watch|unwatch|watchlist|alerts[\w_]*)', (msg.get("text") or "").lower()):
        # If not already handled above, show usage and return
        send_message(chat_id, "Usage: `/watch 0x...`, `/unwatch 0x...`, `/watchlist`, `/alerts_on|/alerts_off|/alerts`")
        return jsonify({"ok": True})

# Only non-command messages trigger scan
    if text.startswith("/"):
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted. Use /upgrade.", reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})
    # --- Processing indicator (address-only) ---
    ph_id = None
    if _is_contract_address(text) or re.match(r"^0x[a-fA-F0-9]{64}$", text) or ('http' in text.lower()):
        ph = send_message(chat_id, "Processing…")
        ph_id = ph.get("result", {}).get("message_id") if isinstance(ph, dict) and ph.get("ok") else None
        try:
            tg("sendChatAction", {"chat_id": chat_id, "action": "typing"})
        except Exception:
            pass
    # --- /Processing indicator ---
    # Safe sender that prefers editing the placeholder; falls back to plain text
    def _send_or_edit_quick(quick_text: str, links: dict) -> int | None:
        msg_id = None
        # Try edit with MarkdownV2 first
        try:
            if 'ph_id' in locals() and ph_id:
                _ed = tg('editMessageText', {
                    'chat_id': chat_id,
                    'message_id': ph_id,
                    'text': quick_text,
                    'parse_mode': 'MarkdownV2',
                    'reply_markup': build_keyboard(chat_id, 0, links)
                })
                if isinstance(_ed, dict) and _ed.get('ok'):
                    return ph_id
        except Exception as _e1:
            try:
                print('EDIT mdv2 failed:', _e1)
            except Exception:
                pass
        # Try edit without parse_mode
        try:
            if 'ph_id' in locals() and ph_id:
                _ed2 = tg('editMessageText', {
                    'chat_id': chat_id,
                    'message_id': ph_id,
                    'text': quick_text,
                    'reply_markup': build_keyboard(chat_id, 0, links)
                })
                if isinstance(_ed2, dict) and _ed2.get('ok'):
                    return ph_id
        except Exception as _e2:
            try:
                print('EDIT plain failed:', _e2)
            except Exception:
                pass
        # Send as a new message with MarkdownV2; if fails, send plain
        try:
            sent = send_message(chat_id, quick_text, reply_markup=build_keyboard(chat_id, 0, links))
            if isinstance(sent, dict) and sent.get('ok'):
                msg_id = sent.get('result', {}).get('message_id')
        except Exception as _e3:
            try:
                print('SEND mdv2 failed:', _e3)
            except Exception:
                pass
            # Plain-text last resort
            try:
                import re as _re
                _plain = _re.sub(r'[\\`*_\[\]()~>#+\-=|{}.!]', '', quick_text)
                sent2 = tg('sendMessage', {'chat_id': chat_id, 'text': _plain})
                if isinstance(sent2, dict) and sent2.get('ok'):
                    msg_id = sent2.get('result', {}).get('message_id')
            except Exception as _e4:
                try:
                    print('SEND plain failed:', _e4)
                except Exception:
                    pass
        # Delete placeholder if we ended up sending a new message
        try:
            if 'ph_id' in locals() and ph_id and (msg_id is None or msg_id != ph_id):
                tg('deleteMessage', {'chat_id': chat_id, 'message_id': ph_id})
        except Exception:
            pass
        return msg_id



    # QuickScan flow
    try:
        market = fetch_market(text) or {}
    except Exception as e:
        print('QUICKSCAN ERROR (fetch_market)', e, traceback.format_exc())
        market = {}

    if not market.get("ok"):
        if re.match(r"^0x[a-fA-F0-9]{64}$", text):
            pass
        elif re.match(r"^0x[a-fA-F0-9]{40}$", text):
            market.setdefault("tokenAddress", text)
        market.setdefault("chain", market.get("chain") or "—")
        market.setdefault("sources", [])
        market.setdefault("priceChanges", {})
        market.setdefault("links", {})
    # --- OMEGA-713K D1: robust Age computation ---
    try:
        _ts = market.get("pairCreatedAt") or market.get("launchedAt") or market.get("createdAt")
        _now = market.get("asOf") or int(time.time())

        # If _ts missing, pull from DexScreener pairs endpoint (one-shot, 5s)
        if not _ts:
            try:
                import os as _os, requests as _rq
                _chain0 = (market.get("chain") or "").lower()
                _map = {"ethereum":"ethereum","eth":"ethereum","bsc":"bsc","binance":"bsc","polygon":"polygon","matic":"polygon",
                        "arbitrum":"arbitrum","base":"base","optimism":"optimism","op":"optimism","avalanche":"avalanche","fantom":"fantom","ftm":"fantom"}
                _short = _map.get(_chain0, _chain0)
                _pair_addr0 = (market.get("pairAddress") or "").lower()
                if _short and _pair_addr0:
                    _base0 = (_os.getenv("DS_PROXY_URL") or _os.getenv("DEXSCREENER_PROXY_BASE") or "https://api.dexscreener.com").rstrip("/")
                    _url0 = f"{_base0}/latest/dex/pairs/{_short}/{_pair_addr0}"
                    _r0 = _rq.get(_url0, timeout=5)
                    if _r0.ok:
                        _j0 = _r0.json() or {}
                        _pd0 = _j0.get("pair")
                        if not isinstance(_pd0, dict):
                            _ps0 = _j0.get("pairs") or _j0.get("data") or []
                            if isinstance(_ps0, list) and _ps0:
                                _pd0 = _ps0[0] if isinstance(_ps0[0], dict) else {}
                        if isinstance(_pd0, dict):
                            _ts = _pd0.get("pairCreatedAt") or _pd0.get("createdAt") or _pd0.get("launchedAt")
            except Exception:
                pass
    
        if isinstance(_ts, (int, float)) and _ts:
            # normalize milliseconds to seconds when needed
            if _ts > 10_000_000_000:  # looks like ms
                _ts = int(_ts // 1000)
            _age_days = max(0.0, round((_now - int(_ts)) / 86400.0, 2))
            market["ageDays"] = _age_days
    except Exception:
        pass
    # --- /D1 Age ---

    # --- OMEGA-713K: Buttons links enrichment ---
    try:
        _links = market.get("links") or {}
    except Exception:
        _links = {}
    _chain = (market.get("chain") or "").lower()
    _token = (market.get("tokenAddress") or "").lower()
    _pair  = (market.get("pairAddress") or "").lower()
    _dexId = (_links.get("dexId") or "").lower()

    # DexScreener link (kept separate from real DEX)
    if not _links.get("dexscreener"):
        ds_url = (_links.get("dexscreener") or "").strip()
        if not ds_url and _chain and _pair:
            ds_url = f"https://dexscreener.com/{_chain}/{_pair}"
        if ds_url:
            _links["dexscreener"] = ds_url

    # Scan link per chain
    if not _links.get("scan") and _token:
        _scan_bases = {
            "ethereum": "https://etherscan.io/token/",
            "eth": "https://etherscan.io/token/",
            "bsc": "https://bscscan.com/token/",
            "binance": "https://bscscan.com/token/",
            "polygon": "https://polygonscan.com/token/",
            "matic": "https://polygonscan.com/token/",
            "arbitrum": "https://arbiscan.io/token/",
            "arb": "https://arbiscan.io/token/",
            "base": "https://basescan.org/token/",
            "optimism": "https://optimistic.etherscan.io/token/",
            "op": "https://optimistic.etherscan.io/token/",
            "avalanche": "https://snowtrace.io/token/",
            "avax": "https://snowtrace.io/token/",
            "fantom": "https://ftmscan.com/token/",
            "ftm": "https://ftmscan.com/token/",
        }
        base = _scan_bases.get(_chain)
        if base:
            _links["scan"] = base + _token

    # Real DEX link (shows as 'Open in DEX' if not DexScreener)
    if not _links.get("dex") and _token:
        if _dexId in ("uniswap", "uniswapv2", "uniswapv3") and _chain in ("ethereum","base","arbitrum","polygon","optimism"):
            _links["dex"] = f"https://app.uniswap.org/explore/tokens/{_chain}/{_token}"
        elif _dexId.startswith("pancake") and _chain in ("bsc","binance"):
            _links["dex"] = f"https://pancakeswap.finance/swap?outputCurrency={_token}"
        elif "quickswap" in _dexId and _chain == "polygon":
            _links["dex"] = f"https://quickswap.exchange/#/swap?outputCurrency={_token}"

    # Discover project website if missing (DexScreener fallback)
    if not _links.get("site"):
        try:
            _site_guess = _discover_site_via_ds(_chain, _pair, _token, timeout=6)
            if _site_guess:
                _links["site"] = _site_guess
        except Exception:
            pass
    # Prefer known_domains override if site is missing
    if not _links.get("site") and _token:
        _known = _load_known_domains()
        _site = (_known.get(_token.lower()) or {}).get("site") if isinstance(_known, dict) else None
        if _site:
            _links["site"] = _site
    market["links"] = _links
    # --- /OMEGA-713K ---


    # Ensure asof timestamp and pair age
    if not market.get("asof"):
        market["asof"] = int(time.time() * 1000)
    if not market.get("ageDays"):
        pc = market.get("pairCreatedAt") or market.get("launchedAt") or market.get("createdAt")
        if pc:
            try:
                ts = int(pc)
            except Exception:
                ts = None
            if ts:
                if ts < 10**12:
                    ts *= 1000
                age_days = (time.time()*1000 - ts) / (1000*60*60*24)
                if age_days < 0:
                    age_days = 0
                market["ageDays"] = round(age_days, 2)

    verdict = compute_verdict(market)
    # --- precompute website intel and pass into ctx so renderers can show it ---
    links = (market.get("links") or {})
    web = {

        "whois": {"created": None, "registrar": None},

        "ssl": {"ok": None, "expires": None, "issuer": None},

        "wayback": {"first": None}

    }

    site_url = None
    try:

        site_url = links.get("site") or os.getenv("WEBINTEL_SITE_OVERRIDE")

        if site_url:

            web = analyze_website(site_url)

    except Exception:

        pass

    web = _enrich_webintel_fallback(derive_domain(site_url), web)
    # >>> FIX: pass precomputed webintel into ctx so renderers see it
    try:
        _dom = derive_domain(site_url)
    except Exception:
        _dom = None
    ctx = {"webintel": web or {}, "domain": _dom}

    quick = render_quick(verdict, market, ctx, DEFAULT_LANG)
    # Reuse same ctx (no re-computation)
    details = render_details(verdict, market, ctx, DEFAULT_LANG)
    why = safe_render_why(verdict, market, DEFAULT_LANG)
    whypp = safe_render_whypp(verdict, market, DEFAULT_LANG)

    # --- AI Why++ enrichment (OpenAI) ----------------------------------------
    try:
        _ctx_onchain = None
        if os.getenv("WHYPP_ENRICH_ONCHAIN","1") == "1":
            try:
                _token_addr = market.get('tokenAddress')
                _chain_hint = (market.get('chain') or market.get('chainId') or 'ethereum')
                _ctx_onchain = fetch_onchain_factors(_token_addr, chain_hint=_chain_hint)
            except Exception:
                _ctx_onchain = None
        _webintel = (ctx.get('webintel') if isinstance(ctx, dict) else {}) or {}
        _ai_whypp = _generate_whypp_ai_enriched(market, why, _webintel, _ctx_onchain)
        if _ai_whypp:
            whypp = _ai_whypp
    except Exception as _e_ai_over:
        pass
    # --------------------------------------------------------------------------
    try:
        ch_ = (market.get("chain") or "").lower()
        _map = {"ethereum":"eth","bsc":"bsc","polygon":"polygon","arbitrum":"arb","optimism":"op","base":"base","avalanche":"avax","fantom":"ftm"}
        _short = _map.get(ch_, ch_ or "eth")
        pair_addr = market.get("pairAddress") or resolve_pair(_short, market.get("tokenAddress"))
        try:
            oc_for_lp = onchain_inspector.inspect_token(_short, market.get('tokenAddress'), market.get('pairAddress'))
        except Exception as _e_lp:
            oc_for_lp = {}
        info = _lp_info_from_inspector(oc_for_lp, _short, market.get('pairAddress'))
        _lpdbg('LP.init', chain=_short, pair=_short_addr(market.get('pairAddress')),
               oc_ok=(isinstance(oc_for_lp, dict) and oc_for_lp.get('ok')))
        try:
            lp = _render_lp_compat(info, DEFAULT_LANG)
        except TypeError:
            try:
                lp = _render_lp_compat(info, market, DEFAULT_LANG)
            except Exception:
                lp = 'LP lock: unknown'
        if not lp or 'unknown' in str(lp).lower():
            _lpdbg('LP.fallback_v2', chain=_short, pair=_short_addr(market.get('pairAddress')))
            try:
                info2 = check_lp_lock_v2(_short, market.get('pairAddress'))
                try:
                    if isinstance(info2, dict) and not info2.get('chain'):
                        info2['chain'] = _short
                except Exception:
                    pass
                try:
                    lp = _render_lp_compat(info2, DEFAULT_LANG)
                except TypeError:
                    lp = _render_lp_compat(info2, market, DEFAULT_LANG)
            except Exception:
                lp = 'LP lock: unknown'
    except TypeError:
        lp = _render_lp_compat({"provider":"lite-burn-check","lpAddress": market.get("pairAddress"), "until": "—"})
    except Exception:
        lp = _render_lp_compat({"provider":"lite-burn-check","lpAddress": pair_addr or market.get("pairAddress"), "until": "—"}, DEFAULT_LANG)

    links = (market.get("links") or {})
    bundle = {
        "verdict": {"level": getattr(verdict, "level", None), "score": getattr(verdict, "score", None)},
        "reasons": list(getattr(verdict, "reasons", []) or []),
        "market": {
            "pairSymbol": market.get("pairSymbol"), "chain": market.get("chain"),
            "price": market.get("price"), "fdv": market.get("fdv"), "mc": market.get("mc"),
            "liq": market.get("liq"), "vol24h": market.get("vol24h"),
            "priceChanges": market.get("priceChanges") or {},
            "tokenAddress": market.get("tokenAddress"), "pairAddress": market.get("pairAddress"),
            "ageDays": market.get("ageDays"), "source": market.get("source"), "sources": market.get("sources"), "asof": market.get("asof")
        },
        "links": {"dex": links.get("dex"), "scan": links.get("scan"), "dexscreener": links.get("dexscreener"), "site": links.get("site")},
        "details": details, "why": why, "whypp": whypp, "lp": (lp if isinstance(lp, str) else "LP lock: unknown"), "webintel": web
    }

    msg_id = _send_or_edit_quick(quick, links)
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
        try:
            # WATCHLITE: remember last token per chat for /watch without args
            watchlite.note_quickscan(chat_id, bundle, msg_id)
        except Exception:
            pass

        try:
            tg("editMessageReplyMarkup", {
                "chat_id": chat_id,
                "message_id": msg_id,
                "reply_markup": json.dumps(build_keyboard(chat_id, msg_id, links, ctx="quick"))
            })
        except Exception as e:
            print("editMessageReplyMarkup failed:", e)

    # --- Remove processing indicator if present ---
    if 'ph_id' in locals() and ph_id:
        try:
            tg("deleteMessage", {"chat_id": chat_id, "message_id": ph_id})
        except Exception:
            pass
    # --- /Remove processing indicator ---
    register_scan(chat_id)
    return jsonify({"ok": True})


def on_callback(cb):


    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")

    # --- WATCHLITE intercept: UNWATCH_T, MUTE/UNMUTE ---
    try:
        if watchlite.handle_callback(cb):
            return jsonify({"ok": True})
    except Exception as _e_wl_cb:
        try:
            print("WATCHLITE handle_callback error:", _e_wl_cb)
        except Exception:
            pass
    # --- /WATCHLITE intercept ---
    current_msg_id = msg.get("message_id")

    m = parse_cb(data)
    if not m:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})
    action, orig_msg_id, orig_chat_id = m

    if orig_msg_id == 0:
        orig_msg_id = current_msg_id

    if str(chat_id) != str(orig_chat_id) and str(orig_chat_id) != '0':
        answer_callback_query(cb_id, "This control expired.", True)
        return jsonify({"ok": True})

    
    # Idempotency: throttle only *heavy* actions for a short period
    heavy_actions = {"DETAILS", "ONCHAIN", "REPORT", "REPORT_PDF", "WHY", "WHYPP", "LP"}
    idem_key = f"cb:{chat_id}:{orig_msg_id}:{action}"
    if action in heavy_actions:
        if cache_get(idem_key):
            answer_callback_query(cb_id, "Please wait…", False)
            return jsonify({"ok": True})
        cache_set(idem_key, "1", ttl_sec=CALLBACK_DEDUP_TTL_SEC)

    bundle = load_bundle(chat_id, orig_msg_id) or {}
    links = bundle.get("links")

    
    if action == "WATCHLIST":
        import os, json, time, hashlib, re as _re
        db_path = os.environ.get("WATCH_DB_PATH", "./watch_db.json")
        # load db
        try:
            with open(db_path, "r", encoding="utf-8") as _f:
                _data = json.load(_f)
        except Exception:
            _data = {}
        # extract chat watchlist
        arr = []
        if isinstance(_data, dict):
            _key = str(chat_id) if chat_id is not None else None
            if _key and _key in _data and isinstance(_data[_key], list):
                arr = _data[_key]
        # normalize
        norm = []
        for t in arr or []:
            s = str(t or "").strip()
            if s:
                norm.append(s)
        # empty -> toast only, no message
        if not norm:
            try:
                answer_callback_query(cb_id, "Your watchlist is empty. Add tokens with /watch 0x…", False)
            except Exception:
                pass
            return jsonify({"ok": True})
        # build body
        lines = [f"{i+1}) {tok}" for i, tok in enumerate(norm[:50])]
        body_text = "Your Watchlist\n" + "\n".join(lines)
        # dedup within 10s for same content
        try:
            _dedup = globals().setdefault("_DEDUP_WATCHLIST", {})
            rec = _dedup.get(chat_id)
            now = time.time()
            body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
            if isinstance(rec, dict) and now - float(rec.get("ts", 0)) < 10.0 and rec.get("hash") == body_hash:
                answer_callback_query(cb_id, "Already shown.", False)
                return jsonify({"ok": True})
            _dedup[chat_id] = {"ts": now, "hash": body_hash}
        except Exception:
            pass
        # respond
        try:
            answer_callback_query(cb_id, "Watchlist loaded.", False)
        except Exception:
            pass
        try:
            send_message(chat_id, body_text, disable_web_page_preview=True)
        except Exception:
            pass
        return jsonify({"ok": True})



    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details", "(no details)"),
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))

    elif action == "WHY":


        # Re-render WHY

        _b = load_bundle(chat_id, orig_msg_id) or {}

        _ver = _b.get("verdict") or verdict

        _mkt = _b.get("market")  or market

        try:

            txt = render_why(_ver, _mkt)

            _b["why"] = txt

            store_bundle(chat_id, orig_msg_id, _b)

        except Exception:

            txt = _b.get("why") or "*Why? unavailable*"

        send_message(chat_id, txt, reply_markup=None)

        answer_callback_query(cb_id, "Why posted.", False)

    elif action == "WHYPP":


        # Re-render WHY++

        _b = load_bundle(chat_id, orig_msg_id) or {}

        _ver = _b.get("verdict") or verdict

        _mkt = _b.get("market")  or market

        try:

            txt = render_whypp(_ver, _mkt)

            _b["whypp"] = txt

            store_bundle(chat_id, orig_msg_id, _b)

        except Exception:

            txt = _b.get("whypp") or "*Why++ unavailable*"

        # Split into chunks to avoid Telegram limits

        MAX = 3500

        if len(txt) <= MAX:

            send_message(chat_id, txt, reply_markup=None)

        else:

            send_message(chat_id, txt[:MAX], reply_markup=None)

            rest = txt[MAX:]

            i = 2

            while rest:

                chunk = rest[:MAX]

                rest = rest[MAX:]

                prefix = f"Why++ ({i})\n"

                send_message(chat_id, prefix + chunk, reply_markup=None)

                i += 1

        answer_callback_query(cb_id, "Why++ posted.", False)

    elif action == "LP":
        


        # LP: prefer inspector data from bundle; otherwise render from pairAddress/chain

        _b = load_bundle(chat_id, orig_msg_id) or {}

        _mkt = _b.get("market") or market or {}

        info = None

        if isinstance(_b.get("lp"), dict):

            info = _b.get("lp")

        elif isinstance(_b.get("lp_info"), dict):

            info = _b.get("lp_info")

        if not isinstance(info, dict):

            _lp = _mkt.get("pairAddress") or _mkt.get("lpToken") or _mkt.get("lpAddress")

            _chain = _mkt.get("chain") or _mkt.get("chainId") or "eth"

            info = {"lpToken": _lp, "chain": _chain}

        try:

            txt = _render_lp_compat(info)

            _b["lp"] = txt

            store_bundle(chat_id, orig_msg_id, _b)

        except Exception:

            txt = _b.get("lp") or "LP lock: temporarily unavailable"

        send_message(chat_id, txt, reply_markup=None)

        answer_callback_query(cb_id, "LP lock posted.", False)

    elif action == "REPORT":
        try:
            # dynamic, human-friendly filename
            mkt = (bundle.get('market') or {})
            pair_sym = (mkt.get('pairSymbol') or 'Metridex')
            ts_ms = mkt.get('asof') or 0
            try:
                from datetime import datetime as _dt
                ts_str = _dt.utcfromtimestamp(int(ts_ms)/1000.0).strftime("%Y-%m-%d_%H%M")
            except Exception:
                ts_str = "now"
            import re as _re
            safe_pair = _re.sub(r"[^A-Za-z0-9._-]+", "_", str(pair_sym))
            fname = f"{safe_pair}_Report_{ts_str}.html"

            html_bytes = _build_html_report_safe(bundle)
            send_document(chat_id, fname, html_bytes, caption='Metridex QuickScan report', content_type='text/html; charset=utf-8')
            answer_callback_query(cb_id, 'Report exported.', False)
        except Exception as e:
            try:
                import json as _json
                pretty = _json.dumps(bundle, ensure_ascii=False, indent=2)
                html = ("<!doctype html><html><head><meta charset='utf-8'/>"
                        "<style>body{background:#0b0b0f;color:#e7e5e4;font-family:Inter,Arial,sans-serif;margin:24px}" 
                        "pre{background:#13151a;border:1px solid #262626;border-radius:12px;padding:12px;white-space:pre-wrap}</style></head>"
                        "<body><h1>Metridex Report (fallback)</h1><pre>"+pretty+"</pre></body></html>")
                send_document(chat_id, 'Metridex_Report.html', html.encode('utf-8'), caption='Metridex QuickScan report', content_type='text/html; charset=utf-8')
                answer_callback_query(cb_id, 'Report exported (fallback).', False)
            except Exception as e2:
                answer_callback_query(cb_id, f'Export failed: {e2}', True)
    elif action == "REPORT_PDF":
        try:
            html_bytes = _build_html_report_safe(bundle)
            pdf = _html_to_pdf(html_bytes)
            if not pdf:
                answer_callback_query(cb_id, "PDF export unavailable on this server.", True)
            else:
                mkt = (bundle.get('market') or {})
                pair_sym = (mkt.get('pairSymbol') or 'Metridex')
                ts_ms = mkt.get('asof') or 0
                from datetime import datetime as _dt
                try:
                    ts_str = _dt.utcfromtimestamp(int(ts_ms)/1000.0).strftime("%Y-%m-%d_%H%M")
                except Exception:
                    ts_str = "now"
                import re as _re
                safe_pair = _re.sub(r"[^A-Za-z0-9._-]+", "_", str(pair_sym))
                fname = f"{safe_pair}_Report_{ts_str}.pdf"
                send_document(chat_id, fname, pdf, caption='Metridex QuickScan report (PDF)', content_type='application/pdf')
                answer_callback_query(cb_id, "PDF exported.", False)
        except Exception as e:
            answer_callback_query(cb_id, f"PDF export failed: {e}", True)
    

    elif action == "ONCHAIN":
        # MDX v4.2: robust inspector->v2 fallback (fast, Polygon-safe)
        mkt = (bundle.get('market') if isinstance(bundle, dict) else None) or {}
        # Normalize chain
        chain = (mkt.get('chain') or mkt.get('chainId') or '').strip().lower()
        if chain.isdigit():
            chain = {'1':'eth','56':'bsc','137':'polygon'}.get(chain, chain)
        if chain in ('matic','pol','poly'):
            chain = 'polygon'
        token_addr = mkt.get('tokenAddress')
        # Try cached onchain first
        _lpdbg('ONCHAIN.hit', chain=chain, token=_short_addr(token_addr), pair=_short_addr((bundle.get('market') or {}).get('pairAddress')))
        oc = (bundle.get('onchain') or None) if isinstance(bundle, dict) else None
        if not oc:
            _lpdbg('ONCHAIN.fetch', chain=chain, token=_short_addr(token_addr))
            # Try inspector first
            try:
                oc = onchain_inspector.inspect_token(chain, token_addr, mkt.get('pairAddress'))
            except Exception as _e:
                oc = {'ok': False, 'error': str(_e)}
        ok = bool((oc or {}).get('ok'))
        # If inspector failed or returned stub — fallback to v2
        if not ok or not (oc.get('codePresent') is True or oc.get('name') or (oc.get('decimals') is not None)):
            try:
                from onchain_v2 import check_contract_v2
                from renderers_onchain_v2 import render_onchain_v2
                info = check_contract_v2(chain, token_addr, timeout_s=2.5)
                text = render_onchain_v2(chain, token_addr, info)
                send_message(chat_id, text, reply_markup=build_keyboard(chat_id, 0, (bundle.get('links') if isinstance(bundle, dict) else {}), ctx='onchain'))
                answer_callback_query(cb_id, 'On-chain ready.', False)
            except Exception as _e2:
                send_message(chat_id, "On-chain\ninspection failed")
                answer_callback_query(cb_id, 'On-chain failed.', False)
        else:
            text = format_onchain_text(oc, mkt)
            # Refresh LP in bundle from inspector result (no extra RPC)
            try:
                info_lp = _lp_info_from_inspector(oc, chain, mkt.get('pairAddress'))
                try:
                    new_lp = _render_lp_compat(info_lp, DEFAULT_LANG)
                except TypeError:
                    new_lp = _render_lp_compat(info_lp, mkt, DEFAULT_LANG)
                _lpdbg('ONCHAIN.lp_refresh', used_cache=True, pair=_short_addr(mkt.get('pairAddress')), empty=not bool(new_lp))
                if isinstance(bundle, dict):
                    bundle['lp'] = new_lp
                    bundle['onchain'] = oc
                    # persist updated bundle for future callbacks
                    try:
                        store_bundle(chat_id, orig_msg_id, bundle)
                    except Exception:
                        pass
            except Exception:
                pass
            except Exception:
                pass
            send_message(chat_id, text, reply_markup=build_keyboard(chat_id, 0, (bundle.get('links') if isinstance(bundle, dict) else {}), ctx='onchain'))
            answer_callback_query(cb_id, 'On-chain ready.', False)
    elif action == "COPY_CA":
        mkt = (bundle.get("market") or {})
        token = (mkt.get("tokenAddress") or "—")
        send_message(chat_id, f"*Contract address*\n`{token}`", reply_markup=_mk_copy_keyboard(token, links))
        answer_callback_query(cb_id, "Address ready to copy.", False)

    elif action.startswith("DELTA_"):
        mkt = (bundle.get('market') or {})
        ch = (mkt.get('priceChanges') or {})
        label = {"DELTA_M5":"Δ5m","DELTA_1H":"Δ1h","DELTA_6H":"Δ6h","DELTA_24H":"Δ24h"}.get(action, "Δ")
        def _pct(v):
            try:
                n = float(v)
                arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
                return f"{arrow} {n:+.2f}%"
            except Exception:
                return "—"
        if action == "DELTA_M5":
            val = ch.get("m5")
        elif action == "DELTA_1H":
            val = ch.get("h1")
        elif action == "DELTA_6H":
            val = ch.get("h6") or ch.get("h6h") or ch.get("6h")
        else:
            val = ch.get("h24")
        send_message(chat_id, f"*{label}*: {_pct(val)}", reply_markup=None)
        answer_callback_query(cb_id, f"{label}: {_pct(val)}", False)

    else:
        answer_callback_query(cb_id, "Unsupported action", True)

    return jsonify({"ok": True})


# === INLINE DIAGNOSTICS (no shell needed) ====================================
import os as _os

from onchain_v2 import check_contract_v2
from renderers_onchain_v2 import render_onchain_v2
# Prefer enhanced/lite import above; optionally override with v2 if available
try:
    from lp_lite_v2 import check_lp_lock_v2 as _check_lp_lock_v2_new
    check_lp_lock_v2 = _check_lp_lock_v2_new
except Exception:
    pass
from onchain_inspector import build_onchain_payload
from renderers_mdx import sanitize_market_fields, age_label
def _ua():
    return _os.getenv("HTTP_UA", "MetridexDiag/1.0")
def _http_get_json(url, timeout=10, headers=None):
    import requests as _rq
    h = {"User-Agent": _ua(), "Accept": "application/json"}
    if headers: h.update(headers)
    try:
        r = _rq.get(url, timeout=timeout, headers=h)
        ctype = r.headers.get("content-type","" )
        try:
            return r.status_code, r.json(), ctype
        except Exception:
            return r.status_code, r.text, ctype
    except Exception as e:
        return 599, {"error": str(e)}, ""
def _rpc_call(rpc, method, params, timeout=8):
    import requests as _rq
    try:
        r = _rq.post(rpc, json={"jsonrpc":"2.0","id":1,"method":method,"params":params},
                     timeout=timeout, headers={"User-Agent": _ua()})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}
def _mask(s, keep=4):
    if not s: return ""
    return (s[:keep] + "…" + "*"*max(0, len(s)-keep)) if len(s) > keep else "*"*len(s)
def _diag_make(token_default="0x6982508145454Ce325dDbE47a25d4ec3d2311933"):
    try:
        from dex_client import fetch_market as _fm
        fm_ok = callable(_fm)
    except Exception:
        fm_ok = False
    try:
        from onchain_inspector import inspect_token as _it
        it_ok = callable(_it)
    except Exception:
        it_ok = False
    env = {
        "BOT_WEBHOOK_SECRET": _os.getenv("BOT_WEBHOOK_SECRET",""),
        "ENABLED_NETWORKS": _os.getenv("ENABLED_NETWORKS",""),
        "DEXSCREENER_PROXY_BASE": _os.getenv("DEXSCREENER_PROXY_BASE") or _os.getenv("DS_PROXY_BASE") or "",
        "ETH_RPC_URL_PRIMARY": _os.getenv("ETH_RPC_URL_PRIMARY",""),
        "BSC_RPC_URL_PRIMARY": _os.getenv("BSC_RPC_URL_PRIMARY",""),
        "POLYGON_RPC_URL_PRIMARY": _os.getenv("POLYGON_RPC_URL_PRIMARY",""),
        "BASE_RPC_URL_PRIMARY": _os.getenv("BASE_RPC_URL_PRIMARY",""),
        "ARB_RPC_URL_PRIMARY": _os.getenv("ARB_RPC_URL_PRIMARY",""),
        "OP_RPC_URL_PRIMARY": _os.getenv("OP_RPC_URL_PRIMARY",""),
        "AVAX_RPC_URL_PRIMARY": _os.getenv("AVAX_RPC_URL_PRIMARY",""),
        "FTM_RPC_URL_PRIMARY": _os.getenv("FTM_RPC_URL_PRIMARY",""),
        "PUBLIC_URL": _os.getenv("PUBLIC_URL") or _os.getenv("RENDER_EXTERNAL_URL") or "",
    }
    ds_direct = None; ds_proxy = None
    tok = token_default
    code, body, ctype = _http_get_json(f"https://api.dexscreener.com/latest/dex/tokens/{tok}", timeout=10)
    ds_direct = bool(code == 200 and isinstance(body, dict) and body.get("pairs"))
    proxy = (env["DEXSCREENER_PROXY_BASE"] or "").strip("/")
    if proxy:
        code2, body2, ctype2 = _http_get_json(f"{proxy}/latest/dex/tokens/{tok}", timeout=12)
        ds_proxy = bool(code2 == 200 and isinstance(body2, dict) and body2.get("pairs"))
    rpc_ok = {}
    chain_env = {
        "eth":"ETH_RPC_URL_PRIMARY", "bsc":"BSC_RPC_URL_PRIMARY", "polygon":"POLYGON_RPC_URL_PRIMARY",
        "base":"BASE_RPC_URL_PRIMARY", "arb":"ARB_RPC_URL_PRIMARY", "op":"OP_RPC_URL_PRIMARY",
        "avax":"AVAX_RPC_URL_PRIMARY", "ftm":"FTM_RPC_URL_PRIMARY",
    }
    enabled = (env["ENABLED_NETWORKS"] or "eth,bsc,polygon,base,arb,op,avax,ftm").split(",")
    for short in [x.strip() for x in enabled if x.strip()]:
        key = chain_env.get(short); rpc = env.get(key) if key else None
        if not rpc:
            rpc_ok[short] = None
            continue
        j1 = _rpc_call(rpc, "eth_chainId", [])
        j2 = _rpc_call(rpc, "eth_blockNumber", [])
        rpc_ok[short] = ("result" in j1 and "result" in j2)
    actions = []
    if not fm_ok: actions.append("dex_client.py: fetch_market() отсутствует — заменить файл.")
    if ds_direct is False and not ds_proxy: actions.append("DexScreener блокируется — задайте DEXSCREENER_PROXY_BASE (CF worker)." )
    if not any(v for v in rpc_ok.values() if v is not None): actions.append("Нет доступных RPC — заполните *_RPC_URL_PRIMARY.")
    if not it_ok: actions.append("onchain_inspector.py не найден — кнопка On-chain будет пустой.")
    summary = {
        "fetch_market_present": fm_ok,
        "onchain_present": it_ok,
        "dexscreener_direct_ok": ds_direct,
        "dexscreener_proxy_ok": ds_proxy,
        "rpc_ok": rpc_ok,
        "env_masked": {
            "BOT_WEBHOOK_SECRET": _mask(env["BOT_WEBHOOK_SECRET"]),
            "ENABLED_NETWORKS": env["ENABLED_NETWORKS"] or "(default)",
            "DEXSCREENER_PROXY_BASE": env["DEXSCREENER_PROXY_BASE"] or "(not set)",
            "PUBLIC_URL": env["PUBLIC_URL"] or "(not set)",
            "ETH_RPC_URL_PRIMARY": _mask(env["ETH_RPC_URL_PRIMARY"], keep=12),
            "BSC_RPC_URL_PRIMARY": _mask(env["BSC_RPC_URL_PRIMARY"], keep=12),
            "POLYGON_RPC_URL_PRIMARY": _mask(env["POLYGON_RPC_URL_PRIMARY"], keep=12),
            "BASE_RPC_URL_PRIMARY": _mask(env["BASE_RPC_URL_PRIMARY"], keep=12),
            "ARB_RPC_URL_PRIMARY": _mask(env["ARB_RPC_URL_PRIMARY"], keep=12),
            "OP_RPC_URL_PRIMARY": _mask(env["OP_RPC_URL_PRIMARY"], keep=12),
            "AVAX_RPC_URL_PRIMARY": _mask(env["AVAX_RPC_URL_PRIMARY"], keep=12),
            "FTM_RPC_URL_PRIMARY": _mask(env["FTM_RPC_URL_PRIMARY"], keep=12),
        },
        "next_steps": actions
    }
    return summary

@app.get("/diag")
def diag_http():
    sec = request.args.get("secret","" )
    if sec != os.getenv("DIAG_SECRET","" ):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    token = request.args.get("token") or "0x6982508145454Ce325dDbE47a25d4ec3d2311933"
    res = _diag_make(token)
    return jsonify({"ok": True, "summary": res})

def _format_diag(summary: dict) -> str:
    rpc_good = [k for k,v in (summary.get("rpc_ok") or {}).items() if v]
    lines = []
    ok = lambda b: "✅" if b else ("❌" if b is False else "—")
    lines.append(f"*fetch_market()*: {ok(summary.get('fetch_market_present'))}")
    lines.append(f"*On-chain модуль*: {ok(summary.get('onchain_present'))}")
    lines.append(f"*DexScreener direct*: {ok(summary.get('dexscreener_direct_ok'))}")
    lines.append(f"*DexScreener proxy*: {ok(summary.get('dexscreener_proxy_ok'))}")
    lines.append(f"*RPC OK*: `{','.join(rpc_good) if rpc_good else 'none'}`")
    steps = summary.get("next_steps") or []
    if steps:
        lines.append("\n*NEXT:*")
        for i,s in enumerate(steps,1):
            lines.append(f"{i}. {s}")
    return "\n".join(lines)

def _handle_diag_command(chat_id: int):
    s = _diag_make()
    txt = _format_diag(s)
    send_message(chat_id, txt, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
# === END INLINE DIAGNOSTICS ==================================================



def _mk_copy_keyboard(token: str, links: dict | None):
    links = links or {}
    kb = {"inline_keyboard": []}
    if token and token != "—":
        kb["inline_keyboard"].append([{
            "text": "📋 Copy to input",
            "switch_inline_query_current_chat": token
        }])
    nav = []
    if links.get("dex"): nav.append({"text": "🟢 Open in DEX", "url": links["dex"]})
    if links.get("scan"): nav.append({"text": "🔍 Open in Scan", "url": links["scan"]})
    if nav: kb["inline_keyboard"].append(nav)
    return kb

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8000")))




def _build_html_report(bundle: dict) -> bytes:
    """Premium dark+gold HTML report (no logos, no markdown)."""
    import html, datetime as _dt
    b = bundle or {}
    v = b.get("verdict") or {}
    m = b.get("market") or {}
    links = b.get("links") or {}
    web = b.get("webintel") or {}

    def g(d, *ks, default="n/a"):
        cur = d or {}
        for k in ks:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(k)
        return default if cur is None else cur

    def fmt_money(x):
        try:
            n = float(x)
        except Exception:
            return '<span class="muted">n/a</span>'
        a = abs(n)
        if a >= 1_000_000_000: s = f"${n/1_000_000_000:.2f}B"
        elif a >= 1_000_000:   s = f"${n/1_000_000:.2f}M"
        elif a >= 1_000:       s = f"${n/1_000:.2f}K"
        else:                  s = f"${n:.6f}" if a < 1 else f"${n:.2f}"
        return s

    def fmt_pct(x):
        try:
            n = float(x)
            arrow = "▲" if n>0 else ("▼" if n<0 else "•")
            return f"{arrow} {n:+.2f}%"
        except Exception:
            return '<span class="muted">n/a</span>'

    def fmt_chain(c):
        c = (c or "").strip().lower()
        mp = {"ethereum":"Ethereum","eth":"Ethereum","bsc":"BSC","binance smart chain":"BSC","polygon":"Polygon","matic":"Polygon",
              "arbitrum":"Arbitrum","arb":"Arbitrum","optimism":"Optimism","op":"Optimism","base":"Base","avalanche":"Avalanche",
              "avax":"Avalanche","fantom":"Fantom","ftm":"Fantom","sol":"Solana","solana":"Solana"}
        return mp.get(c, c.capitalize() if c else "—")

    def fmt_time_ms(ts):
        try:
            ts = int(ts)
            if ts < 10**12: ts *= 1000
            return _dt.datetime.utcfromtimestamp(ts/1000.0).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return "—"

    pair  = g(m, "pairSymbol", default="—")
    chain = fmt_chain(g(m, "chain", default="—"))
    price = fmt_money(g(m, "price", default=None))
    fdv   = g(m, "fdv", default=None)
    mc    = g(m, "mc", default=None)
    liq   = g(m, "liq", default=None) or g(m, "liquidityUSD", default=None)
    vol24 = g(m, "vol24h", default=None) or g(m, "volume24hUSD", default=None)
    ch5   = g(m, "priceChanges","m5", default=None)
    ch1   = g(m, "priceChanges","h1", default=None)
    ch24  = g(m, "priceChanges","h24", default=None)
    token = g(m, "tokenAddress", default="—")
    asof  = fmt_time_ms(g(m, "asof", default=None))

    whois = g(web, "whois", default={})
    ssl   = g(web, "ssl", default={})
    way   = g(web, "wayback", default={})

    kpi_fdv = fmt_money(fdv) if fdv not in (None,"n/a") else '<span class="muted">n/a</span>'
    kpi_mc  = fmt_money(mc)  if mc  not in (None,"n/a") else '<span class="muted">n/a</span>'
    kpi_liq = fmt_money(liq) if liq not in (None,"n/a") else '<span class="muted">n/a</span>'
    kpi_vol = fmt_money(vol24) if vol24 not in (None,"n/a") else '<span class="muted">n/a</span>'

    why = b.get("why") or "Why: n/a"
    whypp = b.get("whypp") or "Why++: n/a"
    lp = b.get("lp") or "LP: n/a"

    html_doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(str(pair))} — Metridex QuickScan</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body {{ background:#0b0b0f; color:#e7e7ea; font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif; margin:0; }}
.wrap {{ max-width:1024px; margin:0 auto; padding:24px; }}
h1 {{ font-weight:600; font-size:20px; margin:0 0 8px; }}
h2 {{ font-weight:600; font-size:16px; margin:24px 0 8px; color:#f0d98a; }}
.grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.card {{ background:#121218; border:1px solid #1f1f27; border-radius:12px; padding:16px; }}
.muted {{ color:#9aa0a6; }}
.badge {{ padding:2px 8px; border-radius:999px; background:#1f1f27; border:1px solid #2b2b34; font-size:12px; }}
.row {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
.kv b {{ color:#fff; }}
.btns a {{ color:#111; background:#f0d98a; padding:10px 14px; border-radius:10px; text-decoration:none; display:inline-block; }}
.btns a.secondary {{ background:#2b2b34; color:#e7e7ea; }}
pre {{ white-space:pre-wrap; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{html.escape(str(pair))} <span class="badge">{html.escape(chain)}</span></h1>
  <div class="row muted">as of {html.escape(asof)}</div>
  <div class="grid" style="margin-top:12px">
    <div class="card"><div class="kv"><div class="muted">Price</div><b>{price}</b></div><div class="muted">{fmt_pct(ch5)} • {fmt_pct(ch1)} • {fmt_pct(ch24)}</div></div>
    <div class="card"><div class="kv"><div class="muted">FDV</div><b>{kpi_fdv}</b></div></div>
    <div class="card"><div class="kv"><div class="muted">Market Cap</div><b>{kpi_mc}</b></div></div>
    <div class="card"><div class="kv"><div class="muted">Liquidity / 24h Vol</div><b>{kpi_liq}</b><div class="muted">{kpi_vol}</div></div></div>
  </div>
  <div class="card" style="margin-top:12px">
    <div class="row btns">
      {'<a href="'+html.escape(links.get('dex'))+'" target="_blank">🟢 Open in DEX</a>' if links.get('dex') else ''}
      {'<a href="'+html.escape(links.get('scan'))+'" target="_blank">🔍 Open in Scan</a>' if links.get('scan') else ''}
      {'<a href="'+html.escape(links.get('site'))+'" target="_blank" class="secondary">🌐 Website</a>' if links.get('site') else ''}
    </div>
    <div class="row" style="margin-top:8px"><span class="muted">Contract:</span> <code>{html.escape(str(token))}</code></div>
  </div>

  <h2>Why</h2>
  <div class="card"><pre>{html.escape(why.replace('*',''))}</pre></div>

  <h2>Why++</h2>
  <div class="card"><pre>{html.escape(whypp.replace('*',''))}</pre></div>

  <h2>LP lock (lite)</h2>
  <div class="card"><pre>{html.escape(lp.replace('*',''))}</pre></div>

  <h2>Website intel</h2>
  <div class="card">
    <div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr))">
      <div><div class="muted">WHOIS Created</div><b>{html.escape(str(g(whois,'created', default='n/a')))}</b></div>
      <div><div class="muted">Registrar</div><b>{html.escape(str(g(whois,'registrar', default='n/a')))}</b></div>
      <div><div class="muted">Wayback first</div><b>{html.escape(str(g(way,'first', default='n/a')))}</b></div>
    </div>
    <div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr)); margin-top:8px">
      <div><div class="muted">SSL OK</div><b>{html.escape(str(g(ssl,'ok', default='n/a')))}</b></div>
      <div><div class="muted">SSL Expires</div><b>{html.escape(str(g(ssl,'expires', default='n/a')))}</b></div>
      <div><div class="muted">SSL Issuer</div><b>{html.escape(str(g(ssl,'issuer', default='n/a')))}</b></div>
    </div>
  </div>
</div>
</body>
</html>'''
    return html_doc.encode("utf-8")


# --- Safe HTML report builder (dark, no logos) ---
def _build_html_report_safe(bundle: dict) -> bytes:
    try:
        def _s(x): 
            return str(x) if x is not None else "—"
        def _fmt_time(v):
            try:
                ts = int(v)
                if ts < 10**12:
                    ts *= 1000
                from datetime import datetime as _dt
                return _dt.utcfromtimestamp(ts/1000.0).strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                return "—"
        def _fmt_num(v, prefix="$"):
            try:
                n = float(v)
            except Exception:
                return "—"
            a = abs(n)
            if a >= 1_000_000_000: s = f"{n/1_000_000_000:.2f}B"
            elif a >= 1_000_000:  s = f"{n/1_000_000:.2f}M"
            elif a >= 1_000:      s = f"{n/1_000:.2f}K"
            else:                 s = f"{n:.6f}" if a < 1 else f"{n:.2f}"
            return prefix + s
        def _fmt_pct(v):
            try:
                n = float(v)
                arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
                return f"{arrow} {n:+.2f}%"
            except Exception:
                return "—"
        def _fmt_chain(c):
            c = (str(c) if c is not None else "—").strip().lower()
            mp = {
                "ethereum":"Ethereum","eth":"Ethereum",
                "bsc":"BSC","binance smart chain":"BSC",
                "polygon":"Polygon","matic":"Polygon",
                "arbitrum":"Arbitrum","arb":"Arbitrum",
                "optimism":"Optimism","op":"Optimism",
                "base":"Base",
                "avalanche":"Avalanche","avax":"Avalanche",
                "fantom":"Fantom","ftm":"Fantom",
                "sol":"Solana","solana":"Solana",
            }
            return mp.get(c, c.capitalize() if c else "—")
        def _fmt_age(v):
            try:
                d = float(v)
                if d < 1/24:   return "<1h"
                if d < 1:      return f"{d*24:.1f}h"
                return f"{d:.1f}d"
            except Exception:
                return "—"



        m = bundle.get("market") or {}
        v = bundle.get("verdict") or {}
        why  = bundle.get("why")  or "Why: n/a"
        whyp = bundle.get("whypp") or "Why++: n/a"
        lp   = bundle.get("lp")   or "LP: n/a"
        pair = _s(m.get("pairSymbol"))
        chain= _fmt_chain(m.get("chain"))
        price= _fmt_num(m.get("price"))
        fdv  = _fmt_num(m.get("fdv"))
        mc   = _fmt_num(m.get("mc"))
        liq  = _fmt_num(m.get("liq"))
        vol  = _fmt_num(m.get("vol24h"))
        chg5 = _fmt_pct((m.get("priceChanges") or {}).get("m5"))
        chg1 = _fmt_pct((m.get("priceChanges") or {}).get("h1"))
        chg24= _fmt_pct((m.get("priceChanges") or {}).get("h24"))
        asof = _fmt_time(m.get("asof"))
        age  = _fmt_age(m.get("ageDays"))
        score = _s((v.get("score") if isinstance(v, dict) else getattr(v, "score", None)))
        level = (v.get("level") if isinstance(v, dict) else getattr(v, "level", "")) or ""
        score_ui = ("15" if (str(score) in ("0","0.0") and str(level).lower().startswith("low")) else str(score))



        html = (
            "<!doctype html><html><head><meta charset='utf-8'/>"
            "<title>Metridex QuickScan — " + pair + "</title>"
            "<style>"
            "body{background:#0b0b0f;color:#e7e5e4;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif;margin:24px}"
            "h1{font-size:24px;margin:0 0 12px}"
            ".meta,.block pre{background:#13151a;border:1px solid #262626;border-radius:12px;padding:12px}"
            ".meta{margin:12px 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}"
            ".pill{display:inline-block;background:#1f2937;border-radius:999px;padding:3px 8px;margin-left:8px;color:#f59e0b;font-weight:600}"
            "a{color:#93c5fd}"
            "</style></head><body>"
            "<h1>Metridex QuickScan — " + pair + " <span class='pill'>Score: " + score_ui + "</span></h1>"
            "<div class='meta'>"
            "<div>Chain: " + chain + "</div><div>Price: " + price + "</div>"
            "<div>FDV: " + fdv + "</div><div>MC: " + mc + "</div>"
            "<div>Liquidity: " + liq + "</div><div>Vol 24h: " + vol + "</div>"
            "<div>Δ5m: " + chg5 + "</div><div>Δ1h: " + chg1 + "</div>"
            "<div>Δ24h: " + chg24 + "</div><div>Age: " + age + "</div><div>As of: " + asof + "</div>"
            "</div>"
            "<div class='block'><pre>" + str(why)  + "</pre></div>"
            "<div class='block'><pre>" + str(whyp) + "</pre></div>"
            "<div class='block'><pre>" + str(lp)   + "</pre></div>"
            "</body></html>"
        )
        return html.encode("utf-8")
    except Exception:
        try:
            import json as _json
            pretty = _json.dumps(bundle, ensure_ascii=False, indent=2)
        except Exception:
            pretty = str(bundle)
        html = (
            "<!doctype html><html><head><meta charset='utf-8'/>"
            "<style>body{background:#0b0b0f;color:#e7e5e4;font-family:Inter,Arial,sans-serif;margin:24px}"
            "pre{background:#13151a;border:1px solid #262626;border-radius:12px;padding:12px;white-space:pre-wrap}</style></head>"
            "<body><h1>Metridex Report (fallback)</h1><pre>" + pretty + "</pre></body></html>"
        )
        return html.encode("utf-8")


# === NOWPAYMENTS SMART INVOICE HELPER (appended) =============================
def _np_create_invoice_smart(amount_usd: float, order_id: str, order_desc: str, success_url: str, cancel_url: str, ipn_url: str, plan_key: str | None = None):
    """
    Robust NOWPayments invoice creator with low-ticket fallbacks.
    Env:
      NOWPAY_LOW_TICKET_CURRENCIES = "usdtbsc,usdtmatic,ton,trx,ltc,xrp,xlm,bnbbsc"
      NOWPAYMENTS_PAY_CURRENCY_HIGH (fallback to NOWPAYMENTS_PAY_CURRENCY) (default: "bnbbsc")
      NOWPAYMENTS_FIXED_RATE (0/1, default: 1 for high-ticket)
      NOWPAYMENTS_FEE_PAID_BY_USER (0/1, default: 1)
    """
    api_key = (os.getenv("NOWPAYMENTS_API_KEY") or "").strip()
    if not api_key:
        return {"ok": False, "error": "NOWPAYMENTS_API_KEY is not set"}

    fee_by_user = bool(int(os.getenv("NOWPAYMENTS_FEE_PAID_BY_USER", "1")))
    low_ticket = bool((plan_key or "").lower().startswith(("deep","day"))) or float(amount_usd) < 15.0

    def _try_create(pay_currency: str, is_fixed_rate: bool):
        payload = {
            "price_amount": float(amount_usd),
            "price_currency": "usd",
            "order_id": order_id,
            "order_description": order_desc,
            "is_fixed_rate": bool(is_fixed_rate),
            "is_fee_paid_by_user": fee_by_user,
            "ipn_callback_url": ipn_url,
            "pay_currency": pay_currency.lower().strip() if pay_currency else None,
        }
        if success_url: payload["success_url"] = success_url
        if cancel_url:  payload["cancel_url"]  = cancel_url
        r = _rq_np.post("https://api.nowpayments.io/v1/invoice", json=payload, timeout=12, headers={"x-api-key": api_key})
        ctype = r.headers.get("content-type","")
        try:
            j = r.json() if ctype.startswith("application/json") else {"error": r.text}
        except Exception:
            j = {"error": r.text}
        if r.ok and isinstance(j, dict) and (j.get("invoice_id") or j.get("id")):
            return {"ok": True, "json": j}
        return {"ok": False, "status": r.status_code, "json": j}

    if low_ticket:
        # Default list excludes TRC20 since it's not available in your account;
        # adjust via env NOWPAY_LOW_TICKET_CURRENCIES if needed.
        raw_list = os.getenv("NOWPAY_LOW_TICKET_CURRENCIES", "ton,usdtbsc,usdtmatic,bnbbsc,maticmainnet")
        candidates = [c.strip() for c in raw_list.split(",") if c.strip()]
        last_err = None
        for cur in candidates:
            res = _try_create(cur, is_fixed_rate=False)
            if res.get("ok"):
                return res
            j = res.get("json") or {}
            err_txt = (json.dumps(j, ensure_ascii=False) if isinstance(j, dict) else str(j)).lower()
            if ("amountto is too small" in err_txt) or ("too small" in err_txt) or ("invalid currency" in err_txt):
                last_err = res
                continue
            return res
        res = _try_create(None, is_fixed_rate=False)
        if res.get('ok'):
            return res
        return last_err or {'ok': False, 'error': 'All low-ticket currencies failed (and generic invoice failed)'}
    else:
        is_fixed = True if os.getenv("NOWPAYMENTS_FIXED_RATE") is None else bool(int(os.getenv("NOWPAYMENTS_FIXED_RATE","1")))
        pay_cur = (os.getenv("NOWPAYMENTS_PAY_CURRENCY_HIGH") or os.getenv("NOWPAYMENTS_PAY_CURRENCY") or "bnbbsc").strip().lower()
        return _try_create(pay_cur, is_fixed_rate=is_fixed)
# === /NOWPAYMENTS SMART INVOICE HELPER =======================================


# Back-compat: force any calls to _np_create_invoice to use smart variant
try:
    _np_create_invoice  # may exist
    _np_create_invoice = _np_create_invoice_smart
except NameError:
    _np_create_invoice = _np_create_invoice_smart

# D0: ensure Share button present via buttons.build_keyboard(links['share'])
