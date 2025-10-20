import hashlib
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
import onchain_inspector
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
        # RDAP
        try:
            r = _rq.get(f"https://rdap.org/domain/{domain}", timeout=2.5)
            if r.ok:
                j = r.json()
                if (who.get("created") in (None, "—")):
                    for ev in (j.get("events") or []):
                        act = str(ev.get("eventAction") or "").lower()
                        if act in ("registration","registered","creation"):
                            d = (ev.get("eventDate") or "")[:10]
                            if d:
                                who["created"] = d
                                break
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
                                        raise StopIteration
                            except StopIteration:
                                break
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
# === WATCHLIST (lite) =========================================================
WATCH_DB_PATH = os.getenv("WATCH_DB_PATH","./watch_db.json")
WATCHLIST_LIMIT = int(os.getenv("WATCHLIST_LIMIT","200"))
_last_msg_by_chat = {}

def _load_watch_db():
    try:
        with open(WATCH_DB_PATH,"r",encoding="utf-8") as f:
            j=json.load(f)
            return j if isinstance(j, dict) else {}
    except Exception:
        return {}

def _save_watch_db(db):
    try:
        with open(WATCH_DB_PATH,"w",encoding="utf-8") as f:
            json.dump(db or {}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _bundle_token_info(bundle):
    try:
        m = (bundle.get("market") or {})
        token = (m.get("tokenAddress") or "—")
        chain = (m.get("chain") or "—")
        symbol = (m.get("pairSymbol") or "")
        return token, (chain or "—"), (symbol or "")
    except Exception:
        return "—","—",""

def _watch_list(chat_id: int):
    db = _load_watch_db()
    return db.get(str(chat_id)) or []

def _watch_add(chat_id: int, token: str, chain: str, symbol: str = ""):
    db = _load_watch_db()
    arr = db.get(str(chat_id)) or []
    token = (token or "").lower()
    chain = (chain or "").lower()
    if not (token.startswith("0x") and len(token) == 42):
        return False, "Invalid token"
    if any((x.get("token") or "").lower() == token for x in arr):
        return True, "Already watching"
    if len(arr) >= WATCHLIST_LIMIT:
        return False, f"Watchlist is full ({WATCHLIST_LIMIT})."
    arr.append({"token": token, "chain": chain, "symbol": symbol})
    db[str(chat_id)] = arr
    _save_watch_db(db)
    return True, "Added"

def _watch_remove(chat_id: int, token: str):
    db = _load_watch_db()
    arr = db.get(str(chat_id)) or []
    token = (token or "").lower()
    new = [x for x in arr if (x.get("token") or "").lower() != token]
    db[str(chat_id)] = new
    _save_watch_db(db)
    return len(arr) != len(new)

def _format_watchlist_md(chat_id: int) -> str:
    lst = _watch_list(chat_id)
    if not lst:
        return "👀 *Watchlist*\n(Empty)"
    lines = ["👀 *Watchlist*"]
    for i, it in enumerate(lst, 1):
        tok = it.get("token") or "—"
        ch  = (it.get("chain") or "—").upper()
        sym = it.get("symbol") or ""
        if sym:
            lines.append(f"{i}. `{tok}` — *{sym}* ({ch})")
        else:
            lines.append(f"{i}. `{tok}` ({ch})")
    return "\n".join(lines)
# === /WATCHLIST ===============================================================
# === WATCH ALERTS (lite) ======================================================
WATCH_ALERTS_ENABLED = int(os.getenv("WATCH_ALERTS_ENABLED","1"))
WATCH_ALERTS_INTERVAL_MIN = int(os.getenv("WATCH_ALERTS_INTERVAL_MIN","15"))
ALERTS_D5M = float(os.getenv("ALERTS_D5M","2"))
ALERTS_D1H = float(os.getenv("ALERTS_D1H","5"))
ALERTS_D24H = float(os.getenv("ALERTS_D24H","10"))
ALERTS_VOL24 = float(os.getenv("ALERTS_VOL24","250000"))  # USD
ALERTS_COOLDOWN_MIN = int(os.getenv("ALERTS_COOLDOWN_MIN","60"))
WATCH_STATE_PATH = os.getenv("WATCH_STATE_PATH","./watch_state.json")

def _load_watch_state():
    try:
        with open(WATCH_STATE_PATH,"r",encoding="utf-8") as f:
            j=json.load(f)
            return j if isinstance(j, dict) else {}
    except Exception:
        return {}

def _save_watch_state(st):
    try:
        with open(WATCH_STATE_PATH,"w",encoding="utf-8") as f:
            json.dump(st or {}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _fmt_usd(x):
    try:
        x = float(x or 0)
    except Exception:
        return "—"
    if x >= 1_000_000:
        return f"${x/1_000_000:.2f}M"
    if x >= 1_000:
        return f"${x/1_000:.1f}k"
    return f"${x:.0f}"

def _num(x):
    # Convert percent string/number to float
    try:
        if isinstance(x, str):
            x = x.strip().replace("%","")
        return float(x)
    except Exception:
        return 0.0

def _state_for_chat(st, chat_id):
    s = st.get(str(chat_id))
    if not isinstance(s, dict):
        s = {"enabled": True, "last_run": 0, "last": {}}
        st[str(chat_id)] = s
    s.setdefault("enabled", True)
    s.setdefault("last_run", 0)
    s.setdefault("last", {})
    return s

def _should_notify(last_ts, now_ts, cooldown_min):
    try:
        return (now_ts - (last_ts or 0)) >= cooldown_min*60
    except Exception:
        return True

def _tick_watch_alerts(force=False):
    if not WATCH_ALERTS_ENABLED:
        return
    now = int(time.time())
    st = _load_watch_state()
    db = _load_watch_db()
    # Global throttle per file to avoid too frequent scans
    g = st.get("__global__", {"last_run": 0})
    if not force and now - int(g.get("last_run", 0)) < WATCH_ALERTS_INTERVAL_MIN*60:
        return
    g["last_run"] = now
    st["__global__"] = g

    for chat_id_str, items in db.items():
        try:
            chat_id = int(chat_id_str)
        except Exception:
            continue
        chat_state = _state_for_chat(st, chat_id)
        if not chat_state.get("enabled", True):
            continue
        th = _get_chat_thresholds(chat_id)
        if not force and now - int(chat_state.get("last_run", 0)) < th.get("interval", WATCH_ALERTS_INTERVAL_MIN)*60:
            continue
        last_map = chat_state.get("last") or {}

        for it in (items or []):
            token = (it.get("token") or "").lower()
            if not (token.startswith("0x") and len(token)==42):
                continue
            try:
                mkt = fetch_market(token) or {}
            except Exception as e:
                print("ALERT fetch_market error", token, e, traceback.format_exc())
                mkt = {}
            if not mkt:
                continue

            pc = mkt.get("priceChanges") or {}
            d5  = _num(pc.get("m5") or pc.get("5m") or 0)
            d1h = _num(pc.get("h1") or pc.get("1h") or 0)
            d24 = _num(pc.get("h24") or pc.get("24h") or 0)
            vol = mkt.get("volume24hUsd") or mkt.get("vol24hUsd") or mkt.get("volume24h") or 0
            try:
                vol = float(vol)
            except Exception:
                vol = 0.0

            sym = mkt.get("pairSymbol") or mkt.get("symbol") or ""
            chain = (mkt.get("chain") or "").upper() or (it.get("chain") or "—").upper()
            pair = mkt.get("pairAddress") or ""
            dex_url = mkt.get("dexUrl") or ""
            scan_url = mkt.get("scanUrl") or _explorer_url(chain, token) or ""

            lm = last_map.get(token) or {}
            # Cooldowns by metric
            t_last_d5  = int(lm.get("d5", 0))
            t_last_d1h = int(lm.get("d1h", 0))
            t_last_d24 = int(lm.get("d24", 0))
            t_last_vol = int(lm.get("vol", 0))

            alerts = []
            if abs(d5) >= ALERTS_D5M and _should_notify(t_last_d5, now, ALERTS_COOLDOWN_MIN):
                alerts.append(f"Δ5m {d5:+.2f}%")
                lm["d5"] = now
            if abs(d1h) >= ALERTS_D1H and _should_notify(t_last_d1h, now, ALERTS_COOLDOWN_MIN):
                alerts.append(f"Δ1h {d1h:+.2f}%")
                lm["d1h"] = now
            if abs(d24) >= ALERTS_D24H and _should_notify(t_last_d24, now, ALERTS_COOLDOWN_MIN):
                alerts.append(f"Δ24h {d24:+.2f}%")
                lm["d24"] = now
            if vol >= ALERTS_VOL24 and _should_notify(t_last_vol, now, ALERTS_COOLDOWN_MIN):
                alerts.append(f"Vol24h {_fmt_usd(vol)}")
                lm["vol"] = now

            if alerts:
                title = f"👀 *Watch alert* — *{sym or token[:6]}* ({chain})"
                body  = " • ".join(alerts)
                msg = f"{title}\n{body}"
                try:
                    kb = _alert_keyboard(dex_url, scan_url, token)
                    send_message(chat_id, msg, reply_markup=kb)
                except Exception as e:
                    print("ALERT send_message error", e)
                last_map[token] = lm

        chat_state["last"] = last_map
        chat_state["last_run"] = now
        st[str(chat_id)] = chat_state

    _save_watch_state(st)

# Commands for alerts
def _toggle_alerts(chat_id, enable: bool):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    cs["enabled"] = bool(enable)
    st[str(chat_id)] = cs
    _save_watch_state(st)
    return cs

def _alerts_status_md(chat_id):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    enabled = cs.get("enabled", True)
    th = _get_chat_thresholds(chat_id)
    return (
        "🔔 *Alerts*: ON\n"
        if enabled else
        "🔕 *Alerts*: OFF\n"
    ) + (
        f"Interval: {th.get('interval')}m • Cooldown: {th.get('cooldown')}m\n"
        f"Thresholds: Δ5m≥{th.get('d5'):.1f}% • Δ1h≥{th.get('d1h'):.1f}% • Δ24h≥{th.get('d24'):.1f}% • Vol24h≥{_fmt_usd(th.get('vol'))}"
    )
# === /WATCH ALERTS ============================================================
def _alert_keyboard(dex_url: str, scan_url: str, token: str):
    try:
        rows = []
        row = []
        if dex_url:
            row.append({"text": "🟢 Open in DEX", "url": dex_url})
        if scan_url:
            row.append({"text": "🔍 Open in Scan", "url": scan_url})
        if row:
            rows.append(row)
        if token and token.startswith("0x") and len(token) == 42:
            rows.append([{"text": "👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
        return {"inline_keyboard": rows} if rows else None
    except Exception:
        return None

def _get_chat_thresholds(chat_id):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    th = cs.get("th") or {}
    try:
        return {
            "d5": float(th.get("d5", ALERTS_D5M)),
            "d1h": float(th.get("d1h", ALERTS_D1H)),
            "d24": float(th.get("d24", ALERTS_D24H)),
            "vol": float(th.get("vol", ALERTS_VOL24)),
            "interval": int(th.get("interval", WATCH_ALERTS_INTERVAL_MIN)),
            "cooldown": int(th.get("cooldown", ALERTS_COOLDOWN_MIN)),
        }
    except Exception:
        return {
            "d5": ALERTS_D5M, "d1h": ALERTS_D1H, "d24": ALERTS_D24H,
            "vol": ALERTS_VOL24, "interval": WATCH_ALERTS_INTERVAL_MIN,
            "cooldown": ALERTS_COOLDOWN_MIN
        }

def _set_chat_thresholds(chat_id, **kwargs):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    th = cs.get("th") or {}
    th.update({k:v for k,v in kwargs.items() if v is not None})
    cs["th"] = th
    st[str(chat_id)] = cs
    _save_watch_state(st)
    return th

def _parse_amount(val: str):
    try:
        s = str(val).strip().lower().replace("%","").replace("$","")
        mult = 1.0
        if s.endswith("k"):
            mult, s = 1000.0, s[:-1]
        elif s.endswith("m"):
            mult, s = 1_000_000.0, s[:-1]
        return float(s) * mult
    except Exception:
        return None



def send_message(chat_id, text, reply_markup=None, parse_mode='Markdown', disable_web_page_preview=None):
    data = {"chat_id": chat_id, "text": mdv2_escape(str(text)), "parse_mode": PARSE_MODE}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

def send_message_raw(chat_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "text": str(text)}
    if reply_markup: data["reply_markup"] = json.dumps(reply_markup)
    return tg("sendMessage", data)

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

def on_message(msg):
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    low = text.lower()

    # Absolute early return on /start to avoid any accidental fallthrough
    if low == "/start":
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})


    if low.startswith("/start"):
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

    # Only non-command messages trigger scan

    # --- Watchlist commands (lite) ---
    if low.startswith("/watchlist"):
        txt = _format_watchlist_md(chat_id)
        send_message(chat_id, txt)
        return jsonify({"ok": True})

    if low.startswith("/watch"):
        parts = text.split()
        token_arg = parts[1].strip() if len(parts) > 1 else None
        if token_arg and token_arg.lower().startswith("0x") and len(token_arg) in (42,66):
            last_id = _last_msg_by_chat.get(chat_id)
            bndl = load_bundle(chat_id, last_id) if last_id else {}
            _, chain_guess, sym_guess = _bundle_token_info(bndl or {})
            ok_, msg_ = _watch_add(chat_id, token_arg[:42], chain_guess or "eth", sym_guess or "")
            send_message(chat_id, f"👀 *Watch*: {msg_}\n`{token_arg[:42]}`")
            return jsonify({"ok": True})
        last_id = _last_msg_by_chat.get(chat_id)
        bndl = load_bundle(chat_id, last_id) if last_id else {}
        token, chain, sym = _bundle_token_info(bndl or {})
        if token and token.startswith("0x") and len(token) == 42:
            ok_, msg_ = _watch_add(chat_id, token, chain or "eth", sym or "")
            send_message(chat_id, f"👀 *Watch*: {msg_}\n`{token}`")
        else:
            send_message(chat_id, "👀 *Watch*: nothing to add — send a token first.")
        return jsonify({"ok": True})

    if low.startswith("/unwatch"):
        parts = text.split()
        token_arg = parts[1].strip() if len(parts) > 1 else None
        if not token_arg:
            last_id = _last_msg_by_chat.get(chat_id)
            bndl = load_bundle(chat_id, last_id) if last_id else {}
            token_arg, _, _ = _bundle_token_info(bndl or {})
        if token_arg and token_arg.startswith("0x") and len(token_arg) == 42:
            removed = _watch_remove(chat_id, token_arg[:42])
            msg_ = "Removed" if removed else "Not found"
            send_message(chat_id, f"👀 *Unwatch*: {msg_}\n`{token_arg[:42]}`")
        else:
            send_message(chat_id, "👀 *Unwatch*: specify a token, e.g. /unwatch 0x…")
        return jsonify({"ok": True})
    # --- /Watchlist commands ---

    # --- Alerts commands (lite) ---
    if low.startswith("/alerts_on"):
        _toggle_alerts(chat_id, True)
        send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
        return jsonify({"ok": True})

    if low.startswith("/alerts_off"):
        _toggle_alerts(chat_id, False)
        send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
        return jsonify({"ok": True})

    if low.startswith("/alerts"):
        send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
        return jsonify({"ok": True})
    # --- /Alerts commands ---

    # --- Alerts config (lite) ---
    if low.startswith("/alerts_set"):
        parts = text.split()[1:]
        if parts and parts[0].lower() == "reset":
            _set_chat_thresholds(chat_id, d5=None, d1h=None, d24=None, vol=None, interval=None, cooldown=None)
            send_message(chat_id, "🔄 *Alerts settings reset*")
            send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
            return jsonify({"ok": True})
        update = {}
        keymap = {"d5":"d5","d1h":"d1h","d24":"d24","vol":"vol","int":"interval","interval":"interval","cd":"cooldown","cooldown":"cooldown"}
        for p in parts:
            if "=" not in p: 
                continue
            k, v = p.split("=", 1)
            k = (k or "").lower().strip()
            v = (v or "").strip()
            kk = keymap.get(k)
            if not kk:
                continue
            val = _parse_amount(v)
            if val is None:
                continue
            update[kk] = float(val)
        if update:
            _set_chat_thresholds(chat_id, **update)
            send_message(chat_id, "✅ *Alerts updated*")
        else:
            send_message(chat_id, "ℹ️ Usage: /alerts_set d5=2 d1h=5 d24=10 vol=250k int=15 cd=60")
        send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
        return jsonify({"ok": True})
    # --- /Alerts config ---
    if text.startswith("/"):
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

        try:
            _tick_watch_alerts()
        except Exception:
            pass

    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted. Use /upgrade.", reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    # --- Strict input guard: only proceed if a token address or URL with token is present ---
    _addr = None
    try:
        m = re.search(r'0x[0-9a-fA-F]{40}', text)
        if m:
            _addr = m.group(0)
        else:
            # Extract from common DEX/scan URLs
            m = re.search(r'(?:address|token|outputCurrency|inputCurrency)=0x([0-9a-fA-F]{40})', text)
            if m:
                _addr = '0x' + m.group(1)
    except Exception:
        _addr = None

    if not _addr:
        # No clear token → show usage hint and exit early without scanning
        send_message(chat_id, build_hint_quickscan(HINT_CLICKABLE_LINKS), reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})
    # normalize text to extracted address
    text = _addr
    # --- /Strict input guard ---
    # --- Processing indicator (safe, minimal) ---
    ph = send_message(chat_id, "Processing…")
    ph_id = ph.get("result", {}).get("message_id") if isinstance(ph, dict) and ph.get("ok") else None
    try:
        tg("sendChatAction", {"chat_id": chat_id, "action": "typing"})
    except Exception:
        pass
    # --- /Processing indicator ---


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

    try:
        ch_ = (market.get("chain") or "").lower()
        _map = {"ethereum":"eth","bsc":"bsc","polygon":"polygon","arbitrum":"arb","optimism":"op","base":"base","avalanche":"avax","fantom":"ftm"}
        _short = _map.get(ch_, ch_ or "eth")
        pair_addr = market.get("pairAddress") or resolve_pair(_short, market.get("tokenAddress"))
        info = check_lp_lock_v2(_short, pair_addr)
        try:
            if isinstance(info, dict) and not info.get('chain'):
                info['chain'] = _short
        except Exception:
            pass
        lp = render_lp(info, DEFAULT_LANG)
    except TypeError:
        lp = render_lp({"provider":"lite-burn-check","lpAddress": market.get("pairAddress"), "until": "—"})
    except Exception:
        lp = "LP lock: unknown"

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
        "details": details, "why": why, "whypp": whypp, "lp": lp, "webintel": web
    }

    sent = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, 0, links))
    msg_id = sent.get("result", {}).get("message_id") if sent.get("ok") else None
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
        try:
            _last_msg_by_chat[chat_id] = msg_id
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
    
    # --- /Remove processing indicator ---
    register_scan(chat_id)
    return jsonify({"ok": True})


def on_callback(cb):
    try:
        _tick_watch_alerts()
    except Exception:
        pass
    # Quick handler for UNWATCH from alert cards (no bundle required)
    data = cb.get("data") or ""
    cb_id = cb["id"]
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    if isinstance(data, str) and data.startswith("UNWATCH_T:"):
        tok = data.split(":",1)[1][:42]
        removed = _watch_remove(chat_id, tok)
        send_message(chat_id, f"👀 *Unwatch*: {'Removed' if removed else 'Not found'}\n`{tok}`")
        answer_callback_query(cb_id, "Removed from Watchlist." if removed else "Token not found.", False)
        return jsonify({"ok": True})
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    current_msg_id = msg.get("message_id")

    m = parse_cb(data)
    if not m:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})
    action, orig_msg_id, orig_chat_id = m

    if orig_msg_id == 0:
        orig_msg_id = current_msg_id

    if chat_id != orig_chat_id and orig_chat_id != 0:
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

    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details", "(no details)"),
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))

    elif action == "WHY":
        txt = bundle.get("why") or "*Why?*\n• No specific risk factors detected"
        send_message(chat_id, txt, reply_markup=None)
        answer_callback_query(cb_id, "Why? posted.", False)

    elif action == "WHYPP":
        txt = bundle.get("whypp") or "*Why++* n/a"
        MAX = 3500
        if len(txt) <= MAX:
            send_message(chat_id, txt, reply_markup=None)
        else:
            chunk = txt[:MAX]
            txt = txt[MAX:]
            send_message(chat_id, chunk, reply_markup=None)
            i = 1
            while txt:
                i += 1
                chunk_part = txt[:MAX]
                txt = txt[MAX:]
                prefix = f"Why++ ({i})\n"
                send_message(chat_id, prefix + chunk_part, reply_markup=None)
        answer_callback_query(cb_id, "Why++ posted.", False)

    elif action == "LP":
        text = bundle.get("lp", "LP lock: n/a")
        send_message(chat_id, text, reply_markup=None)
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
                send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, bundle.get('links') if isinstance(bundle, dict) else {}, ctx='onchain'))
                answer_callback_query(cb_id, 'On-chain ready.', False)
            except Exception as _e2:
                send_message(chat_id, "On-chain\ninspection failed")
                answer_callback_query(cb_id, 'On-chain failed.', False)
        else:
            text = format_onchain_text(oc, mkt)
            send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, bundle.get('links') if isinstance(bundle, dict) else {}, ctx='onchain'))
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

    elif action == "WATCH":
        bndl = load_bundle(chat_id, orig_msg_id) or {}
        token, chain, sym = _bundle_token_info(bndl)
        if token and token.startswith("0x") and len(token) == 42:
            ok_, msg_ = _watch_add(chat_id, token, (chain or "eth"), sym or "")
            send_message(chat_id, f"👀 *Watch*: {msg_}\n`{token}`", reply_markup=None)
            answer_callback_query(cb_id, "Added to Watchlist." if ok_ else msg_, False)
        else:
            send_message(chat_id, "👀 *Watch*: nothing to add — send a token first.")
            answer_callback_query(cb_id, "No token found.", False)

    elif action == "UNWATCH":
        bndl = load_bundle(chat_id, orig_msg_id) or {}
        token, _, _ = _bundle_token_info(bndl)
        if token and token.startswith("0x") and len(token) == 42:
            removed = _watch_remove(chat_id, token)
            send_message(chat_id, f"👀 *Unwatch*: {'Removed' if removed else 'Not found'}\n`{token}`", reply_markup=None)
            answer_callback_query(cb_id, "Removed from Watchlist." if removed else "Token not found.", False)
        else:
            send_message(chat_id, "👀 *Unwatch*: specify a token.", reply_markup=None)
            answer_callback_query(cb_id, "No token found.", False)

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

def _explorer_url(chain: str, token: str):
    try:
        ch = (chain or "").lower()
        if not token or not token.startswith("0x") or len(token)!=42:
            return None
        if ch in ("eth","ethereum"):
            return f"https://etherscan.io/token/{token}"
        if ch in ("bsc","bnb","binance"):
            return f"https://bscscan.com/token/{token}"
        if ch in ("polygon","matic"):
            return f"https://polygonscan.com/token/{token}"
        return None
    except Exception:
        return None
# =================== EXTENSION: presets & mute (non-invasive) =================
try:
    _orig_alerts_status_md = _alerts_status_md
except NameError:
    def _orig_alerts_status_md(chat_id): return "N/A"

try:
    _orig_tick_watch_alerts = _tick_watch_alerts
except NameError:
    def _orig_tick_watch_alerts(force=False): return None

try:
    _orig_on_callback = on_callback
except NameError:
    def _orig_on_callback(cb): return jsonify({"ok": True})

try:
    _orig_on_message = on_message
except NameError:
    def _orig_on_message(msg): return jsonify({"ok": True})

def _preset_thresholds(name: str):
    n = (name or "").strip().lower()
    if n == "fast":
        return {"d5": 1.0, "d1h": 3.0, "d24": 6.0, "vol": 100_000.0, "interval": 10, "cooldown": 45}
    if n == "calm":
        return {"d5": 3.0, "d1h": 7.0, "d24": 15.0, "vol": 500_000.0, "interval": 20, "cooldown": 90}
    return {"d5": 2.0, "d1h": 5.0, "d24": 10.0, "vol": 250_000.0, "interval": 15, "cooldown": 60}

def _mute_chat(chat_id, minutes: int):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    now = int(time.time())
    cs["mute_until"] = now + max(1, int(minutes))*60
    st[str(chat_id)] = cs
    _save_watch_state(st)
    return cs.get("mute_until")

def _unmute_chat(chat_id):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    cs["mute_until"] = 0
    st[str(chat_id)] = cs
    _save_watch_state(st)

def _fmt_until(ts):
    try:
        if not ts:
            return "—"
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(ts)))
    except Exception:
        return "—"

def _ensure_alert_keyboard():
    # define keyboard helpers if not present
    if "_alert_keyboard" in globals(): 
        return
    def _alert_keyboard(dex_url: str, scan_url: str, token: str):
        try:
            rows = []
            row = []
            if dex_url:
                row.append({"text": "🟢 Open in DEX", "url": dex_url})
            if scan_url:
                row.append({"text": "🔍 Open in Scan", "url": scan_url})
            if row:
                rows.append(row)
            if token and isinstance(token, str) and token.startswith("0x") and len(token)==42:
                rows.append([{"text": "👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
            rows.append([{"text": "🔕 Mute 24h", "callback_data": "ALERTS_MUTE:24h"}, {"text": "🔔 Unmute", "callback_data": "ALERTS_UNMUTE"}])
            return {"inline_keyboard": rows} if rows else None
        except Exception:
            return None
    globals()['_alert_keyboard'] = _alert_keyboard

    if "_explorer_url" not in globals():
        def _explorer_url(chain: str, token: str):
            try:
                ch = (chain or "").lower()
                if not token or not token.startswith("0x") or len(token)!=42:
                    return None
                if ch in ("eth","ethereum"):
                    return f"https://etherscan.io/token/{token}"
                if ch in ("bsc","bnb","binance"):
                    return f"https://bscscan.com/token/{token}"
                if ch in ("polygon","matic"):
                    return f"https://polygonscan.com/token/{token}"
                return None
            except Exception:
                return None
        globals()['_explorer_url'] = _explorer_url

def _alerts_status_md(chat_id):
    st = _load_watch_state()
    cs = _state_for_chat(st, chat_id)
    enabled = cs.get("enabled", True)
    th = _get_chat_thresholds(chat_id)
    mute_until = cs.get("mute_until", 0)
    mute_line = (f"Muted until: {_fmt_until(mute_until)}\n" if mute_until and mute_until>int(time.time()) else "")
    return (
        "🔔 *Alerts*: ON\n"
        if enabled else
        "🔕 *Alerts*: OFF\n"
    ) + (
        f"{mute_line}"
        f"Interval: {th.get('interval')}m • Cooldown: {th.get('cooldown')}m\n"
        f"Thresholds: Δ5m≥{th.get('d5'):.1f}% • Δ1h≥{th.get('d1h'):.1f}% • Δ24h≥{th.get('d24'):.1f}% • Vol24h≥{_fmt_usd(th.get('vol'))}"
    )

def _tick_watch_alerts(force=False):
    # Enhanced ticker with per-chat intervals, mute, and buttons
    if not WATCH_ALERTS_ENABLED:
        return
    now = int(time.time())
    st = _load_watch_state()
    db = _load_watch_db()
    g = st.get("__global__", {"last_run": 0})
    if not force and now - int(g.get("last_run", 0)) < WATCH_ALERTS_INTERVAL_MIN*60:
        return
    g["last_run"] = now
    st["__global__"] = g

    _ensure_alert_keyboard()

    for chat_id_str, items in db.items():
        try:
            chat_id = int(chat_id_str)
        except Exception:
            continue
        chat_state = _state_for_chat(st, chat_id)
        if not chat_state.get("enabled", True):
            continue
        th = _get_chat_thresholds(chat_id)
        mu = int(chat_state.get("mute_until", 0))
        if mu and now < mu:
            continue
        if not force and now - int(chat_state.get("last_run", 0)) < th.get("interval", WATCH_ALERTS_INTERVAL_MIN)*60:
            continue
        last_map = chat_state.get("last") or {}

        for it in (items or []):
            token = (it.get("token") or "").lower()
            if not (token.startswith("0x") and len(token)==42):
                continue
            try:
                mkt = fetch_market(token) or {}
            except Exception:
                mkt = {}
            if not mkt:
                continue

            pc = mkt.get("priceChanges") or {}
            d5  = float(str(pc.get("m5") or pc.get("5m") or 0).replace("%","") or 0)
            d1h = float(str(pc.get("h1") or pc.get("1h") or 0).replace("%","") or 0)
            d24 = float(str(pc.get("h24") or pc.get("24h") or 0).replace("%","") or 0)
            vol = mkt.get("volume24hUsd") or mkt.get("vol24hUsd") or mkt.get("volume24h") or 0
            try: vol = float(vol)
            except Exception: vol = 0.0

            sym = mkt.get("pairSymbol") or mkt.get("symbol") or ""
            chain = (mkt.get("chain") or "").upper() or (it.get("chain") or "—").upper()
            dex_url = mkt.get("dexUrl") or ""
            scan_url = mkt.get("scanUrl") or _explorer_url(chain, token) or ""

            lm = last_map.get(token) or {}
            t_last_d5  = int(lm.get("d5", 0)); t_last_d1h = int(lm.get("d1h", 0)); t_last_d24 = int(lm.get("d24", 0)); t_last_vol = int(lm.get("vol", 0))

            alerts = []
            if abs(d5) >= th.get("d5", ALERTS_D5M) and _should_notify(t_last_d5, now, th.get("cooldown", ALERTS_COOLDOWN_MIN)):
                alerts.append(f"Δ5m {d5:+.2f}%"); lm["d5"] = now
            if abs(d1h) >= th.get("d1h", ALERTS_D1H) and _should_notify(t_last_d1h, now, th.get("cooldown", ALERTS_COOLDOWN_MIN)):
                alerts.append(f"Δ1h {d1h:+.2f}%"); lm["d1h"] = now
            if abs(d24) >= th.get("d24", ALERTS_D24H) and _should_notify(t_last_d24, now, th.get("cooldown", ALERTS_COOLDOWN_MIN)):
                alerts.append(f"Δ24h {d24:+.2f}%"); lm["d24"] = now
            if vol >= th.get("vol", ALERTS_VOL24) and _should_notify(t_last_vol, now, th.get("cooldown", ALERTS_COOLDOWN_MIN)):
                alerts.append(f"Vol24h {_fmt_usd(vol)}"); lm["vol"] = now

            if alerts:
                title = f"👀 *Watch alert* — *{sym or token[:6]}* ({chain})"
                body  = " • ".join(alerts)
                msg = f"{title}\n{body}"
                try:
                    kb = _alert_keyboard(dex_url, scan_url, token)
                    send_message(chat_id, msg, reply_markup=kb)
                except Exception as e:
                    print("ALERT send_message error", e)
                last_map[token] = lm

        chat_state["last"] = last_map
        chat_state["last_run"] = now
        st[str(chat_id)] = chat_state

    _save_watch_state(st)

def on_callback(cb):
    try:
        _tick_watch_alerts()
    except Exception:
        pass
    cb_id = cb["id"]
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    current_msg_id = msg.get("message_id")

    # Fast shortcuts
    if isinstance(data, str) and data.startswith("UNWATCH_T:"):
        tok = data.split(":",1)[1][:42]
        removed = _watch_remove(chat_id, tok)
        send_message(chat_id, f"👀 *Unwatch*: {'Removed' if removed else 'Not found'}\n`{tok}`")
        answer_callback_query(cb_id, "Removed from Watchlist." if removed else "Token not found.", False)
        return jsonify({"ok": True})

    
    if isinstance(data, str) and data.startswith("ALERTS_PRESET:"):
        name = data.split(":",1)[1] or "normal"
        _set_chat_thresholds(chat_id, **_preset_thresholds(name))
        answer_callback_query(cb_id, f"Preset: {name}", False)
        send_message(chat_id, f"✅ *Preset applied*: {name}")
        send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
        return jsonify({"ok": True})
    if isinstance(data, str) and data.startswith("ALERTS_MUTE:"):
        arg = data.split(":",1)[1]
        minutes = 1440 if arg == "24h" else (480 if arg == "8h" else (60 if arg == "1h" else 60))
        until = _mute_chat(chat_id, minutes)
        answer_callback_query(cb_id, "Muted", False)
        send_message(chat_id, f"🔕 *Alerts muted* until {_fmt_until(until)}")
        return jsonify({"ok": True})

    if data == "ALERTS_UNMUTE":
        _unmute_chat(chat_id)
        answer_callback_query(cb_id, "Unmuted", False)
        send_message(chat_id, "🔔 *Alerts unmuted*")
        return jsonify({"ok": True})

    # Fallback to original
    return _orig_on_callback(cb)

# Wrap on_message to add new commands without touching original logic
def on_message(msg):
    # Hard guard: do not trigger any post-actions on /start|/help|/upgrade
    try:
        chat_id = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()
        low = text.lower()
        if low.startswith("/start") or low.startswith("/help") or low.startswith("/upgrade"):
            return _orig_on_message(msg)
    except Exception:
        pass

    try:
        chat_id = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()
        low = text.lower()
        if not text:
            return _orig_on_message(msg)

        if low.startswith("/alerts_mute"):
            parts = text.split()
            mins = 1440
            if len(parts)>1 and parts[1].isdigit():
                mins = int(parts[1])
            until = _mute_chat(chat_id, mins)
            send_message(chat_id, f"🔕 *Alerts muted* until {_fmt_until(until)}")
            return jsonify({"ok": True})

        if low.startswith("/alerts_unmute"):
            _unmute_chat(chat_id)
            send_message(chat_id, "🔔 *Alerts unmuted*")
            return jsonify({"ok": True})

        if low.startswith("/alerts_set"):
            parts = text.split()[1:]
            if parts and parts[0].lower() in ("preset","presets"):
                name = (parts[1] if len(parts)>1 else "normal").lower()
                _set_chat_thresholds(chat_id, **_preset_thresholds(name))
                send_message(chat_id, f"✅ *Preset applied*: {name}")
                send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
                return jsonify({"ok": True})
            if parts and parts[0].lower() == "reset":
                _set_chat_thresholds(chat_id, d5=None, d1h=None, d24=None, vol=None, interval=None, cooldown=None)
                send_message(chat_id, "🔄 *Alerts settings reset*")
                send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
                return jsonify({"ok": True})
            # parse key=value pairs
            update = {}
            keymap = {"d5":"d5","d1h":"d1h","d24":"d24","vol":"vol","int":"interval","interval":"interval","cd":"cooldown","cooldown":"cooldown"}
            def _parse_amount(val: str):
                try:
                    s = str(val).strip().lower().replace("%","").replace("$","")
                    mult = 1.0
                    if s.endswith("k"):
                        mult, s = 1000.0, s[:-1]
                    elif s.endswith("m"):
                        mult, s = 1_000_000.0, s[:-1]
                    return float(s) * mult
                except Exception:
                    return None
            for p in parts:
                if "=" not in p: 
                    continue
                k, v = p.split("=", 1)
                kk = keymap.get(k.strip().lower())
                if not kk:
                    continue
                val = _parse_amount(v)
                if val is None:
                    continue
                update[kk] = float(val)
            if update:
                _set_chat_thresholds(chat_id, **update)
                send_message(chat_id, "✅ *Alerts updated*")
            else:
                send_message(chat_id, "ℹ️ Usage: /alerts_set d5=2 d1h=5 d24=10 vol=250k int=15 cd=60\nOr: /alerts_set preset fast|normal|calm")
            send_message(chat_id, _alerts_status_md(chat_id), reply_markup=_alerts_control_keyboard())
            return jsonify({"ok": True})

        # fallthrough: use original handler
        # --- POST-ACTIONS: watch/watchlist ---
        if low.startswith("/watch") or low.startswith("/watchlist"):
            # capture before state
            before_tokens = set((x.get("token") or "").lower() for x in (_watch_list(chat_id) or []))
            res = _orig_on_message(msg)
            after = _watch_list(chat_id) or []

            if low.startswith("/watch"):
                # try to find newly added token, else use arg or last in list
                parts = text.split()
                arg_tok = parts[1].strip() if len(parts) > 1 else None
                new = [ (x.get("token") or "").lower() for x in after if (x.get("token") or "").lower() not in before_tokens ]
                tok = (new[-1] if new else (arg_tok or (after[-1].get("token") if after else None)))
                if tok:
                    tok = tok[:42]
                    ch = "eth"
                    for x in reversed(after):
                        if (x.get("token") or "").lower() == tok.lower():
                            ch = x.get("chain") or ch
                            break
                    try:
                        m = fetch_market(tok) or {}
                    except Exception:
                        m = {}
                    dex_url = (m.get("dexUrl") or "")
                    scan_url = (m.get("scanUrl") or _explorer_url(ch, tok) or "")
                    kb = _alert_keyboard(dex_url, scan_url, tok)
                    if kb:
                        send_message(chat_id, "Quick actions", reply_markup=kb)
                return res

            # /watchlist: show action buttons for up to 5 первых токенов
            toks = [(x.get("token"), x.get("chain") or "eth") for x in after[:5]]
            kb = _tokens_actions_keyboard(toks)
            if kb:
                send_message(chat_id, "Quick actions", reply_markup=kb)
            return res

        return _orig_on_message(msg)
    except Exception:
        return _orig_on_message(msg)
# ================= /EXTENSION =================================================

def _alerts_control_keyboard():
    try:
        return {
            "inline_keyboard": [
                [
                    {"text": "Fast", "callback_data": "ALERTS_PRESET:fast"},
                    {"text": "Normal", "callback_data": "ALERTS_PRESET:normal"},
                    {"text": "Calm", "callback_data": "ALERTS_PRESET:calm"}
                ],
                [
                    {"text": "Mute 1h", "callback_data": "ALERTS_MUTE:1h"},
                    {"text": "Mute 8h", "callback_data": "ALERTS_MUTE:8h"},
                    {"text": "Mute 24h", "callback_data": "ALERTS_MUTE:24h"}
                ],
                [
                    {"text": "Unmute", "callback_data": "ALERTS_UNMUTE"}
                ]
            ]
        }
    except Exception:
        return None

def _tokens_actions_keyboard(tokens):
    # tokens: list of (token, chain)
    rows = []
    for token, chain in (tokens or []):
        dex_url = ""
        scan_url = _explorer_url(chain, token) or ""
        try:
            m = fetch_market(token) or {}
            dex_url = m.get("dexUrl") or dex_url
            scan_url = m.get("scanUrl") or scan_url
        except Exception:
            pass
        row1 = []
        if dex_url:
            row1.append({"text": "🟢 Open in DEX", "url": dex_url})
        if scan_url:
            row1.append({"text": "🔍 Open in Scan", "url": scan_url})
        if row1:
            rows.append(row1)
        if token and token.startswith("0x") and len(token)==42:
            rows.append([{"text": f"👁️ Unwatch {token[:6]}…", "callback_data": f"UNWATCH_T:{token}"}])
    return {"inline_keyboard": rows} if rows else None

# === PATCH: DEX/Scan fallbacks & explorer expansion ===========================
def _generic_scan_url(token: str):
    try:
        if token and token.startswith("0x") and len(token)==42:
            return f"https://blockscan.com/address/{token}"
        return None
    except Exception:
        return None

def _generic_dex_search(token: str):
    try:
        if token and token.startswith("0x"):
            return f"https://dexscreener.com/search?q={token}"
        return None
    except Exception:
        return None

# Redefine _alert_keyboard to ensure buttons even when URLs absent
try:
    _prev_alert_keyboard = _alert_keyboard
except Exception:
    _prev_alert_keyboard = None

def _alert_keyboard(dex_url: str, scan_url: str, token: str):
    try:
        # Fallbacks
        if not dex_url:
            dex_url = _generic_dex_search(token) or ""
        if not scan_url:
            scan_url = _generic_scan_url(token) or ""

        rows = []
        row = []
        if dex_url:
            row.append({"text": "🟢 Open in DEX", "url": dex_url})
        if scan_url:
            row.append({"text": "🔍 Open in Scan", "url": scan_url})
        if row:
            rows.append(row)
        if token and isinstance(token, str) and token.startswith("0x") and len(token)==42:
            rows.append([{"text": "👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
        return {"inline_keyboard": rows} if rows else None
    except Exception:
        # Fall back to previous implementation if anything goes wrong
        if _prev_alert_keyboard:
            try:
                return _prev_alert_keyboard(dex_url, scan_url, token)
            except Exception:
                return None
        return None

# Overwrite explorer with broader chain support
def _explorer_url(chain: str, token: str):
    try:
        ch = (chain or "").lower()
        if not token or not token.startswith("0x") or len(token)!=42:
            return None
        if ch in ("eth","ethereum","mainnet"):
            return f"https://etherscan.io/token/{token}"
        if ch in ("bsc","bnb","binance"):
            return f"https://bscscan.com/token/{token}"
        if ch in ("polygon","matic"):
            return f"https://polygonscan.com/token/{token}"
        if ch in ("arbitrum","arb","arb1"):
            return f"https://arbiscan.io/token/{token}"
        if ch in ("base","basesepolia","base-mainnet"):
            return f"https://basescan.org/token/{token}"
        if ch in ("optimism","op"):
            return f"https://optimistic.etherscan.io/token/{token}"
        if ch in ("avalanche","avax"):
            return f"https://snowtrace.io/token/{token}"
        if ch in ("fantom","ftm"):
            return f"https://ftmscan.com/token/{token}"
        if ch in ("gnosis","gno","xdai"):
            return f"https://gnosisscan.io/token/{token}"
        if ch in ("linea",):
            return f"https://lineascan.build/token/{token}"
        if ch in ("scroll",):
            return f"https://scrollscan.com/token/{token}"
        if ch in ("pulse","pulsechain","plsx","pls"):
            return f"https://scan.pulsechain.com/token/{token}"
        # Default to generic multi-chain viewer
        return _generic_scan_url(token)
    except Exception:
        return _generic_scan_url(token)
# === /PATCH ===================================================================
