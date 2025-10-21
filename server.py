import os
import json
import re
import traceback
import requests
from flask import Flask, request, jsonify, redirect
from ratelimit import limits, sleep_and_retry
from openai import OpenAI
from datetime import datetime as _dt
from urllib.parse import urlparse
import socket
import ssl
import html

from common import chain_from_hint
from limits import can_scan, register_scan
from state import store_bundle, load_bundle
from buttons import build_keyboard
from cache import cache_get, cache_set
from dex_client import fetch_market
from risk_engine import compute_verdict
from onchain_inspector import inspect_token
from pair_resolver import resolve_pair
from chain_client import fetch_onchain_factors, check_lp_lock_v2
from renderers_mdx import render_quick, render_details, render_why, render_whypp, render_lp
from onchain_formatter import format_onchain_text

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_WEBHOOK_SECRET = os.getenv("BOT_WEBHOOK_SECRET", "").strip()
WEBHOOK_PATH = f"/webhook/{BOT_WEBHOOK_SECRET}" if BOT_WEBHOOK_SECRET else "/webhook/secret-not-set"
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
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

# Rate-limiting для внешних API
@sleep_and_retry
@limits(calls=5, period=1)
def fetch_external_api(url, params=None, timeout=2.5):
    return requests.get(url, params=params, timeout=timeout)

# Объединённая функция для webintel
def analyze_website(site_url: str | None):
    host = urlparse(site_url).hostname if site_url else None
    if not host:
        return {"whois": {"created": None, "registrar": None},
                "ssl": {"ok": None, "expires": None, "issuer": None},
                "wayback": {"first": None}}

    # WHOIS/RDAP
    whois = {"created": None, "registrar": None}
    try:
        r = fetch_external_api(f"https://rdap.org/domain/{host}")
        if r.ok:
            j = r.json()
            for ev in j.get("events", []):
                if ev.get("eventAction", "").lower() in ("registration", "registered", "creation"):
                    whois["created"] = ev.get("eventDate", "")[:10]
                    break
            for ent in j.get("entities", []):
                if "registrar" in [r.lower() for r in ent.get("roles", [])]:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                whois["registrar"] = item[3]
                                break
    except Exception:
        pass

    # SSL
    ssl_info = {"ok": None, "expires": None, "issuer": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=2.0) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_info["ok"] = True
                if "notAfter" in cert:
                    ssl_info["expires"] = _dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
    except Exception:
        pass

    # Wayback
    wayback = {"first": None}
    try:
        r = fetch_external_api("https://web.archive.org/cdx/search/cdx", params={
            "url": host, "output": "json", "fl": "timestamp", "filter": "statuscode:200", "limit": "1",
            "from": "19960101", "to": "99991231", "sort": "ascending"
        })
        if r.ok:
            j = r.json()
            if len(j) > 1 and j[1]:
                ts = j[1][0]
                wayback["first"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass

    return {"whois": whois, "ssl": ssl_info, "wayback": wayback}

# AI для Why++
def generate_ai_explanation(verdict: dict):
    if not OPENAI_KEY:
        return "AI explanation unavailable"
    client = OpenAI(api_key=OPENAI_KEY)
    prompt = f"Explain token risk verdict: score={verdict.get('score')}, positives={verdict.get('positives')}, negatives={verdict.get('negatives')} in simple terms."
    try:
        response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
        return response.choices[0].message.content
    except Exception:
        return "AI error"

# Owner-bypass для лимитов
def _owner_ids():
    ids = set()
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
    try:
        if int(chat_id) in _owner_ids():
            return True, "Pro (owner)"
    except Exception:
        pass
    return False, "Free"

# Webintel контекст
def build_webintel_ctx(market: dict) -> dict:
    links = market.get("links", {})
    site_url = links.get("site") or os.getenv("WEBINTEL_SITE_OVERRIDE")
    web = analyze_website(site_url)
    dom = urlparse(site_url).hostname if site_url else None
    return {"webintel": web, "domain": dom}

# NOWPayments
def _np_create_invoice_smart(amount_usd: float, order_id: str, order_desc: str, success_url: str, cancel_url: str, ipn_url: str, plan_key: str | None = None):
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
        if cancel_url:  payload["cancel_url"] = cancel_url
        r = requests.post("https://api.nowpayments.io/v1/invoice", json=payload, timeout=12, headers={"x-api-key": api_key})
        try:
            j = r.json()
        except Exception:
            j = {"error": r.text}
        if r.ok and isinstance(j, dict) and (j.get("invoice_id") or j.get("id")):
            return {"ok": True, "json": j}
        return {"ok": False, "status": r.status_code, "json": j}

    if low_ticket:
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
        return last_err or {'ok': False, 'error': 'All low-ticket currencies failed'}
    else:
        is_fixed = bool(int(os.getenv("NOWPAYMENTS_FIXED_RATE", "1")))
        pay_cur = (os.getenv("NOWPAYMENTS_PAY_CURRENCY_HIGH") or os.getenv("NOWPAYMENTS_PAY_CURRENCY") or "bnbbsc").strip().lower()
        return _try_create(pay_cur, is_fixed_rate=is_fixed)

# HTML-рендер (оптимизированный, без truncated)
def _build_html_report_safe(bundle: dict) -> bytes:
    def _s(x): 
        return str(x) if x is not None else "—"
    def _fmt_time(v):
        try:
            ts = int(v)
            if ts < 10**12: ts *= 1000
            return _dt.utcfromtimestamp(ts/1000.0).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return "—"
    def _fmt_num(v, prefix="$"):
        try:
            n = float(v)
            a = abs(n)
            if a >= 1_000_000_000: return f"{prefix}{n/1_000_000_000:.2f}B"
            elif a >= 1_000_000: return f"{prefix}{n/1_000_000:.2f}M"
            elif a >= 1_000: return f"{prefix}{n/1_000:.2f}K"
            else: return f"{prefix}{n:.6f}" if a < 1 else f"{prefix}{n:.2f}"
        except Exception:
            return "—"
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
            if d < 1/24: return "<1h"
            if d < 1: return f"{d*24:.1f}h"
            return f"{d:.1f}d"
        except Exception:
            return "—"

    m = bundle.get("market") or {}
    v = bundle.get("verdict") or {}
    why = bundle.get("why") or "Why: n/a"
    whypp = bundle.get("whypp") or "Why++: n/a"
    lp = bundle.get("lp") or "LP: n/a"
    web = bundle.get("webintel") or {}
    links = m.get("links", {})

    pair = _s(m.get("pairSymbol"))
    chain = _fmt_chain(m.get("chain"))
    price = _fmt_num(m.get("price"))
    fdv = _fmt_num(m.get("fdv"))
    mc = _fmt_num(m.get("mc"))
    liq = _fmt_num(m.get("liq"))
    vol = _fmt_num(m.get("vol24h"))
    chg5 = _fmt_pct((m.get("priceChanges") or {}).get("m5"))
    chg1 = _fmt_pct((m.get("priceChanges") or {}).get("h1"))
    chg24 = _fmt_pct((m.get("priceChanges") or {}).get("h24"))
    asof = _fmt_time(m.get("asof"))
    age = _fmt_age(m.get("ageDays"))
    score = _s(v.get("score", "—"))
    level = _s(v.get("level", ""))
    score_ui = ("15" if (str(score) in ("0","0.0") and str(level).lower().startswith("low")) else str(score))
    ai_explanation = generate_ai_explanation(v) if OPENAI_KEY else ""

    whois = web.get("whois", {})
    ssl = web.get("ssl", {})
    way = web.get("wayback", {})

    html = f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Metridex QuickScan — {html.escape(pair)}</title>
<style>
body {{background:#0b0b0f;color:#e7e5e4;font-family:Inter,system-ui,Arial,sans-serif;margin:24px}}
h1 {{font-size:24px;margin:0 0 12px}}
.meta,.block pre {{background:#13151a;border:1px solid #262626;border-radius:12px;padding:12px}}
.meta {{margin:12px 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}
.pill {{display:inline-block;background:#1f2937;border-radius:999px;padding:3px 8px;margin-left:8px;color:#f59e0b;font-weight:600}}
a {{color:#93c5fd}}
</style>
</head>
<body>
<h1>Metridex QuickScan — {html.escape(pair)} <span class='pill'>Score: {html.escape(score_ui)}</span></h1>
<div class='meta'>
<div>Chain: {html.escape(chain)}</div><div>Price: {html.escape(price)}</div>
<div>FDV: {html.escape(fdv)}</div><div>MC: {html.escape(mc)}</div>
<div>Liquidity: {html.escape(liq)}</div><div>Vol 24h: {html.escape(vol)}</div>
<div>Δ5m: {html.escape(chg5)}</div><div>Δ1h: {html.escape(chg1)}</div>
<div>Δ24h: {html.escape(chg24)}</div><div>Age: {html.escape(age)}</div>
<div>As of: {html.escape(asof)}</div>
</div>
<div class='block'><pre>{html.escape(why)}</pre></div>
<div class='block'><pre>{html.escape(whypp)}\nAI Explanation: {html.escape(ai_explanation)}</pre></div>
<div class='block'><pre>{html.escape(lp)}</pre></div>
<div class='block'>
<pre>
Website Intel:
WHOIS Created: {html.escape(_s(whois.get('created')))}
Registrar: {html.escape(_s(whois.get('registrar')))}
Wayback First: {html.escape(_s(way.get('first')))}
SSL OK: {html.escape(_s(ssl.get('ok')))}
SSL Expires: {html.escape(_s(ssl.get('expires')))}
</pre>
</div>
</body>
</html>
"""
    return html.encode("utf-8")

@app.route('/healthz')
def healthz():
    return "OK", 200

if __name__ == "__main__":
    app.run(debug=True)
