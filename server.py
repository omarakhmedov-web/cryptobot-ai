import os, json, re, traceback, requests
import time
from flask import Flask, request, jsonify

from limits import can_scan, register_scan
from state import store_bundle, load_bundle
from buttons import build_keyboard
from cache import cache_get, cache_set
from webintel import analyze_website
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
from renderers import render_quick, render_details, render_why, render_whypp, render_lp
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
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en") or "en"

HELP_URL = os.getenv("HELP_URL", "https://metridex.com/help")
DEEP_REPORT_URL = os.getenv("DEEP_REPORT_URL", "https://metridex.com/upgrade/deep-report")
DAY_PASS_URL = os.getenv("DAY_PASS_URL", "https://metridex.com/upgrade/day-pass")
PRO_URL = os.getenv("PRO_URL", "https://metridex.com/upgrade/pro")
TEAMS_URL = os.getenv("TEAMS_URL", "https://metridex.com/upgrade/teams")
FREE_DAILY_SCANS = int(os.getenv("FREE_DAILY_SCANS", "2"))
HINT_CLICKABLE_LINKS = os.getenv("HINT_CLICKABLE_LINKS", "0") == "1"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
PARSE_MODE = "MarkdownV2"

app = Flask(__name__)

_MD2_SPECIALS = r'_[]()~>#+-=|{}.!'
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
    return {
        "deep_report": DEEP_REPORT_URL,
        "day_pass": DAY_PASS_URL,
        "pro": PRO_URL,
        "teams": TEAMS_URL,
        "help": HELP_URL,
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

@app.post(WEBHOOK_PATH)
def webhook():
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
    if text.startswith("/"):
        send_message(chat_id, WELCOME, reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

    ok, _tier = can_scan(chat_id)
    if not ok:
        send_message(chat_id, "Free scans exhausted. Use /upgrade.", reply_markup=build_keyboard(chat_id, 0, _pricing_links(), ctx="start"))
        return jsonify({"ok": True})

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

    quick = render_quick(verdict, market, {}, DEFAULT_LANG)
    details = render_details(verdict, market, {}, DEFAULT_LANG)
    why = safe_render_why(verdict, market, DEFAULT_LANG)
    whypp = safe_render_whypp(verdict, market, DEFAULT_LANG)

    try:
        ch_ = (market.get("chain") or "").lower()
        _map = {"ethereum":"eth","bsc":"bsc","polygon":"polygon","arbitrum":"arb","optimism":"op","base":"base","avalanche":"avax","fantom":"ftm"}
        _short = _map.get(ch_, ch_ or "eth")
        info = check_lp_lock_v2(_short, market.get("pairAddress"))
        lp = render_lp(info, DEFAULT_LANG)
    except TypeError:
        lp = render_lp({"provider":"lite-burn-check","lpAddress": market.get("pairAddress"), "until": "—"})
    except Exception:
        lp = "LP lock: unknown"

    links = (market.get("links") or {})
    web = {}
    try:
        web = analyze_website(links.get("site")) if links.get("site") else {"whois": {"created": None, "registrar": None}, "ssl": {"ok": None, "expires": None, "issuer": None}, "wayback": {"first": None}}
    except Exception:
        web = {"whois": {"created": None, "registrar": None}, "ssl": {"ok": None, "expires": None, "issuer": None}, "wayback": {"first": None}}
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

    sent = send_message(chat_id, quick, reply_markup=build_keyboard(chat_id, 0, links, ctx="quick"))
    msg_id = sent.get("result", {}).get("message_id") if sent.get("ok") else None
    if msg_id:
        store_bundle(chat_id, msg_id, bundle)
        try:
            tg("editMessageReplyMarkup", {
                "chat_id": chat_id,
                "message_id": msg_id,
                "reply_markup": json.dumps(build_keyboard(chat_id, msg_id, links, ctx="quick"))
            })
        except Exception as e:
            print("editMessageReplyMarkup failed:", e)
    register_scan(chat_id)
    return jsonify({"ok": True})


def on_callback(cb):
    cb_id = cb["id"]
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
        cache_set(idem_key, "1", ttl_sec=30)

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
        # On-chain details via live inspect (hardened) with guard on unknown chain
        mkt = (bundle.get('market') if isinstance(bundle, dict) else None) or {}
        chain_name = (mkt.get('chain') or '').strip().lower()
        if not chain_name:
            send_message(chat_id, "On-chain\nUnsupported/unknown chain", reply_markup=None)
            answer_callback_query(cb_id, "On-chain not available", False)
        else:
            _map = {"ethereum":"eth","eth":"eth","bsc":"bsc","binance smart chain":"bsc","polygon":"polygon","matic":"polygon",
                    "arbitrum":"arb","arb":"arb","optimism":"op","op":"op","base":"base","avalanche":"avax","avax":"avax","fantom":"ftm","ftm":"ftm"}
            chain_short = _map.get(chain_name, chain_name)
            token_addr = mkt.get('tokenAddress')
            pair_addr = mkt.get('pairAddress')
            if chain_short not in _map.values():
                send_message(chat_id, "On-chain\nUnsupported/unknown chain", reply_markup=None)
                answer_callback_query(cb_id, "On-chain not available", False)
            else:
                try:
                    oc = onchain_inspector.inspect_token(chain_short, token_addr, pair_addr)
                except Exception as _e:
                    oc = {'ok': False, 'error': str(_e)}
                if isinstance(bundle, dict):
                    bundle['onchain'] = oc
                ok = bool(oc.get('ok'))
                def _s(x):
                    try:
                        return str(x) if x is not None else '—'
                    except Exception:
                        return '—'
                owner_raw = oc.get('owner')
                owner = owner_raw.lower() if isinstance(owner_raw, str) else ''
                renounced = oc.get('renounced')
                if renounced in (None, '—'):
                    if owner in ('0x0000000000000000000000000000000000000000','0x000000000000000000000000000000000000dead'):
                        renounced = True
                token_name = _s(oc.get('token_name') or oc.get('token') or mkt.get('pairSymbol'))
                paused = _s(oc.get('paused'))
                upgradeable = _s(oc.get('upgradeable'))
                maxTx = _s(oc.get('maxTx'))
                maxWallet = _s(oc.get('maxWallet'))
                if not ok:
                    text = 'On-chain\n' + _s(oc.get('error') or 'inspection failed')
                else:
                    text = (
                        'On-chain\n'
                        f'token: {token_name}\n'
                        f'owner: {_s(owner_raw)}\n'
                        f'renounced: {renounced}\n'
                        f'paused: {paused}  upgradeable: {upgradeable}\n'
                        f'maxTx: {maxTx}  maxWallet: {maxWallet}'
                    )
                send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, (bundle.get('links') if isinstance(bundle, dict) else {}), ctx='onchain'))
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
        answer_callback_query(cb_id, f"{label}: {_pct(val)}", False)

    else:
        answer_callback_query(cb_id, "Unsupported action", True)

    return jsonify({"ok": True})


# === INLINE DIAGNOSTICS (no shell needed) ====================================
import os as _os
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
        def _s(x): return str(x) if x is not None else "—"
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

        m = bundle.get("market") or {}
        v = bundle.get("verdict") or {}
        why  = bundle.get("why")  or "Why: n/a"
        whyp = bundle.get("whypp") or "Why++: n/a"
        lp   = bundle.get("lp")   or "LP: n/a"

        pair = _s(m.get("pairSymbol"))
        chain= _s(m.get("chain"))
        price= _fmt_num(m.get("price"))
        fdv  = _fmt_num(m.get("fdv"))
        mc   = _fmt_num(m.get("mc"))
        liq  = _fmt_num(m.get("liq"))
        vol  = _fmt_num(m.get("vol24h"))
        chg5 = _fmt_pct((m.get("priceChanges") or {}).get("m5"))
        chg1 = _fmt_pct((m.get("priceChanges") or {}).get("h1"))
        chg24= _fmt_pct((m.get("priceChanges") or {}).get("h24"))
        asof = _s(m.get("asof"))
        score = _s((v.get("score") if isinstance(v, dict) else getattr(v, "score", None)))

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
            "<h1>Metridex QuickScan — " + pair + " <span class='pill'>Score: " + score + "</span></h1>"
            "<div class='meta'>"
            "<div>Chain: " + chain + "</div><div>Price: " + price + "</div>"
            "<div>FDV: " + fdv + "</div><div>MC: " + mc + "</div>"
            "<div>Liquidity: " + liq + "</div><div>Vol 24h: " + vol + "</div>"
            "<div>Δ5m: " + chg5 + "</div><div>Δ1h: " + chg1 + "</div>"
            "<div>Δ24h: " + chg24 + "</div><div>Asof: " + asof + "</div>"
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

