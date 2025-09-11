import os
import hashlib
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from functools import wraps
import re
import socket
import ssl
import json

from flask import Flask, request, jsonify
import requests

from quickscan import (
    quickscan_entrypoint,
    quickscan_pair_entrypoint,
    normalize_input,
    SafeCache,
)
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

APP_VERSION = os.environ.get("APP_VERSION", "0.3.7-quickscan-mvp+details")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
DEBUG_MORE = os.environ.get("DEBUG_MORE", "0") == "1"
TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "6.0"))

LOC = locale_text

app = Flask(__name__)

cache = SafeCache(ttl=CACHE_TTL_SECONDS)
seen_callbacks = SafeCache(ttl=300)
cb_cache = SafeCache(ttl=600)   # short-token -> original callback_data
msg2addr = SafeCache(ttl=86400) # message_id(str) -> base 0x-address

ADDR_RE = re.compile(r'0x[a-fA-F0-9]{40}')
NEWLINE_ESC_RE = re.compile(r'\\n')  # literal backslash+n

# Built-in homepage hints for bluechips (lowercased addresses)
KNOWN_HOMEPAGES = {
    # Ethereum
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "circle.com",     # USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether.to",      # USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f": "makerdao.com",   # DAI
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum.org",   # WETH
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "bitcoin.org",    # WBTC custodian
}

KNOWN_DOMAINS_FILE_PATH = None
KNOWN_DOMAINS_LOADED = 0

def _norm_domain(url: str):
    if not url:
        return None
    try:
        u = urlparse(url.strip())
        host = u.netloc or u.path
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        return host.strip("/")
    except Exception:
        return None

def _load_known_domains():
    """Load/merge known_domains (env: KNOWN_DOMAINS_FILE or KNOWN_DOMAINS_PATH) into KNOWN_HOMEPAGES."""
    global KNOWN_DOMAINS_FILE_PATH, KNOWN_DOMAINS_LOADED
    try:
        # accept both env names; fall back to ./known_domains.json next to this file
        KNOWN_DOMAINS_FILE_PATH = (
            os.getenv("KNOWN_DOMAINS_FILE")
            or os.getenv("KNOWN_DOMAINS_PATH")
            or os.path.join(os.path.dirname(__file__), "known_domains.json")
        )
        path = KNOWN_DOMAINS_FILE_PATH
        if not os.path.exists(path):
            app.logger.info(f"[KNOWN] {path} not found — using built-ins only")
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = 0
        for k, v in (data or {}).items():
            addr = (k or "").lower().strip()
            if not ADDR_RE.fullmatch(addr):
                continue
            dom = v[0] if isinstance(v, list) else v
            dom = _norm_domain(dom)
            if dom:
                KNOWN_HOMEPAGES[addr] = dom
                merged += 1
        KNOWN_DOMAINS_LOADED = merged
        app.logger.info(f"[KNOWN] loaded {merged} domain hints from {path}")
    except Exception as e:
        app.logger.warning(f"[KNOWN] failed to load known domains: {e}")

# merge external known_domains.json (optional)
_load_known_domains()

def _extract_base_addr_from_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict):
        return None
    ik = kb.get("inline_keyboard") or []
    for row in ik:
        for btn in row:
            data = (btn.get("callback_data") or "")
            if data.startswith("qs2:"):
                path, _, _ = data.split(":", 1)[1].partition("?")
                _, _, pair_addr = path.partition("/")
                parts = pair_addr.split("-")
                addrs = [p for p in parts if ADDR_RE.fullmatch(p)]
                if addrs:
                    return addrs[-1]  # prefer last
            if data.startswith("qs:"):
                payload = data.split(":", 1)[1]
                addr = payload.split("?", 1)[0]
                if ADDR_RE.fullmatch(addr):
                    return addr
    return None

def _extract_addr_from_text(s: str):
    if not s:
        return None
    matches = list(ADDR_RE.finditer(s))
    return matches[-1].group(0) if matches else None

def _store_addr_for_message(result_obj, addr: str):
    try:
        if not result_obj or not isinstance(result_obj, dict) or not addr:
            return
        if result_obj.get("ok") and isinstance(result_obj.get("result"), dict):
            mid = str(result_obj["result"].get("message_id"))
            if mid and ADDR_RE.fullmatch(addr):
                msg2addr.set(mid, addr)
    except Exception:
        pass

def _cg_homepage(addr: str):
    addr_l = addr.lower()
    if addr_l in KNOWN_HOMEPAGES:
        return KNOWN_HOMEPAGES[addr_l]
    try:
        url = f"https://api.coingecko.com/api/v3/coins/ethereum/contract/{addr}"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200:
            return None
        data = r.json()
        hp = (data.get("links") or {}).get("homepage") or []
        for u in hp:
            d = _norm_domain(u)
            if d:
                return d
    except Exception:
        return None
    return None

def _rdap(domain: str):
    # returns (handle, created, registrar)
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200:
            return ("—", "—", "—")
        j = r.json()
        handle = j.get("handle") or "—"
        created = "—"
        for ev in j.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate", "—")
                break
        registrar = "—"
        for ent in j.get("entities", []):
            if (ent.get("roles") or []) and "registrar" in ent["roles"]:
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) == 2:
                    for item in v[1]:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break
        return (handle, created, registrar)
    except Exception:
        return ("—", "—", "—")

def _ssl_info(domain: str):
    # returns (notAfter, issuerCN)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp = cert.get("notAfter", "—")
        issuer = cert.get("issuer", [])
        cn = "—"
        for tup in issuer:
            for k, v in tup:
                if k.lower() == "commonName".lower():
                    cn = v
                    break
        return (exp, cn)
    except Exception:
        return ("—", "—")

def _wayback_first(domain: str):
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp&filter=statuscode:200&from=2000"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200:
            return "—"
        data = r.json()
        if isinstance(data, list) and len(data) > 1 and isinstance(data[1], list) and data[1]:
            ts = data[1][0]
            try:
                dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                return dt.date().isoformat()
            except Exception:
                return ts
        return "—"
    except Exception:
        return "—"

def _needs_enrichment(text: str) -> bool:
    if not text:
        return True
    if "Domain:" not in text or "SSL:" not in text or "Wayback:" not in text:
        return True
    if re.search(r"Domain:\s*(?:—)?\s*(?:\n|$)", text):
        return True
    return False

def _enrich_full(addr: str, text: str):
    txt = NEWLINE_ESC_RE.sub("\n", text or "")
    domain = _cg_homepage(addr)
    if not domain:
        return txt
    h, created, reg = _rdap(domain)
    exp, issuer = _ssl_info(domain)
    wb = _wayback_first(domain)
    block = f"Domain: {domain}\nWHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}\nSSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}\nWayback: first {wb}"
    if "Domain:" in txt:
        txt = re.sub(r"Domain:.*", f"Domain: {domain}", txt)
        if "WHOIS/RDAP:" in txt:
            txt = re.sub(r"WHOIS/RDAP:.*", f"WHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}", txt)
        else:
            txt += f"\nWHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}"
        if "SSL:" in txt:
            txt = re.sub(r"SSL:.*", f"SSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}", txt)
        else:
            txt += f"\nSSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}"
        if "Wayback:" in txt:
            txt = re.sub(r"Wayback:.*", f"Wayback: first {wb}", txt)
        else:
            txt += f"\nWayback: first {wb}"
        return txt
    return txt + "\n" + block

def require_webhook_secret(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if WEBHOOK_HEADER_SECRET:
            header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if header != WEBHOOK_HEADER_SECRET:
                app.logger.warning("[AUTH] bad header secret")
                return ("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

def _compress_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict):
        return kb
    ik = kb.get("inline_keyboard")
    if not ik:
        return kb
    for row in ik:
        for btn in row:
            data = btn.get("callback_data")
            if not data:
                continue
            if len(data) <= 60 and data.startswith(("qs:", "qs2:", "more:", "less:")):
                continue
            h = hashlib.sha1(data.encode("utf-8")).hexdigest()[:10]
            token = f"cb:{h}"
            cb_cache.set(token, data)
            btn["callback_data"] = token
    return {"inline_keyboard": ik}

def _rewrite_keyboard_to_addr(addr, kb: dict, add_more_btn: bool = True):
    if not kb or not isinstance(kb, dict):
        kb = {}
    ik = kb.get("inline_keyboard") or []
    out = []
    for row in ik:
        new_row = []
        for btn in row:
            data = btn.get("callback_data")
            if data and data.startswith("qs2:") and addr:
                _, _, query = data.partition("?")
                params = parse_qs(query)
                window = params.get("window", ["h24"])[0]
                btn = dict(btn)
                btn["callback_data"] = f"qs:{addr}?window={window}"
            new_row.append(btn)
        out.append(new_row)
    if add_more_btn and addr:
        out.append([{"text": "🔎 More details", "callback_data": f"more:{addr}"}])
    return {"inline_keyboard": out} if out else kb

def _send_text(chat_id, text, **kwargs):
    text = NEWLINE_ESC_RE.sub("\n", text or "")
    return tg_send_message(TELEGRAM_TOKEN, chat_id, text, **kwargs)

@app.route("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
        "version": APP_VERSION,
        "allow_all_chats": (len(ALLOWED_CHAT_IDS) == 0),
        "header_secret_required": bool(WEBHOOK_HEADER_SECRET),
    })

@app.route("/debug")
def debug():
    whs = WEBHOOK_SECRET[:6] + "…" if WEBHOOK_SECRET else ""
    return jsonify({
        "version": APP_VERSION,
        "bot": BOT_USERNAME,
        "env": {
            "TELEGRAM_TOKEN_set": bool(TELEGRAM_TOKEN),
            "WEBHOOK_SECRET_hint": whs,
            "WEBHOOK_HEADER_SECRET_set": bool(WEBHOOK_HEADER_SECRET),
            "ALLOWED_CHAT_IDS_count": len(ALLOWED_CHAT_IDS),
            "CACHE_TTL_SECONDS": CACHE_TTL_SECONDS,
            "KNOWN_DOMAINS_FILE_PATH": KNOWN_DOMAINS_FILE_PATH,
            "KNOWN_DOMAINS_LOADED": KNOWN_DOMAINS_LOADED,
        }
    })

@app.route("/selftest")
def selftest():
    chat_id = request.args.get("chat_id")
    text = request.args.get("text", "ping")
    if not TELEGRAM_TOKEN or not chat_id:
        return jsonify({"ok": False, "error": "missing token or chat_id"}), 400
    st, body = _send_text(chat_id, f"[selftest] {text}", logger=app.logger)
    return jsonify({"ok": (st == 200 and (isinstance(body, dict) and body.get("ok"))), "status": st, "resp": body})

@app.route("/qs_preview")
def qs_preview():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"ok": False, "error": "missing q"}), 400
    try:
        text_out, keyboard = quickscan_entrypoint(q, lang="en", lean=True)
        base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(q)
        keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
        keyboard = _compress_keyboard(keyboard)
        return jsonify({"ok": True, "text": text_out, "keyboard": keyboard})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/webhook/<secret>", methods=["POST"])
@require_webhook_secret
def webhook(secret):
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        app.logger.warning("[AUTH] bad path secret")
        return ("forbidden", 403)

    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        app.logger.exception("[UPD] bad json")
        return ("ok", 200)

    try:
        # CALLBACKS
        if "callback_query" in update:
            cq = update["callback_query"]
            chat_id = cq["message"]["chat"]["id"]
            data = cq.get("data", "")
            msg_obj = cq.get("message", {})
            msg_id = str(msg_obj.get("message_id"))
            app.logger.info(f"[UPD] callback chat={chat_id} data={data} msg_id={msg_id}")

            if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
                app.logger.info(f"[UPD] callback ignored (not allowed) chat={chat_id}")
                return ("ok", 200)

            if data.startswith("cb:"):
                orig = cb_cache.get(data)
                if orig:
                    data = orig
                    app.logger.info(f"[CB] expanded {data[:48]}…")
                else:
                    tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), LOC("en", "error"), logger=app.logger)
                    return ("ok", 200)

            cqid = cq.get("id")
            if cqid and seen_callbacks.get(cqid):
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
                return ("ok", 200)
            if cqid:
                seen_callbacks.set(cqid, True)

            try:
                if data.startswith("more:"):
                    raw = data.split(":", 1)[1]
                    addr = (
                        (msg2addr.get(msg_id) if msg_id else None) or
                        _extract_addr_from_text(raw) or
                        _extract_base_addr_from_keyboard(msg_obj.get("reply_markup") or {}) or
                        _extract_addr_from_text(msg_obj.get("text") or "")
                    )
                    if DEBUG_MORE:
                        tg_answer_callback(TELEGRAM_TOKEN, cq["id"], f"Full scan for {addr}", logger=app.logger)
                    app.logger.info(f"[MORE] resolved addr={addr} (payload={raw})")
                    if not addr:
                        tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "error"), logger=app.logger)
                        return ("ok", 200)
                    text, keyboard = quickscan_entrypoint(addr, lang="en", lean=False)  # full details
                    if _needs_enrichment(text):
                        text = _enrich_full(addr, text)
                    keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=False)
                elif data.startswith("qs2:"):
                    path, _, window = data.split(":", 1)[1].partition("?window=")
                    chain, _, pair_addr = path.partition("/")
                    window = window or "h24"
                    text, keyboard = quickscan_pair_entrypoint(chain, pair_addr, window=window)
                    base_addr = (
                        _extract_base_addr_from_keyboard(keyboard) or
                        _extract_addr_from_text(pair_addr)
                    )
                    keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
                elif data.startswith("qs:"):
                    addr, _, window = data.split(":", 1)[1].partition("?window=")
                    window = window or "h24"
                    text, keyboard = quickscan_entrypoint(addr, lang="en", window=window, lean=True)
                    keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=True)
                else:
                    return ("ok", 200)

                keyboard = _compress_keyboard(keyboard)
                app.logger.info(f"[QS] cb -> len={len(text)}")
                st, body = _send_text(chat_id, text, reply_markup=keyboard, logger=app.logger)
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
            except Exception:
                app.logger.exception("[ERR] callback quickscan")
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "error"), logger=app.logger)
            return ("ok", 200)

        # MESSAGES
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            app.logger.info("[UPD] no message/callback")
            return ("ok", 200)

        if (msg.get("from") or {}).get("is_bot"):
            app.logger.info("[UPD] from bot, ignore")
            return ("ok", 200)

        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()
        app.logger.info(f"[UPD] message chat={chat_id} text={text[:80]}")

        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
            app.logger.info(f"[UPD] message ignored (not allowed) chat={chat_id}")
            return ("ok", 200)

        if not text:
            _send_text(chat_id, LOC("en", "empty"), logger=app.logger)
            return ("ok", 200)

        if text.startswith("/"):
            cmd, *rest = text.split(maxsplit=1)
            arg = rest[0] if rest else ""
            app.logger.info(f"[CMD] {cmd} arg={arg}")

        # Commands
            if cmd in ("/start", "/help"):
                _send_text(chat_id, LOC("en", "help").format(bot=BOT_USERNAME), parse_mode="Markdown", logger=app.logger)
                return ("ok", 200)

            if cmd == "/lang":
                if arg.lower().startswith("ru"):
                    _send_text(chat_id, LOC("ru", "lang_switched"), logger=app.logger)
                else:
                    _send_text(chat_id, LOC("en", "lang_switched"), logger=app.logger)
                return ("ok", 200)

            if cmd == "/license":
                _send_text(chat_id, "Metridex QuickScan MVP — MIT License", logger=app.logger)
                return ("ok", 200)

            if cmd == "/quota":
                _send_text(chat_id, "Free tier — 300 DexScreener req/min shared; be kind.", logger=app.logger)
                return ("ok", 200)

            if cmd == "/debug_known":
                _send_text(chat_id, f"known_domains: path={KNOWN_DOMAINS_FILE_PATH}, loaded={KNOWN_DOMAINS_LOADED}", logger=app.logger)
                return ("ok", 200)

            if cmd in ("/quickscan", "/scan"):
                if not arg:
                    _send_text(chat_id, LOC("en", "scan_usage"), logger=app.logger)
                else:
                    try:
                        text_out, keyboard = quickscan_entrypoint(arg, lang="en", lean=True)
                        base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(arg)
                        keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
                        keyboard = _compress_keyboard(keyboard)
                        app.logger.info(f"[QS] cmd -> len={len(text_out)}")
                        st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                        _store_addr_for_message(body, base_addr)
                    except Exception:
                        app.logger.exception("[ERR] cmd quickscan")
                        _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
                return ("ok", 200)

            _send_text(chat_id, LOC("en", "unknown"), logger=app.logger)
            return ("ok", 200)

        # Implicit quickscan
        _send_text(chat_id, "Processing…", logger=app.logger)
        try:
            text_out, keyboard = quickscan_entrypoint(text, lang="en", lean=True)
            base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(text)
            keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
            keyboard = _compress_keyboard(keyboard)
            app.logger.info(f"[QS] implicit -> len={len(text_out)}")
            st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
            _store_addr_for_message(body, base_addr)
        except Exception:
            app.logger.exception("[ERR] implicit quickscan")
            _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
        return ("ok", 200)

    except Exception:
        app.logger.exception("[ERR] webhook handler (outer)")
        try:
            if "callback_query" in update:
                cq = update["callback_query"]
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), LOC("en", "error"), logger=app.logger)
        except Exception:
            pass
        return ("ok", 200)

def detect_lang(user):
    code = (user or {}).get("language_code", "en").lower()
    return "ru" if code.startswith("ru") else "en"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
