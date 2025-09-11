import os, re, json, ssl, socket, hashlib, time, threading
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from functools import wraps
import requests
from flask import Flask, request, jsonify

from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

APP_VERSION = os.environ.get("APP_VERSION", "0.3.7e-quickscan-mvp+details")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
DEBUG_MORE = os.environ.get("DEBUG_MORE", "0") == "1"
TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "6.0"))
KNOWN_AUTORELOAD_SEC = int(os.environ.get("KNOWN_AUTORELOAD_SEC", "300"))

LOC = locale_text
app = Flask(__name__)

cache = SafeCache(ttl=CACHE_TTL_SECONDS)
seen_callbacks = SafeCache(ttl=300)
cb_cache = SafeCache(ttl=600)
msg2addr = SafeCache(ttl=86400)

ADDR_RE = re.compile(r'0x[a-fA-F0-9]{40}')
NEWLINE_ESC_RE = re.compile(r'\\n')

KNOWN_HOMEPAGES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "circle.com",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether.to",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "makerdao.com",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum.org",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "bitcoin.org",
}

KNOWN_SOURCES = []
KNOWN_PATHS = []
KNOWN_LAST_CHECK = 0
KNOWN_MTIME = {}
KNOWN_LOCK = threading.Lock()

def _norm_domain(url: str):
    if not url: return None
    try:
        u = urlparse(url.strip())
        host = u.netloc or u.path
        host = host.lower()
        if host.startswith("www."): host = host[4:]
        return host.strip("/")
    except Exception:
        return None

def _merge_known_from(path: str, diag_only=False):
    entry = {"path": path, "exists": False, "loaded": 0, "error": "", "mtime": None}
    try:
        if not path:
            entry["error"] = "empty path"; return entry
        entry["exists"] = os.path.exists(path)
        if not entry["exists"]: return entry
        entry["mtime"] = os.path.getmtime(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = 0
        if not diag_only:
            for k,v in (data or {}).items():
                addr = (k or "").lower().strip()
                if not ADDR_RE.fullmatch(addr): continue
                dom = v[0] if isinstance(v, list) else v
                dom = _norm_domain(dom)
                if dom:
                    KNOWN_HOMEPAGES[addr] = dom; merged += 1
        else:
            for k in (data or {}):
                addr = (k or "").lower().strip()
                if ADDR_RE.fullmatch(addr): merged += 1
        entry["loaded"] = merged
        return entry
    except Exception as e:
        entry["error"] = str(e); return entry

def _collect_paths():
    paths = [os.path.join(os.path.dirname(__file__), "known_domains.json")]
    envp = os.getenv("KNOWN_DOMAINS_FILE") or os.getenv("KNOWN_DOMAINS_PATH")
    if envp and envp not in paths: paths.append(envp)
    return paths

def _load_known_domains():
    global KNOWN_SOURCES, KNOWN_PATHS, KNOWN_MTIME, KNOWN_LAST_CHECK
    with KNOWN_LOCK:
        KNOWN_PATHS = _collect_paths()
        KNOWN_SOURCES = []
        for p in KNOWN_PATHS:
            e = _merge_known_from(p, diag_only=False)
            KNOWN_SOURCES.append(e)
            if e["exists"]: KNOWN_MTIME[p] = e["mtime"]
        KNOWN_LAST_CHECK = time.time()

def _maybe_reload_known(force=False):
    global KNOWN_LAST_CHECK
    now = time.time()
    if not force and (KNOWN_AUTORELOAD_SEC <= 0 or now - KNOWN_LAST_CHECK < KNOWN_AUTORELOAD_SEC):
        return
    with KNOWN_LOCK:
        KNOWN_LAST_CHECK = now
        paths = _collect_paths()
        changed = False
        for p in paths:
            try:
                m = os.path.getmtime(p)
                if KNOWN_MTIME.get(p) != m: changed = True
            except Exception:
                if p in KNOWN_MTIME: changed = True
        if not changed and set(paths) == set(KNOWN_PATHS): return
        KNOWN_PATHS[:] = paths
        KNOWN_SOURCES.clear()
        for p in KNOWN_PATHS:
            e = _merge_known_from(p, diag_only=False)
            KNOWN_SOURCES.append(e)
            if e["exists"]: KNOWN_MTIME[p] = e["mtime"]

_load_known_domains()

def _extract_addrs_from_pair_payload(data: str):
    # qs2:<chain>/<0xA-0xB>?window=...
    try:
        path, _, _ = data.split(":", 1)[1].partition("?")
        _, _, pair_addr = path.partition("/")
        parts = [p for p in pair_addr.split("-") if ADDR_RE.fullmatch(p)]
        return [p.lower() for p in parts]
    except Exception:
        return []

def _pick_addr(addrs):
    # prefer known domains, else last
    for a in addrs:
        if a.lower() in KNOWN_HOMEPAGES:
            return a.lower()
    return addrs[-1].lower() if addrs else None

def _extract_base_addr_from_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict):
        return None
    ik = kb.get("inline_keyboard") or []
    for row in ik:
        for btn in row:
            data = (btn.get("callback_data") or "")
            if data.startswith("qs2:"):
                addrs = _extract_addrs_from_pair_payload(data)
                choice = _pick_addr(addrs)
                if choice: return choice
            if data.startswith("qs:"):
                payload = data.split(":", 1)[1]
                addr = payload.split("?", 1)[0]
                if ADDR_RE.fullmatch(addr): return addr.lower()
    return None

def _extract_addr_from_text(s: str):
    if not s: return None
    m = list(ADDR_RE.finditer(s))
    return m[-1].group(0).lower() if m else None

def _store_addr_for_message(result_obj, addr: str):
    try:
        if not result_obj or not isinstance(result_obj, dict) or not addr: return
        if result_obj.get("ok") and isinstance(result_obj.get("result"), dict):
            mid = str(result_obj["result"].get("message_id"))
            if mid and ADDR_RE.fullmatch(addr): msg2addr.set(mid, addr)
    except Exception: pass

def _cg_homepage(addr: str):
    addr_l = addr.lower()
    if addr_l in KNOWN_HOMEPAGES: return KNOWN_HOMEPAGES[addr_l]
    try:
        url = f"https://api.coingecko.com/api/v3/coins/ethereum/contract/{addr}"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200: return None
        data = r.json()
        hp = (data.get("links") or {}).get("homepage") or []
        for u in hp:
            d = _norm_domain(u)
            if d: return d
    except Exception: return None
    return None

def _rdap(domain: str):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200: return ("—","—","—")
        j = r.json()
        handle = j.get("handle") or "—"
        created = "—"
        for ev in j.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate","—"); break
        registrar = "—"
        for ent in j.get("entities", []):
            if (ent.get("roles") or []) and "registrar" in ent["roles"]:
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v)==2:
                    for item in v[1]:
                        if item and item[0]=="fn": registrar = item[3]; break
        return (handle, created, registrar)
    except Exception: return ("—","—","—")

def _ssl_info(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp = cert.get("notAfter","—")
        issuer = cert.get("issuer",[])
        cn = "—"
        for tup in issuer:
            for k,v in tup:
                if k.lower()=="commonName".lower(): cn=v; break
        return (exp, cn)
    except Exception: return ("—","—")

def _wayback_first(domain: str):
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp&filter=statuscode:200&from=2000"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200: return "—"
        data = r.json()
        if isinstance(data, list) and len(data)>1 and isinstance(data[1], list) and data[1]:
            ts = data[1][0]
            from datetime import datetime as dt
            try: return dt.strptime(ts,"%Y%m%d%H%M%S").date().isoformat()
            except Exception: return ts
        return "—"
    except Exception: return "—"

def _enrich_full(addr: str, text: str):
    txt = NEWLINE_ESC_RE.sub("\n", text or "")
    domain = _cg_homepage(addr)
    if not domain: return txt
    h, created, reg = _rdap(domain)
    exp, issuer = _ssl_info(domain)
    wb = _wayback_first(domain)
    block = f"Domain: {domain}\nWHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}\nSSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}\nWayback: first {wb}"
    import re as _re
    if "Domain:" in txt:
        txt = _re.sub(r"Domain:.*", f"Domain: {domain}", txt)
        txt = _re.sub(r"WHOIS/RDAP:.*", f"WHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}", txt)
        txt = _re.sub(r"SSL:.*", f"SSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}", txt)
        txt = _re.sub(r"Wayback:.*", f"Wayback: first {wb}", txt)
        return txt
    return txt + "\n" + block

def require_webhook_secret(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if WEBHOOK_HEADER_SECRET:
            header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if header != WEBHOOK_HEADER_SECRET:
                return ("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

def _compress_keyboard(kb: dict):
    if not kb or not isinstance(kb, dict): return kb
    ik = kb.get("inline_keyboard")
    if not ik: return kb
    for row in ik:
        for btn in row:
            data = btn.get("callback_data")
            if not data: continue
            if len(data) <= 60 and data.startswith(("qs:","qs2:","more:","less:")): continue
            h = hashlib.sha1(data.encode("utf-8")).hexdigest()[:10]
            token = f"cb:{h}"; cb_cache.set(token, data); btn["callback_data"] = token
    return {"inline_keyboard": ik}

def _rewrite_keyboard_to_addr(addr, kb: dict, add_more_btn: bool = True):
    if not kb or not isinstance(kb, dict): kb = {}
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
                btn = dict(btn); btn["callback_data"] = f"qs:{addr}?window={window}"
            new_row.append(btn)
        out.append(new_row)
    if add_more_btn and addr:
        out.append([{"text": "🔎 More details", "callback_data": f"more:{addr}"}])
    return {"inline_keyboard": out} if out else kb

def _send_text(chat_id, text, **kwargs):
    text = NEWLINE_ESC_RE.sub("\n", text or "")
    return tg_send_message(TELEGRAM_TOKEN, chat_id, text, **kwargs)

@app.route("/debug_known")
def debug_known():
    diags = []
    for p in _collect_paths():
        diags.append(_merge_known_from(p, diag_only=True))
    return jsonify({"version": APP_VERSION, "paths": _collect_paths(), "loaded_runtime": len(KNOWN_HOMEPAGES), "diagnostics": diags})

@app.route("/reload_known", methods=["POST","GET"])
def reload_known():
    _maybe_reload_known(force=True)
    return jsonify({"ok": True, "loaded_runtime": len(KNOWN_HOMEPAGES), "sources": KNOWN_SOURCES})

@app.route("/webhook/<secret>", methods=["POST"])
@require_webhook_secret
def webhook(secret):
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET: return ("forbidden", 403)
    _maybe_reload_known(force=False)
    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        return ("ok", 200)

    if "callback_query" in update:
        cq = update["callback_query"]; chat_id = cq["message"]["chat"]["id"]
        data = cq.get("data",""); msg_obj = cq.get("message",{}); msg_id = str(msg_obj.get("message_id"))
        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS: return ("ok", 200)
        if data.startswith("cb:"):
            orig = cb_cache.get(data); 
            if orig: data = orig
            else: tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "expired", logger=app.logger); return ("ok", 200)

        cqid = cq.get("id")
        if cqid and seen_callbacks.get(cqid):
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "updated", logger=app.logger); return ("ok", 200)
        if cqid: seen_callbacks.set(cqid, True)

        try:
            if data.startswith("more:"):
                payload_addr = data.split(":",1)[1].strip().lower()
                addr = payload_addr if ADDR_RE.fullmatch(payload_addr) else None
                if not addr:
                    # try recover from keyboard: prefer known addr in pair
                    addrs = _extract_addrs_from_pair_payload((msg_obj.get("reply_markup") or {}).get("inline_keyboard", [{}])[0].get("callback_data","qs2::"))
                    addr = _pick_addr(addrs) or _extract_addr_from_text(msg_obj.get("text") or "")
                if DEBUG_MORE: tg_answer_callback(TELEGRAM_TOKEN, cq["id"], f"Full scan {addr}", logger=app.logger)
                if not addr:
                    tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "address?", logger=app.logger); return ("ok", 200)
                text, keyboard = quickscan_entrypoint(addr, lang="en", lean=False)
                text = _enrich_full(addr, text)
                keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=False)

            elif data.startswith("qs2:"):
                # choose stable/known address from pair
                addrs = _extract_addrs_from_pair_payload(data)
                base_addr = _pick_addr(addrs)
                _, _, window = data.partition("?window="); window = window or "h24"
                chain = data.split(":",1)[1].split("/",1)[0]
                text, keyboard = quickscan_pair_entrypoint(chain, "-".join(addrs) if addrs else "", window=window)
                keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))

            elif data.startswith("qs:"):
                addr, _, window = data.split(":",1)[1].partition("?window="); window = window or "h24"
                text, keyboard = quickscan_entrypoint(addr, lang="en", window=window, lean=True)
                keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=True)
            else:
                return ("ok", 200)

            keyboard = {"inline_keyboard": keyboard.get("inline_keyboard", [])} if isinstance(keyboard, dict) else keyboard
            tg_send_message(TELEGRAM_TOKEN, chat_id, NEWLINE_ESC_RE.sub("\n", text), reply_markup=keyboard, logger=app.logger)
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "updated", logger=app.logger)
        except Exception:
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "error", logger=app.logger)
        return ("ok", 200)

    msg = update.get("message") or update.get("edited_message")
    if not msg or (msg.get("from") or {}).get("is_bot"): return ("ok", 200)
    chat_id = msg["chat"]["id"]; text = (msg.get("text") or "").strip()
    if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS: return ("ok", 200)

    if not text:
        _send_text(chat_id, "empty", logger=app.logger); return ("ok", 200)

    if text.startswith("/"):
        cmd, *rest = text.split(maxsplit=1); arg = rest[0] if rest else ""
        if cmd in ("/start","/help"):
            _send_text(chat_id, LOC("en","help").format(bot=BOT_USERNAME), parse_mode="Markdown", logger=app.logger); return ("ok", 200)
        if cmd == "/debug_known":
            diags = []; 
            for p in _collect_paths(): diags.append(_merge_known_from(p, diag_only=True))
            _send_text(chat_id, f"paths={_collect_paths()}; loaded={len(KNOWN_HOMEPAGES)}; diags={diags}", logger=app.logger); return ("ok", 200)
        if cmd == "/reload_known":
            _maybe_reload_known(force=True); _send_text(chat_id, f"reloaded; loaded={len(KNOWN_HOMEPAGES)}", logger=app.logger); return ("ok", 200)
        if cmd in ("/quickscan","/scan"):
            if not arg: _send_text(chat_id, LOC("en","scan_usage"), logger=app.logger)
            else:
                try:
                    text_out, keyboard = quickscan_entrypoint(arg, lang="en", lean=True)
                    base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(arg)
                    keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
                    keyboard = _compress_keyboard(keyboard)
                    st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                    _store_addr_for_message(body, base_addr)
                except Exception:
                    _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
            return ("ok", 200)
        _send_text(chat_id, LOC("en","unknown"), logger=app.logger); return ("ok", 200)

    _send_text(chat_id, "Processing…", logger=app.logger)
    try:
        text_out, keyboard = quickscan_entrypoint(text, lang="en", lean=True)
        base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(text)
        keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
        keyboard = _compress_keyboard(keyboard)
        st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
        _store_addr_for_message(body, base_addr)
    except Exception:
        _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
    return ("ok", 200)

if __name__ == "__main__":
    port = int(os.environ.get("PORT","10000"))
    app.run(host="0.0.0.0", port=port)
