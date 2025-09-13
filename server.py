import os, re, json, ssl, socket, hashlib, time, threading, tempfile
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from functools import wraps
import requests
from flask import Flask, request, jsonify

# Project-local utilities
from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

# ========================
# Environment & constants
# ========================
APP_VERSION = os.environ.get("APP_VERSION", "0.5.4-report-header")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")  # numeric string
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "6.0"))
KNOWN_AUTORELOAD_SEC = int(os.environ.get("KNOWN_AUTORELOAD_SEC", "300"))

# Domain meta TTLs
try:
    DOMAIN_META_TTL = int(os.getenv("DOMAIN_META_TTL", "2592000"))      # 30 days
    DOMAIN_META_TTL_NEG = int(os.getenv("DOMAIN_META_TTL_NEG", "120"))  # 2 min for negative WB
except Exception:
    DOMAIN_META_TTL = 2592000
    DOMAIN_META_TTL_NEG = 120

LOC = locale_text
app = Flask(__name__)

# Caches
cache = SafeCache(ttl=CACHE_TTL_SECONDS)          # general cache if needed
seen_callbacks = SafeCache(ttl=300)               # dedupe callback ids
cb_cache = SafeCache(ttl=600)                     # long callback payloads by hash
msg2addr = SafeCache(ttl=86400)                   # message_id -> base address mapping (for Why?)
recent_actions = SafeCache(ttl=20)                # action-level dedupe across messages/taps
RISK_CACHE = {}                                   # addr -> {score,label,neg,pos,w_neg,w_pos}

ADDR_RE = re.compile(r'0x[a-fA-F0-9]{40}')
NEWLINE_ESC_RE = re.compile(r'\n')

# Known homepages (seed); can be extended at runtime
KNOWN_HOMEPAGES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "circle.com",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "tether.to",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "makerdao.com",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum.org",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "bitcoin.org",
}

# Domain metadata cache
DOMAIN_META_CACHE = {}  # domain -> {t, h, created, reg, exp, issuer, wb}
KNOWN_SOURCES = []
KNOWN_PATHS = []
KNOWN_LAST_CHECK = 0
KNOWN_MTIME = {}
KNOWN_LOCK = threading.Lock()

# Whitelists
WL_DOMAINS_DEFAULT = {
    "circle.com","tether.to","makerdao.com","frax.finance","binance.com","gemini.com","paxos.com",
    "lido.fi","curve.fi","synthetix.io","liquity.org","paypal.com","firstdigital.com"
}
WL_ADDRESSES_DEFAULT = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0x853d955acef822db058eb8505911ed77f175b99e",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
}
def _env_set(name):
    try:
        v = os.getenv(name, "")
        return set([s.strip().lower() for s in v.split(",") if s.strip()])
    except Exception:
        return set()
WL_DOMAINS = set([d.lower() for d in WL_DOMAINS_DEFAULT]) | _env_set("WL_DOMAINS")
WL_ADDRESSES = set([a.lower() for a in WL_ADDRESSES_DEFAULT]) | _env_set("WL_ADDRESSES")

# ========================
# Helpers
# ========================
def _norm_domain(url: str):
    if not url: return None
    try:
        u = urlparse(url.strip())
        host = u.netloc or u.path
        host = (host or "").lower()
        if host.startswith("www."): host = host[4:]
        return host.strip("/")
    except Exception:
        return None

def _collect_paths():
    paths = [os.path.join(os.path.dirname(__file__), "known_domains.json")]
    envp = os.getenv("KNOWN_DOMAINS_FILE") or os.getenv("KNOWN_DOMAINS_PATH")
    if envp and envp not in paths: paths.append(envp)
    return paths

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

def _send_text(chat_id, text, **kwargs):
    text = NEWLINE_ESC_RE.sub("\n", text or "")
    return tg_send_message(TELEGRAM_TOKEN, chat_id, text, **kwargs)

def _tg_send_document(token: str, chat_id: int, filepath: str, caption: str = None):
    try:
        url = f"https://api.telegram.org/bot{token}/sendDocument"
        with open(filepath, "rb") as f:
            files = {"document": (os.path.basename(filepath), f, "text/html")}
            data = {"chat_id": chat_id}
            if caption:
                data["caption"] = caption[:1000]
            r = requests.post(url, data=data, files=files, timeout=20)
        try:
            return True, r.json()
        except Exception:
            return False, {"ok": False, "status": r.status_code}
    except Exception as e:
        return False, {"ok": False, "error": str(e)}

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
            if len(data) <= 60 and data.startswith(("qs:","qs2:","more:","less:","why:","rep:","hp:","lp:","mon:")): continue
            h = hashlib.sha1(data.encode("utf-8")).hexdigest()[:10]
            token = f"cb:{h}"; cb_cache.set(token, data); btn["callback_data"] = token
    return {"inline_keyboard": ik}

def _ensure_action_buttons(addr, kb: dict, add_more=False, add_why=True, add_report=True):
    ik = (kb or {}).get("inline_keyboard") or []
    new_rows = []
    if add_more and addr:
        new_rows.append([{"text": "🔎 More details", "callback_data": f"more:{addr}"}])
    row = []
    if add_why and addr: row.append({"text": "❓ Why?", "callback_data": f"why:{addr}"})
    if add_report and addr: row.append({"text": "📄 Report (HTML)", "callback_data": f"rep:{addr}"})
    if row: new_rows.append(row)
    if new_rows: ik.extend(new_rows)
    return {"inline_keyboard": ik} if ik else None


def _kb_clone(kb):
    if not kb or not isinstance(kb, dict): return {"inline_keyboard": []}
    ik = kb.get("inline_keyboard") or []
    # deep-ish copy
    return {"inline_keyboard": [ [dict(btn) for btn in row] for row in ik ]}

def _kb_strip_prefixes(kb, prefixes):
    base = _kb_clone(kb)
    ik = base["inline_keyboard"]
    out = []
    for row in ik:
        new_row = []
        for btn in row:
            data = (btn.get("callback_data") or "")
            if any(data.startswith(p) for p in prefixes):
                continue
            new_row.append(btn)
        if new_row:
            out.append(new_row)
    return {"inline_keyboard": out}

def _kb_has_prefix(kb, prefix):
    if not kb or not isinstance(kb, dict): return False
    for row in kb.get("inline_keyboard") or []:
        for btn in row:
            data = (btn.get("callback_data") or "")
            if data.startswith(prefix):
                return True
    return False

def _ensure_action_buttons(addr, kb, want_more=False, want_why=True, want_report=True):
    # 1) remove duplicates (strip existing more/why/rep)
    base = _kb_strip_prefixes(kb, ("more:", "why", "rep:"))
    ik = base.get("inline_keyboard") or []
    # 2) append requested buttons exactly once
    if want_more and addr:
        ik.append([{"text": "🔎 More details", "callback_data": f"more:{addr}"}])
    row = []
    if want_why and addr:
        row.append({"text": "❓ Why?", "callback_data": f"why:{addr}"})
    if want_report and addr:
        row.append({"text": "📄 Report (HTML)", "callback_data": f"rep:{addr}"})
    if row:
        ik.append(row)
    return {"inline_keyboard": ik}
def _extract_addrs_from_pair_payload(data: str):
    try:
        path, _, _ = data.split(":", 1)[1].partition("?")
        _, _, pair_addr = path.partition("/")
        parts = [p for p in pair_addr.split("-") if ADDR_RE.fullmatch(p)]
        return [p.lower() for p in parts]
    except Exception:
        return []

def _pick_addr(addrs):
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

# ========================
# Domain meta (RDAP/SSL/WB)
# ========================
def _normalize_date_iso(s: str):
    try:
        if not s or s == "—": return "—"
        s = s.strip()
        m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
        if m: return m.group(1)
        try:
            dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            pass
        m = re.match(r"^(\d{4})(\d{2})(\d{2})", s)
        if m: return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        return s
    except Exception:
        return s or "—"

def _normalize_registrar(reg: str, handle: str, domain: str):
    reg = reg or "—"
    h = (handle or "").upper()
    if "GOVERNMENT OF KINGDOM OF TONGA" in reg.upper() or "TONIC" in h or domain.endswith(".to"):
        return "Tonic (.to)"
    return reg

def _rdap(domain: str):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=HTTP_TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
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
        with socket.create_connection((domain, 443), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        exp = cert.get("notAfter","—")
        issuer = cert.get("issuer",[])
        cn = "—"
        for tup in issuer:
            for k,v in tup:
                if k.lower()=="commonName".lower(): cn=v; break
        return (_normalize_date_iso(exp), cn)
    except Exception: return ("—","—")

def _wayback_available(domain: str):
    try:
        headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
        for scheme in ("http","https"):
            url = "https://archive.org/wayback/available"
            params = {"url": f"{scheme}://{domain}/", "timestamp": "19960101"}
            r = requests.get(url, params=params, timeout=6, headers=headers)
            if r.status_code != 200:
                continue
            j = r.json() or {}
            snap = (j.get("archived_snapshots") or {}).get("closest") or {}
            ts = snap.get("timestamp")
            if ts and len(ts) >= 8:
                return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass
    return None

def _wayback_cdx(domain: str, require_200: bool):
    headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
    for host in (domain, f"www.{domain}"):
        for scheme in ("http","https"):
            for path in (f"{scheme}://{host}/*", f"{scheme}://{host}/"):
                try:
                    params = {
                        "url": path,
                        "output": "json",
                        "fl": "timestamp,statuscode,original",
                        "limit": "1",
                        "from": "1996",
                        "to": "2035",
                        "collapse": "timestamp:8"
                    }
                    if require_200:
                        params["filter"] = "statuscode:200"
                    r = requests.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=8, headers=headers)
                    if r.status_code != 200:
                        continue
                    j = r.json()
                    if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and len(j[1]) >= 1:
                        ts = str(j[1][0])
                        if len(ts) >= 8:
                            return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
                except Exception:
                    continue
    return None

def _wayback_first(domain: str):
    try:
        d = _wayback_cdx(domain, require_200=True)
        if d: return d
        d = _wayback_cdx(domain, require_200=False)
        if d: return d
        d = _wayback_available(domain)
        return d or "—"
    except Exception:
        return "—"

def _domain_meta(domain: str):
    now = int(time.time())
    ent = DOMAIN_META_CACHE.get(domain)
    if ent:
        ttl = DOMAIN_META_TTL_NEG if ent.get("wb") in (None, "—") else DOMAIN_META_TTL
        if now - ent.get("t",0) < ttl:
            return ent["h"], ent["created"], ent["reg"], ent["exp"], ent["issuer"], ent.get("wb","—")
    h, created, reg = _rdap(domain)
    exp, issuer = _ssl_info(domain)
    wb = _wayback_first(domain)
    created = _normalize_date_iso(created)
    reg = _normalize_registrar(reg, h, domain)
    DOMAIN_META_CACHE[domain] = {"t": now, "h": h, "created": created, "reg": reg, "exp": exp, "issuer": issuer, "wb": wb}
    return h, created, reg, exp, issuer, wb

def _cg_homepage(addr: str):
    addr_l = (addr or "").lower()
    if addr_l in KNOWN_HOMEPAGES: return KNOWN_HOMEPAGES[addr_l]
    try:
        url = f"https://api.coingecko.com/api/v3/coins/ethereum/contract/{addr_l}"
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")})
        if r.status_code != 200: return None
        data = r.json()
        hp = (data.get("links") or {}).get("homepage") or []
        for u in hp:
            d = _norm_domain(u)
            if d: return d
    except Exception:
        return None
    return None

def _symbol_homepage_hint(text: str):
    t = (text or "").upper()
    hints = [
        ("USDT", "tether.to"),
        ("USDC", "circle.com"),
        ("DAI", "makerdao.com"),
        ("TUSD", "tusd.io"),
        ("FRAX", "frax.finance"),
        ("WBTC", "wbtc.network"),
        ("ETH", "ethereum.org"),
        ("BUSD", "binance.com"),
        ("USDP", "paxos.com"),
        ("GUSD", "gemini.com"),
        ("PYUSD", "paypal.com"),
        ("FDUSD", "firstdigital.com"),
        ("LUSD", "liquity.org"),
        ("SUSD", "synthetix.io"),
        ("CRVUSD", "curve.fi"),
        ("USDE", "ether.fi"),
    ]
    for sym, dom in hints:
        if sym in t: return dom
    return None

def _extract_domain_from_text(text: str):
    try:
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("Domain:"):
                dom = line.split(":",1)[1].strip()
                if dom and (" " not in dom) and ("." in dom):
                    return dom
    except Exception:
        return None
    return None

# ========================
# Risk engine (weighted)
# ========================
try:
    RISK_LIQ_LOW = float(os.getenv("RISK_LIQ_LOW", "20000"))      # <$20k => +25
    RISK_LIQ_MED = float(os.getenv("RISK_LIQ_MED", "100000"))     # <$100k => +10
    RISK_VOL_LOW = float(os.getenv("RISK_VOL_LOW", "5000"))       # <  $5k => +10
    RISK_THRESH_CAUTION = int(os.getenv("RISK_THRESH_CAUTION", "30"))
    RISK_THRESH_HIGH    = int(os.getenv("RISK_THRESH_HIGH", "60"))
    RISK_POSITIVE_LIQ   = float(os.getenv("RISK_POSITIVE_LIQ", "1000000"))  # >$1M => positive
    RISK_POSITIVE_AGE_Y = int(os.getenv("RISK_POSITIVE_AGE_Y", "2018"))     # domain created <=2018 => positive
except Exception:
    RISK_LIQ_LOW = 20000.0; RISK_LIQ_MED = 100000.0; RISK_VOL_LOW = 5000.0
    RISK_THRESH_CAUTION = 30; RISK_THRESH_HIGH = 60
    RISK_POSITIVE_LIQ = 1_000_000.0; RISK_POSITIVE_AGE_Y = 2018

def _parse_float_km(s):
    try:
        s = (s or "").strip().upper().replace("$","")
        m = re.match(r'^([0-9]+(?:\.[0-9]+)?)\s*([KMB])?$', s)
        if not m: return None
        num = float(m.group(1))
        suf = m.group(2) or ""
        mult = {"K":1e3, "M":1e6, "B":1e9}.get(suf, 1.0)
        return num*mult
    except Exception:
        return None

def _parse_metric_from_dexline(text, key):
    try:
        patt = rf'{key}\s+([0-9\.\$]+\s*[KMB]?)'
        m = re.search(patt, text, re.IGNORECASE)
        return _parse_float_km(m.group(1)) if m else None
    except Exception:
        return None

def _parse_bool(text, key):
    try:
        m = re.search(rf'{re.escape(key)}:\s*(✅|✔️|Yes|True|No|❌|—)', text, re.IGNORECASE)
        if not m: return None
        val = m.group(1)
        return val in ("✅","✔️","Yes","True")
    except Exception:
        return None

def _parse_roles(text):
    roles = {}
    try:
        m = re.search(r'Roles:\s*([^\n]+)', text)
        if not m: return roles
        chunk = m.group(1)
        for pair in re.split(r'\s*\|\s*', chunk):
            kv = pair.split(":",1)
            if len(kv)==2:
                roles[kv[0].strip()] = ("✅" in kv[1]) or ("✔" in kv[1]) or ("Yes" in kv[1])
        return roles
    except Exception:
        return roles

def _parse_domain_meta(block):
    d={"created":None,"registrar":None,"ssl_exp":None,"wayback":None}
    try:
        m = re.search(r'Created:\s*([0-9\-TZ: ]+)', block); d["created"]=m.group(1) if m else None
        m = re.search(r'Registrar:\s*([^\n]+)', block); d["registrar"]=m.group(1).strip() if m else None
        m = re.search(r'Expires:\s*([0-9\-TZ: ]+)', block); d["ssl_exp"]=m.group(1) if m else None
        m = re.search(r'Wayback:\s*first\s+([0-9\-—]+)', block); d["wayback"]=m.group(1)
    except Exception:
        pass
    return d

def _is_whitelisted(addr: str, text: str):
    try:
        a = (addr or "").lower()
        if a in WL_ADDRESSES:
            return True, "address"
        dom = _extract_domain_from_text(text) or ""
        if dom.lower() in WL_DOMAINS:
            return True, "domain"
    except Exception:
        pass
    return False, None

def _risk_verdict(addr, text):
    score = 0
    neg = []
    pos = []
    weights_neg = []
    weights_pos = []
    whitelisted, wl_type = _is_whitelisted(addr, text)

    liq = _parse_metric_from_dexline(text, "Liq")
    vol = _parse_metric_from_dexline(text, "Vol24h")
    if liq is not None:
        if liq < RISK_LIQ_LOW:
            w = (8 if whitelisted else 25); score += w; neg.append("Low liquidity (<${:,})".format(int(RISK_LIQ_LOW))); weights_neg.append(w)
        elif liq < RISK_LIQ_MED:
            w = (3 if whitelisted else 10); score += w; neg.append("Moderate liquidity (<${:,})".format(int(RISK_LIQ_MED))); weights_neg.append(w)
        elif liq >= RISK_POSITIVE_LIQ:
            w = 15; pos.append("High liquidity (≥${:,})".format(int(RISK_POSITIVE_LIQ))); weights_pos.append(w)
    if vol is not None and vol < RISK_VOL_LOW:
        w = 10; score += w; neg.append("Very low 24h volume (<$5k)"); weights_neg.append(w)

    t_upper = (text or "").upper()
    if whitelisted:
        w = 20; pos.append(f"Whitelisted by {wl_type}"); weights_pos.append(w)
    if ("USDT" in t_upper and "USDC" in t_upper) or ("WBTC" in t_upper and "ETH" in t_upper):
        w = 10; pos.append("Blue-chip pair context"); weights_pos.append(w)

    proxy = _parse_bool(text, "Proxy")
    if proxy is True:
        w = (0 if whitelisted else 15); score += w; neg.append("Upgradeable proxy (owner can change logic)"); weights_neg.append(w)

    roles = _parse_roles(text)
    if roles.get("owner", False):
        w = (0 if whitelisted else 20); score += w; neg.append("Owner privileges present"); weights_neg.append(w)
    if roles.get("blacklister", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Blacklisting capability"); weights_neg.append(w)
    if roles.get("pauser", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Pausing capability"); weights_neg.append(w)
    if roles.get("minter", False) or roles.get("masterMinter", False):
        w = (0 if whitelisted else 10); score += w; neg.append("Minting capability"); weights_neg.append(w)

    dom = _parse_domain_meta(text)
    try:
        if dom.get("created") and dom["created"] != "—":
            y = int(dom["created"][:4])
            if y >= 2024: w=15; score += w; neg.append("Very new domain"); weights_neg.append(w)
            elif y >= 2022: w=5; score += w; neg.append("Newish domain"); weights_neg.append(w)
            elif y <= RISK_POSITIVE_AGE_Y: w=10; pos.append(f"Established domain (≤{RISK_POSITIVE_AGE_Y})"); weights_pos.append(w)
        if dom.get("wayback") in (None, "—"):
            if not whitelisted:
                w=5; score += w; neg.append("No Wayback snapshots"); weights_neg.append(w)
            else:
                w=8; pos.append("Trusted (no WB penalty)"); weights_pos.append(w)
        else:
            w=8; pos.append("Historical presence (Wayback found)"); weights_pos.append(w)
    except Exception:
        pass

    if score >= RISK_THRESH_HIGH: label = "HIGH RISK 🔴"
    elif score >= RISK_THRESH_CAUTION: label = "CAUTION 🟡"
    else: label = "LOW RISK 🟢"
    return int(min(100, score)), label, {"neg": neg, "pos": pos, "w_neg": weights_neg, "w_pos": weights_pos}

def _append_verdict_block(addr, text):
    score, label, rs = _risk_verdict(addr, text)
    try:
        RISK_CACHE[(addr or "").lower()] = {"score": score, "label": label, "neg": rs.get("neg", []), "pos": rs.get("pos", []), "w_neg": rs.get("w_neg", []), "w_pos": rs.get("w_pos", [])}
    except Exception:
        pass
    lines = [f"Trust verdict: {label} (score {score}/100)"]
    if rs.get("neg"):
        lines.append("⚠️ Signals: " + "; ".join(rs["neg"]))
    if rs.get("pos"):
        lines.append("✅ Positives: " + "; ".join(rs["pos"]))
    return text + "\n" + "\n".join(lines)

def _enrich_full(addr: str, text: str):
    txt = NEWLINE_ESC_RE.sub("\n", text or "")
    domain = _cg_homepage(addr) or _symbol_homepage_hint(txt)
    if not domain:
        return txt
    h, created, reg, exp, issuer, wb = _domain_meta(domain)
    block = f"Domain: {domain}\nWHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}\nSSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}\nWayback: first {wb}"
    import re as _re
    if "Domain:" in txt:
        txt = _re.sub(r"Domain:.*", f"Domain: {domain}", txt)
        txt = _re.sub(r"WHOIS/RDAP:.*", f"WHOIS/RDAP: {h} | Created: {created} | Registrar: {reg}", txt)
        txt = _re.sub(r"SSL:.*", f"SSL: {('OK' if exp!='—' else '—')} | Expires: {exp} | Issuer: {issuer}", txt)
        txt = _re.sub(r"Wayback:.*", f"Wayback: first {wb}", txt)
        return txt
    return txt + "\n" + block


def _render_report(addr: str, text: str):
    info = RISK_CACHE.get((addr or "").lower()) or {}
    neg = info.get("neg") or []
    pos = info.get("pos") or []
    wn = info.get("w_neg") or []
    wp = info.get("w_pos") or []
    def lines(items, weights):
        out = []
        for i, t in enumerate(items):
            w = weights[i] if i < len(weights) else None
            out.append(f"- {t}" + (f" (+{w})" if isinstance(w, (int,float)) else ""))
        return "\n".join(out) if out else "—"
    # Subject parsing
    dom = _extract_domain_from_text(text) or "—"
    pair = None; chain = None; dex = None
    try:
        # Example: "USDC/USDT on curve (ethereum)"
        m = re.search(r"^\s*([A-Za-z0-9_\-\.\/]+)\s+on\s+([A-Za-z0-9_\-\.]+)\s*\(([^)]+)\)", text, re.IGNORECASE | re.MULTILINE)
        if m:
            pair, dex, chain = m.group(1), m.group(2), m.group(3)
        else:
            # Fallback: just chain in parentheses on first lines
            m2 = re.search(r"\((ethereum|bsc|polygon|base|arbitrum|optimism|avalanche|solana|tron)[^)]*\)", text, re.IGNORECASE)
            if m2: chain = m2.group(1)
    except Exception:
        pass
    # Timestamp and optional scanner URL
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    scanner_url = os.getenv("SCANNER_URL", "").strip()
    # Build HTML
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Metridex Report — {addr}</title>
<style>body{{font-family:Arial,Helvetica,sans-serif;max-width:900px;margin:20px auto;}}h1,h2{{margin:0.5em 0}}.box{{border:1px solid #ddd;padding:12px;border-radius:8px;margin:12px 0;white-space:pre-wrap}}</style>
</head><body>
<h1>Metridex QuickScan — Report</h1>
<div class="box"><b>Generated:</b> {ts}<br><b>Address:</b> {addr}<br>""" + (f"<b>Pair:</b> {pair} " if pair else "") + (f"<b>on:</b> {dex} " if dex else "") + (f"<b>Chain:</b> {chain}<br>" if chain else "<br>") + f"""<b>Domain:</b> {dom}""" + (f"<br><b>Scanner:</b> {scanner_url}" if scanner_url else "") + """</div>
<div class="box"><h2>Summary</h2><pre>""" + text + """</pre></div>
<div class="box"><h2>Risk verdict</h2><p><b>""" + str(info.get('label','?')) + " (" + str(info.get('score','?')) + """/100)</b></p>
<h3>Signals</h3><pre>""" + lines(neg, wn) + """</pre><h3>Positives</h3><pre>""" + lines(pos, wp) + """</pre></div>
<footer><small>Generated by Metridex</small></footer>
</body></html>"""
    try:
        tsf = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_addr = (addr or "unknown")[:10]
        filename = f"metridex_report_{safe_addr}_{tsf}.html"
        import tempfile, os as _os
        path = _os.path.join(tempfile.gettempdir(), filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path, html
    except Exception:
        return None, html

# ========================
# HTTP routes
# ========================
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "version": APP_VERSION})

@app.route("/reload_meta", methods=["POST","GET"])
def reload_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True})

# ========================
# Telegram webhook & callbacks
# ========================
def _answer_why_quickly(cq, addr_hint=None):
    try:
        msg_obj = cq.get("message", {}) or {}
        text = msg_obj.get("text") or ""
        addr = (addr_hint or msg2addr.get(str(msg_obj.get("message_id"))) or _extract_addr_from_text(text) or "").lower()
        info = RISK_CACHE.get(addr) if addr else None
        if not info:
            score, label, rs = _risk_verdict(addr or "", text or "")
            info = {"score": score, "label": label, "neg": rs.get("neg", []), "pos": rs.get("pos", []), "w_neg": rs.get("w_neg", []), "w_pos": rs.get("w_pos", [])}
        pairs_neg = list(zip(info.get("neg", []), info.get("w_neg", [])))
        pairs_pos = list(zip(info.get("pos", []), info.get("w_pos", [])))
        pairs_neg.sort(key=lambda x: x[1] if isinstance(x[1], (int,float)) else 0, reverse=True)
        pairs_pos.sort(key=lambda x: x[1] if isinstance(x[1], (int,float)) else 0, reverse=True)
        neg_s = "; ".join([f"{t} (+{w})" for t,w in pairs_neg[:2] if t]) if pairs_neg else ""
        pos_s = "; ".join([f"{t} (+{w})" for t,w in pairs_pos[:2] if t]) if pairs_pos else ""
        body = f"{info.get('label','?')} ({info.get('score',0)}/100)"
        if neg_s: body += f" — ⚠️ {neg_s}"
        if pos_s: body += f" — ✅ {pos_s}"
        if len(body) > 190: body = body[:187] + "…"
        tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), body, logger=app.logger)
    except Exception:
        tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "No cached reasons yet. Tap “More details” first.", logger=app.logger)

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
        cq = update["callback_query"]
        chat_id = cq["message"]["chat"]["id"]
        data = cq.get("data","")
        msg_obj = cq.get("message",{})
        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS: return ("ok", 200)

        if data.startswith("cb:"):
            orig = cb_cache.get(data)
            if orig: data = orig
            else:
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "expired", logger=app.logger)
                return ("ok", 200)

        cqid = cq.get("id")
        if cqid and seen_callbacks.get(cqid):
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "updated", logger=app.logger); return ("ok", 200)
        if cqid: seen_callbacks.set(cqid, True)

        try:
            if data.startswith("qs2:"):
                addrs = _extract_addrs_from_pair_payload(data)
                base_addr = _pick_addr(addrs)
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "updating…", logger=app.logger)
                text_out, keyboard = quickscan_pair_entrypoint(data, lang="en", lean=True)
                base_addr = base_addr or _extract_base_addr_from_keyboard(keyboard)
                keyboard = _ensure_action_buttons(base_addr, keyboard, add_more=True, add_why=True, add_report=True)
                keyboard = _compress_keyboard(keyboard)
                st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                _store_addr_for_message(body, base_addr)
                return ("ok", 200)

            if data.startswith("qs:"):
                payload = data.split(":", 1)[1]
                base_addr = payload.split("?", 1)[0]
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "updating…", logger=app.logger)
                text_out, keyboard = quickscan_entrypoint(base_addr, lang="en", lean=True)
                keyboard = _ensure_action_buttons(base_addr, keyboard, add_more=True, add_why=True, add_report=True)
                keyboard = _compress_keyboard(keyboard)
                st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                _store_addr_for_message(body, base_addr)
                return ("ok", 200)

            if data.startswith("more:"):
                addr = data.split(":",1)[1].strip().lower()
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "loading…", logger=app.logger)
                base_text = msg_obj.get("text") or ""
                enriched = _enrich_full(addr, base_text)
                enriched = _append_verdict_block(addr, enriched)
                kb0 = msg_obj.get("reply_markup") or {}
                kb1 = _ensure_action_buttons(addr, kb0, add_more=False, add_why=True, add_report=True)
                kb1 = _compress_keyboard(kb1)
                st, body = _send_text(chat_id, enriched, reply_markup=kb1, logger=app.logger)
                _store_addr_for_message(body, addr)
                return ("ok", 200)

            if data.startswith("why"):
                addr_hint = None
                if ":" in data:
                    addr_hint = data.split(":",1)[1].strip().lower()
                _answer_why_quickly(cq, addr_hint=addr_hint)
                return ("ok", 200)

            if data.startswith("rep:"):
                addr = data.split(":",1)[1].strip().lower()
                act_key = f"rep:{chat_id}:{addr}"
                if recent_actions.get(act_key):
                    tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "report already sent", logger=app.logger)
                    return ("ok", 200)
                recent_actions.set(act_key, True)

                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "building report…", logger=app.logger)
                base_text = msg_obj.get("text") or ""
                path, html = _render_report(addr, base_text)
                caption = ""
                info = RISK_CACHE.get(addr) or {}
                if info:
                    caption = f"{info.get('label','?')} (score {info.get('score','?')}/100)"
                sent = False
                if path:
                    sent, resp = _tg_send_document(TELEGRAM_TOKEN, chat_id, path, caption=caption)
                if not sent:
                    teaser = "Report ready.\n" + (caption + "\n" if caption else "") + "⚠️/✅ details above."
                    _send_text(chat_id, teaser, logger=app.logger)
                return ("ok", 200)

            tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "unknown", logger=app.logger)
            return ("ok", 200)
        except Exception:
            tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), "error", logger=app.logger)
            return ("ok", 200)

    # Regular messages: keep simple (use /quickscan)
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
        if cmd in ("/reload_meta","/clear_meta"):
            if ADMIN_CHAT_ID and str(chat_id) != str(ADMIN_CHAT_ID):
                _send_text(chat_id, "403: forbidden", logger=app.logger); return ("ok", 200)
            DOMAIN_META_CACHE.clear()
            _send_text(chat_id, "Meta cache cleared ✅", logger=app.logger); return ("ok", 200)
        if cmd in ("/quickscan","/scan"):
            if not arg: _send_text(chat_id, LOC("en","scan_usage"), logger=app.logger)
            else:
                try:
                    text_out, keyboard = quickscan_entrypoint(arg, lang="en", lean=True)
                    base_addr = _extract_base_addr_from_keyboard(keyboard) or _extract_addr_from_text(arg)
                    keyboard = _ensure_action_buttons(base_addr, keyboard, add_more=True, add_why=True, add_report=True)
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
        keyboard = _ensure_action_buttons(base_addr, keyboard, add_more=True, add_why=True, add_report=True)
        keyboard = _compress_keyboard(keyboard)
        st, body = _send_text(chat_id, text_out, reply_markup=keyboard, logger=app.logger)
        _store_addr_for_message(body, base_addr)
    except Exception:
        _send_text(chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
    return ("ok", 200)
