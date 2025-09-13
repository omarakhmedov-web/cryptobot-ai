import os, re, json, ssl, socket, hashlib, time, threading
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from functools import wraps
import requests
from flask import Flask, request, jsonify

from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")
APP_VERSION = os.environ.get("APP_VERSION", "0.4.3-wl+why+wbfix+cmds")
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

# === Domain metadata cache (RDAP/SSL/Wayback) ===
DOMAIN_META_CACHE = {}
try:
    DOMAIN_META_TTL = int(os.getenv("DOMAIN_META_TTL", "2592000"))  # 30 days
    DOMAIN_META_TTL_NEG = int(os.getenv("DOMAIN_META_TTL_NEG", "600"))  # 10 minutes for negative WB
except Exception:
    DOMAIN_META_TTL = 2592000
    DOMAIN_META_TTL_NEG = 600

def _normalize_date_iso(s: str):
    try:
        import re as _re
        from datetime import datetime as _dt
        if not s or s == "—":
            return "—"
        s = s.strip()
        # Already ISO: 2025-10-24T11:51:46Z -> 2025-10-24
        m = _re.match(r"^(\d{4}-\d{2}-\d{2})", s)
        if m: return m.group(1)
        # OpenSSL: "Oct 23 23:59:59 2025 GMT"
        try:
            dt = _dt.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            pass
        # Compact yyyymmdd
        m = _re.match(r"^(\d{4})(\d{2})(\d{2})", s)
        if m: return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        # Fallback: keep original (better than truncation)
        return s
    except Exception:
        return s or "—"


def _normalize_registrar(reg: str, handle: str, domain: str):
    reg = reg or "—"
    h = (handle or "").upper()
    if "GOVERNMENT OF KINGDOM OF TONGA" in reg.upper() or "TONIC" in h or domain.endswith(".to"):
        return "Tonic (.to)"
    return reg

def _domain_meta(domain: str):
    import time
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
    exp = _normalize_date_iso(exp)
    reg = _normalize_registrar(reg, h, domain)
    DOMAIN_META_CACHE[domain] = {"t": now, "h": h, "created": created, "reg": reg, "exp": exp, "issuer": issuer, "wb": wb}
    return h, created, reg, exp, issuer, wb

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


def _symbol_homepage_hint(text: str):
    """
    Fallback mapping when contract->homepage cannot be resolved (non-ETH chains, bridges).
    Looks for well-known stable/bluechip symbols in the text block and returns canonical domain.
    """
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
        if sym in t:
            return dom
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
    """
    Robust Wayback lookup using CDX API with multiple candidates:
    http/https + with/without www. Returns '—' if nothing found.
    """
    try:
        import requests, os
        candidates = [
            f"http://{domain}/*",
            f"https://{domain}/*",
            f"http://www.{domain}/*",
            f"https://www.{domain}/*",
        ]
        headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
        for target in candidates:
            url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": target,
                "output": "json",
                "fl": "timestamp,statuscode,original",
                "filter": "statuscode:200",
                "limit": "1",
                "from": "2000",
                "to": "2035",
            }
            r = requests.get(url, params=params, timeout=8, headers=headers)
            if r.status_code != 200: 
                continue
            j = r.json()
            if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and len(j[1]) >= 1:
                ts = str(j[1][0])
                if len(ts) >= 8:
                    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
        return "—"
    except Exception:
        return "—"



# === Simple risk engine (heuristic, no extra APIs) ===
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
    # e.g. "Liq 1.11M | Vol24h 14.66K"
    try:
        patt = rf'{key}\s+([0-9\.\$]+\s*[KMB]?)'
        m = re.search(patt, text, re.IGNORECASE)
        return _parse_float_km(m.group(1)) if m else None
    except Exception:
        return None

def _parse_bool(text, key):
    # e.g. "Proxy: ✅"
    try:
        m = re.search(rf'{re.escape(key)}:\s*(✅|✔️|Yes|True|No|❌|—)', text, re.IGNORECASE)
        if not m: return None
        val = m.group(1)
        return val in ("✅","✔️","Yes","True")
    except Exception:
        return None

def _parse_roles(text):
    # e.g. "Roles: owner: ✅ | masterMinter: ✅ | pauser: ✅ ..."
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
    # expects enriched block already appended (Domain / WHOIS / SSL / Wayback)
    # returns dict: created(date str), registrar(str), ssl_exp(str), wayback(str)
    d={"created":None,"registrar":None,"ssl_exp":None,"wayback":None}
    try:
        m = re.search(r'Created:\s*([0-9\-TZ: ]+)', block); d["created"]=m.group(1) if m else None
        m = re.search(r'Registrar:\s*([^\n]+)', block); d["registrar"]=m.group(1).strip() if m else None
        m = re.search(r'Expires:\s*([0-9\-TZ: ]+)', block); d["ssl_exp"]=m.group(1) if m else None
        m = re.search(r'Wayback:\s*first\s+([0-9\-—]+)', block); d["wayback"]=m.group(1)
    except Exception:
        pass
    return d

# === Risk thresholds (can be tuned via ENV) ===
# === Whitelist for top projects/contracts ===
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


# Risk detail cache for Why?
RISK_CACHE = {}

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
    """
    Heuristic score 0..100 (higher = riskier). Uses only what we already have in text.
    Returns (score:int, label:str, reasons:list[str])
    """
    score = 0
    reasons = []
    positives = []
    whitelisted, wl_type = _is_whitelisted(addr, text)

    # Dex metrics (liquidity and volume)
    liq = _parse_metric_from_dexline(text, "Liq")
    vol = _parse_metric_from_dexline(text, "Vol24h")
    if liq is not None:
        if liq < RISK_LIQ_LOW:
            score += (8 if whitelisted else 25); reasons.append(f"Low liquidity (<${int(RISK_LIQ_LOW):,})")
        elif liq < RISK_LIQ_MED:
            score += (3 if whitelisted else 10); reasons.append(f"Moderate liquidity (<${int(RISK_LIQ_MED):,})")
        elif liq >= RISK_POSITIVE_LIQ:
            positives.append(f"High liquidity (≥${int(RISK_POSITIVE_LIQ):,})")
    if vol is not None and vol < RISK_VOL_LOW:
        score += 10; reasons.append("Very low 24h volume (<$5k)")

    # Blue-chip pair heuristic
    try:
        t_upper = (text or "").upper()
        if whitelisted:
            positives.append(f"Whitelisted by {wl_type}")
        if ("USDT" in t_upper and "USDC" in t_upper) or ("WBTC" in t_upper and "ETH" in t_upper):
            positives.append("Blue-chip pair context")
    except Exception:
        pass

    # Proxy / Upgradable
    proxy = _parse_bool(text, "Proxy")
    if proxy is True:
        score += (0 if whitelisted else 15); reasons.append("Upgradeable proxy (owner can change logic)")

    # Owner / roles
    roles = _parse_roles(text)
    if roles.get("owner", False):
        score += (0 if whitelisted else 20); reasons.append("Owner privileges present")
    if roles.get("blacklister", False):
        score += (0 if whitelisted else 10); reasons.append("Blacklisting capability")
    if roles.get("pauser", False):
        score += (0 if whitelisted else 10); reasons.append("Pausing capability")
    if roles.get("minter", False) or roles.get("masterMinter", False):
        score += (0 if whitelisted else 10); reasons.append("Minting capability")

    # Domain metadata (age & wayback)
    dom = _parse_domain_meta(text)
    try:
        if dom.get("created") and dom["created"] != "—":
            y = int(dom["created"][:4])
            if y >= 2024: score += 15; reasons.append("Very new domain")
            elif y >= 2022: score += 5; reasons.append("Newish domain")
            elif y <= RISK_POSITIVE_AGE_Y: positives.append(f"Established domain (≤{RISK_POSITIVE_AGE_Y})")
        if dom.get("wayback") in (None, "—"):
            score += 5; reasons.append("No Wayback snapshots")
        else:
            positives.append("Historical presence (Wayback found)")
    except Exception:
        pass

    # Clamp & label
    if score >= RISK_THRESH_HIGH: label = "HIGH RISK 🔴"
    elif score >= RISK_THRESH_CAUTION: label = "CAUTION 🟡"
    else: label = "LOW RISK 🟢"
    return int(min(100, score)), label, {"neg": reasons, "pos": positives}

def _append_verdict_block(addr, text):
    score, label, rs = _risk_verdict(addr, text)
    # cache for Why?
    try:
        RISK_CACHE[addr.lower()] = {"score": score, "label": label, "neg": rs.get("neg", []), "pos": rs.get("pos", [])}
    except Exception:
        pass
    lines = [f"Trust verdict: {label} (score {score}/100)"]
    if rs.get("neg"):
        lines.append("⚠️ Signals: " + "; ".join(rs["neg"]))
    if rs.get("pos"):
        lines.append("✅ Positives: " + "; ".join(rs["pos"]))
    return text + "\n" + "\n".join(lines)


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
def _enrich_full(addr: str, text: str):
    txt = NEWLINE_ESC_RE.sub("\n", text or "")
    domain = _cg_homepage(addr)
    if not domain:
        domain = _symbol_homepage_hint(txt)
    if not domain: return txt
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


@app.route("/reload_meta", methods=["POST","GET"])
def reload_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True})

@app.route("/clear_meta", methods=["POST","GET"])
def clear_meta():
    DOMAIN_META_CACHE.clear()
    return jsonify({"ok": True, "cleared": True})


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

import os, re, json, ssl, socket, hashlib, time, threading
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from functools import wraps
import requests
from flask import Flask, request, jsonify

from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")
APP_VERSION = os.environ.get("APP_VERSION", "0.4.3-wl+why+wbfix+cmds")
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

# === Domain metadata cache (RDAP/SSL/Wayback) ===
DOMAIN_META_CACHE = {}
try:
    DOMAIN_META_TTL = int(os.getenv("DOMAIN_META_TTL", "2592000"))  # 30 days
    DOMAIN_META_TTL_NEG = int(os.getenv("DOMAIN_META_TTL_NEG", "600"))  # 10 minutes for negative WB
except Exception:
    DOMAIN_META_TTL = 2592000
    DOMAIN_META_TTL_NEG = 600

def _normalize_date_iso(s: str):
    try:
        import re as _re
        from datetime import datetime as _dt
        if not s or s == "—":
            return "—"
        s = s.strip()
        # Already ISO: 2025-10-24T11:51:46Z -> 2025-10-24
        m = _re.match(r"^(\d{4}-\d{2}-\d{2})", s)
        if m: return m.group(1)
        # OpenSSL: "Oct 23 23:59:59 2025 GMT"
        try:
            dt = _dt.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            pass
        # Compact yyyymmdd
        m = _re.match(r"^(\d{4})(\d{2})(\d{2})", s)
        if m: return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        # Fallback: keep original (better than truncation)
        return s
    except Exception:
        return s or "—"


def _normalize_registrar(reg: str, handle: str, domain: str):
    reg = reg or "—"
    h = (handle or "").upper()
    if "GOVERNMENT OF KINGDOM OF TONGA" in reg.upper() or "TONIC" in h or domain.endswith(".to"):
        return "Tonic (.to)"
    return reg

def _domain_meta(domain: str):
    import time
    now = int(time.time())
    ent = DOMAIN_META_CACHE.get(domain)
    if ent and (now - ent.get("t",0) < DOMAIN_META_TTL):
        return ent["h"], ent["created"], ent["reg"], ent["exp"], ent["issuer"], ent.get("wb","—")
    h, created, reg = _rdap(domain)
    exp, issuer = _ssl_info(domain)
    wb = _wayback_first(domain)
    created = _normalize_date_iso(created)
    exp = _normalize_date_iso(exp)
    reg = _normalize_registrar(reg, h, domain)
    DOMAIN_META_CACHE[domain] = {"t": now, "h": h, "created": created, "reg": reg, "exp": exp, "issuer": issuer, "wb": wb}
    return h, created, reg, exp, issuer, wb

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


def _symbol_homepage_hint(text: str):
    """
    Fallback mapping when contract->homepage cannot be resolved (non-ETH chains, bridges).
    Looks for well-known stable/bluechip symbols in the text block and returns canonical domain.
    """
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
        if sym in t:
            return dom
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
    """
    Robust Wayback lookup using CDX API with multiple candidates:
    http/https + with/without www. Returns '—' if nothing found.
    """
    try:
        import requests, os
        candidates = [
            f"http://{domain}/*",
            f"https://{domain}/*",
            f"http://www.{domain}/*",
            f"https://www.{domain}/*",
        ]
        headers = {"User-Agent": os.getenv("USER_AGENT", "MetridexBot/1.0")}
        for target in candidates:
            url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": target,
                "output": "json",
                "fl": "timestamp,statuscode,original",
                "filter": "statuscode:200",
                "limit": "1",
                "from": "2000",
                "to": "2035",
            }
            r = requests.get(url, params=params, timeout=8, headers=headers)
            if r.status_code != 200: 
                continue
            j = r.json()
            if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and len(j[1]) >= 1:
                ts = str(j[1][0])
                if len(ts) >= 8:
                    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
        return "—"
    except Exception:
        return "—"



# === Simple risk engine (heuristic, no extra APIs) ===
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
    # e.g. "Liq 1.11M | Vol24h 14.66K"
    try:
        patt = rf'{key}\s+([0-9\.\$]+\s*[KMB]?)'
        m = re.search(patt, text, re.IGNORECASE)
        return _parse_float_km(m.group(1)) if m else None
    except Exception:
        return None

def _parse_bool(text, key):
    # e.g. "Proxy: ✅"
    try:
        m = re.search(rf'{re.escape(key)}:\s*(✅|✔️|Yes|True|No|❌|—)', text, re.IGNORECASE)
        if not m: return None
        val = m.group(1)
        return val in ("✅","✔️","Yes","True")
    except Exception:
        return None

def _parse_roles(text):
    # e.g. "Roles: owner: ✅ | masterMinter: ✅ | pauser: ✅ ..."
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
    # expects enriched block already appended (Domain / WHOIS / SSL / Wayback)
    # returns dict: created(date str), registrar(str), ssl_exp(str), wayback(str)
    d={"created":None,"registrar":None,"ssl_exp":None,"wayback":None}
    try:
        m = re.search(r'Created:\s*([0-9\-TZ: ]+)', block); d["created"]=m.group(1) if m else None
        m = re.search(r'Registrar:\s*([^\n]+)', block); d["registrar"]=m.group(1).strip() if m else None
        m = re.search(r'Expires:\s*([0-9\-TZ: ]+)', block); d["ssl_exp"]=m.group(1) if m else None
        m = re.search(r'Wayback:\s*first\s+([0-9\-—]+)', block); d["wayback"]=m.group(1)
    except Exception:
        pass
    return d

# === Risk thresholds (can be tuned via ENV) ===
# === Whitelist for top projects/contracts ===
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


# Risk detail cache for Why?
RISK_CACHE = {}

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
    """
    Heuristic score 0..100 (higher = riskier). Uses only what we already have in text.
    Returns (score:int, label:str, reasons:list[str])
    """
    score = 0
    reasons = []
    positives = []
    whitelisted, wl_type = _is_whitelisted(addr, text)

    # Dex metrics (liquidity and volume)
    liq = _parse_metric_from_dexline(text, "Liq")
    vol = _parse_metric_from_dexline(text, "Vol24h")
    if liq is not None:
        if liq < RISK_LIQ_LOW:
            score += (8 if whitelisted else 25); reasons.append(f"Low liquidity (<${int(RISK_LIQ_LOW):,})")
        elif liq < RISK_LIQ_MED:
            score += (3 if whitelisted else 10); reasons.append(f"Moderate liquidity (<${int(RISK_LIQ_MED):,})")
        elif liq >= RISK_POSITIVE_LIQ:
            positives.append(f"High liquidity (≥${int(RISK_POSITIVE_LIQ):,})")
    if vol is not None and vol < RISK_VOL_LOW:
        score += 10; reasons.append("Very low 24h volume (<$5k)")

    # Blue-chip pair heuristic
    try:
        t_upper = (text or "").upper()
        if whitelisted:
            positives.append(f"Whitelisted by {wl_type}")
        if ("USDT" in t_upper and "USDC" in t_upper) or ("WBTC" in t_upper and "ETH" in t_upper):
            positives.append("Blue-chip pair context")
    except Exception:
        pass

    # Proxy / Upgradable
    proxy = _parse_bool(text, "Proxy")
    if proxy is True:
        score += (0 if whitelisted else 15); reasons.append("Upgradeable proxy (owner can change logic)")

    # Owner / roles
    roles = _parse_roles(text)
    if roles.get("owner", False):
        score += (0 if whitelisted else 20); reasons.append("Owner privileges present")
    if roles.get("blacklister", False):
        score += (0 if whitelisted else 10); reasons.append("Blacklisting capability")
    if roles.get("pauser", False):
        score += (0 if whitelisted else 10); reasons.append("Pausing capability")
    if roles.get("minter", False) or roles.get("masterMinter", False):
        score += (0 if whitelisted else 10); reasons.append("Minting capability")

    # Domain metadata (age & wayback)
    dom = _parse_domain_meta(text)
    try:
        if dom.get("created") and dom["created"] != "—":
            y = int(dom["created"][:4])
            if y >= 2024: score += 15; reasons.append("Very new domain")
            elif y >= 2022: score += 5; reasons.append("Newish domain")
            elif y <= RISK_POSITIVE_AGE_Y: positives.append(f"Established domain (≤{RISK_POSITIVE_AGE_Y})")
        if dom.get("wayback") in (None, "—"):
            score += 5; reasons.append("No Wayback snapshots")
        else:
            positives.append("Historical presence (Wayback found)")
    except Exception:
        pass

    # Clamp & label
    if score >= RISK_THRESH_HIGH: label = "HIGH RISK 🔴"
    elif score >= RISK_THRESH_CAUTION: label = "CAUTION 🟡"
    else: label = "LOW RISK 🟢"
    return int(min(100, score)), label, {"neg": reasons, "pos": positives}

def _append_verdict_block(addr, text):
    score, label, rs = _risk_verdict(addr, text)
    # cache for Why?
    try:
        RISK_CACHE[addr.lower()] = {"score": score, "label": label, "neg": rs.get("neg", []), "pos": rs.get("pos", [])}
    except Exception:
        pass
    lines = [f"Trust verdict: {label} (score {score}/100)"]
    if rs.get("neg"):
        lines.append("⚠️ Signals: " + "; ".join(rs["neg"]))
    if rs.get("pos"):
        lines.append("✅ Positives: " + "; ".join(rs["pos"]))
    return text + "\n" + "\n".join(lines)


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
def _enrich_full(addr: str, text: str):
    txt = NEWLINE_ESC_RE.sub("\n", text or "")
    domain = _cg_homepage(addr)
    if not domain:
        domain = _symbol_homepage_hint(txt)
    if not domain: return txt
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
            send_addr = None
            if data.startswith("more:"):
                payload_addr = data.split(":",1)[1].strip().lower()
                addr = payload_addr if ADDR_RE.fullmatch(payload_addr) else None
                if not addr:
                    addr = msg2addr.get(msg_id) or _extract_base_addr_from_keyboard(msg_obj.get("reply_markup")) or _extract_addr_from_text(msg_obj.get("text") or "")
                if DEBUG_MORE: tg_answer_callback(TELEGRAM_TOKEN, cq["id"], f"Full scan {addr or '?'}", logger=app.logger)
                if not addr:
                    tg_answer_callback(TELEGRAM_TOKEN, cq["id"], "address?", logger=app.logger); return ("ok", 200)
                text, keyboard = quickscan_entrypoint(addr, lang="en", window="h24", lean=False)
                text = _enrich_full(addr, text)
                text = _append_verdict_block(addr, text)
                keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=False)
                keyboard = _compress_keyboard(keyboard)
                # Add URL buttons if domain present
                try:
                    _dom = _extract_domain_from_text(text)
                    if _dom:
                        btns = [{"text": "🌐 Open website", "url": f"https://{_dom}"},
                                {"text": "🗂️ Archive", "url": f"https://web.archive.org/web/*/{_dom}"}]
                        if isinstance(keyboard, dict):
                            ik = keyboard.get("inline_keyboard", [])
                        else:
                            ik = keyboard or []
                        ik.append(btns)
                        keyboard = {"inline_keyboard": ik}
                except Exception:
                    pass
                # WHY button
                try:
                    if isinstance(keyboard, dict):
                        ik = keyboard.get("inline_keyboard", [])
                    else:
                        ik = keyboard or []
                    ik.append([{"text": "❓ Why?", "callback_data": f"why:{addr}"}])
                    keyboard = {"inline_keyboard": ik}
                except Exception:
                    pass
                send_addr = addr
            elif data.startswith("qs2:"):
                addrs = _extract_addrs_from_pair_payload(data)
                base_addr = _pick_addr(addrs)
                _, _, window = data.partition("?window="); window = window or "h24"
                chain = data.split(":",1)[1].split("/",1)[0]
                text, keyboard = quickscan_pair_entrypoint(chain, "-".join(addrs) if addrs else "", window=window)
                keyboard = _rewrite_keyboard_to_addr(base_addr, keyboard, add_more_btn=bool(base_addr))
                keyboard = _compress_keyboard(keyboard)
                send_addr = base_addr
            elif data.startswith("qs:"):
                addr, _, window = data.split(":",1)[1].partition("?window="); window = window or "h24"
                text, keyboard = quickscan_entrypoint(addr, lang="en", window=window, lean=True)
                keyboard = _rewrite_keyboard_to_addr(addr, keyboard, add_more_btn=True)
                keyboard = _compress_keyboard(keyboard)
                # Add URL buttons if domain present
                try:
                    _dom = _extract_domain_from_text(text)
                    if _dom:
                        btns = [{"text": "🌐 Open website", "url": f"https://{_dom}"},
                                {"text": "🗂️ Archive", "url": f"https://web.archive.org/web/*/{_dom}"}]
                        if isinstance(keyboard, dict):
                            ik = keyboard.get("inline_keyboard", [])
                        else:
                            ik = keyboard or []
                        ik.append(btns)
                        keyboard = {"inline_keyboard": ik}
                except Exception:
                    pass
                # WHY button
                try:
                    if isinstance(keyboard, dict):
                        ik = keyboard.get("inline_keyboard", [])
                    else:
                        ik = keyboard or []
                    ik.append([{"text": "❓ Why?", "callback_data": f"why:{addr}"}])
                    keyboard = {"inline_keyboard": ik}
                except Exception:
                    pass
                send_addr = addr
            else:
                return ("ok", 200)

            keyboard = {"inline_keyboard": keyboard.get("inline_keyboard", [])} if isinstance(keyboard, dict) else keyboard
            text_to_send = NEWLINE_ESC_RE.sub("\n", text).replace("\\n", "\n") if isinstance(text, str) else text
            st, body = tg_send_message(TELEGRAM_TOKEN, chat_id, text_to_send, reply_markup=keyboard, logger=app.logger)
            _store_addr_for_message(body, send_addr)
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
