import os
import json
import ssl
import socket
from datetime import datetime, timezone

import requests
try:
    from metri_domain_rdap import _rdap as _rdap_hardened
except Exception:
    _rdap_hardened = None

USER_AGENT = os.environ.get("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "10.0"))
DEBUG = os.environ.get("DEBUG", "0") == "1"

COMMON_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json"
}

def _dbg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", flush=True)

def http_get_json(url):
    try:
        _dbg(f"GET {url}")
        r = requests.get(url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        _dbg(f"-> {r.status_code}")
        if r.status_code == 200:
            return r.json()
        else:
            _dbg(f"Non-200: {r.text[:200]}")
    except Exception as e:
        _dbg(f"EXC {type(e).__name__}: {e}")
        return None
    return None

def http_post_json(url, payload):
    try:
        _dbg(f"POST {url}")
        r = requests.post(url, json=payload, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        _dbg(f"-> {r.status_code}")
        if r.status_code == 200:
            return r.json()
        else:
            _dbg(f"Non-200: {r.text[:200]}")
    except Exception as e:
        _dbg(f"POST EXC {type(e).__name__}: {e}")
        return None
    return None

def rdap_domain(domain):
    """Return minimal RDAP dict using hardened resolver when available."""
    try:
        if _rdap_hardened is not None:
            h, created, registrar = _rdap_hardened((domain or '').strip().lower())
            return {
                "handle": h,
                "name": h,
                "created": created if created else None,
                "registrar": registrar if registrar else None,
            }
        # Fallback to legacy rdap.net
        url = f"https://www.rdap.net/domain/{domain}"
        data = http_get_json(url)
        if not data:
            return None
        out = {
            "handle": data.get("handle"),
            "name": (data.get("name") or ""),
            "created": None,
            "registrar": None,
        }
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                out["created"] = ev.get("eventDate")
        ents = data.get("entities") or []
        for e in ents:
            if (e.get("roles") or []) and ("registrar" in e.get("roles")):
                vcard = e.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            out["registrar"] = item[3]
                            break
        return out
    except Exception as e:
        _dbg(f"RDAP EXC {e}")
        return None
        out = {
            "handle": data.get("handle"),
            "name": (data.get("name") or ""),
            "created": None,
            "registrar": None,
        }
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                out["created"] = ev.get("eventDate")
        ents = data.get("entities") or []
        for e in ents:
            if (e.get("roles") or []) and ("registrar" in e.get("roles")):
                vcard = e.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            out["registrar"] = item[3]
                            break
        return out
    except Exception as e:
        _dbg(f"RDAP EXC {e}")
        return None

def wayback_first_capture(domain):
    try:
        url = f"https://archive.org/wayback/available?url={domain}"
        data = http_get_json(url)
        if not data:
            return None
        snap = data.get("archived_snapshots", {}).get("closest")
        if snap and snap.get("available"):
            ts = snap.get("timestamp")
            if ts and len(ts) >= 8:
                dt = datetime.strptime(ts[:8], "%Y%m%d").date()
                return dt.isoformat()
        return None
    except Exception as e:
        _dbg(f"WAYBACK EXC {e}")
        return None

def ssl_certificate_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get("notAfter")
                issuer_t = cert.get("issuer")
                issuer = None
                if issuer_t:
                    issuer = " ".join(["=".join(x[0]) for x in issuer_t if x])
                valid = True
                if notAfter:
                    exp_dt = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    if exp_dt.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                        valid = False
                return {"notAfter": notAfter, "issuer": issuer, "valid": valid}
    except Exception as e:
        _dbg(f"SSL EXC {e}")
        return None

def tg_send_message(token, chat_id, text, reply_markup=None, parse_mode=None):
    if not token:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    try:
        requests.post(url, json=payload, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        _dbg(f"TG_SEND EXC {e}")

def tg_answer_callback(token, callback_id, text=None):
    if not token:
        return
    url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text
    try:
        requests.post(url, json=payload, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        _dbg(f"TG_CB EXC {e}")

def make_markdown_safe(s):
    return s.replace("_","\\_").replace("*","\\*").replace("[","\\[").replace("`","\\`")

def format_kv(d):
    parts = []
    for k,v in d.items():
        if v is None:
            continue
        if isinstance(v, (int,float)):
            parts.append(f"{k}: {v:,}")
        else:
            parts.append(f"{k}: {v}")
    return " | ".join(parts)


KNOWN_DOMAINS_PATH = os.environ.get("KNOWN_DOMAINS_PATH", "./known_domains.json")

def _normalize_host(h: str) -> str:
    h = (h or "").strip().lower()
    if h.startswith("www."):
        h = h[4:]
    return h

def load_known_domains(path: str = None):
    """Load a flat CA->host mapping. Returns {} on failure."""
    p = (path or KNOWN_DOMAINS_PATH).strip()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        flat = {}
        if isinstance(data, dict):
            # chain maps or flat map
            if all(isinstance(v, str) for v in data.values()):
                for k, v in data.items():
                    flat[str(k).lower()] = _normalize_host(str(v))
            else:
                for _, sub in data.items():
                    if isinstance(sub, dict):
                        for k, v in sub.items():
                            flat[str(k).lower()] = _normalize_host(str(v))
        return flat
    except Exception as e:
        _dbg(f"KNOWN_DOMAINS load fail: {e}")
        return {}

# Preload once (safe for heroku/render dynos)
try:
    KNOWN_DOMAINS = load_known_domains()
except Exception:
    KNOWN_DOMAINS = {}

def get_known_domain_for_address(addr: str):
    try:
        a = (addr or "").strip().lower()
        if not a:
            return None
        host = KNOWN_DOMAINS.get(a)
        return host
    except Exception:
        return None

I18N = {
  "en": {
    "help": "*Metridex QuickScan*\nSend a contract address, token or pair URL (DexScreener / explorers), or use `/quickscan <address|url>`.\nI will fetch pools from DexScreener and basic domain signals (WHOIS/RDAP, SSL, Wayback).",
    "empty": "Send a contract address or URL.",
    "unknown": "Unknown command. Try /quickscan",
    "scan_usage": "Usage: `/quickscan <address|url>`",
    "lang_switched": "Language fixed to EN. Type /lang ru to switch back.",
    "cache_miss": "Cache expired, run /quickscan again.",
    "updated": "Updated.",
    "no_pairs": "No pools found on DexScreener."
  },
  "ru": {
    "help": "*Metridex QuickScan*\nОтправьте адрес контракта, ссылку на токен/пул (DexScreener/эксплореры) или `/quickscan <address|url>`.\nЯ подтяну пулы из DexScreener и базовые доменные сигналы (WHOIS/RDAP, SSL, Wayback).",
    "empty": "Отправьте адрес или ссылку.",
    "unknown": "Неизвестная команда. Попробуйте /quickscan",
    "scan_usage": "Формат: `/quickscan <address|url>`",
    "lang_switched": "Язык зафиксирован: RU. Напишите /lang en для EN.",
    "cache_miss": "Кэш истёк, запустите /quickscan ещё раз.",
    "updated": "Обновлено.",
    "no_pairs": "Пулы на DexScreener не найдены."
  }
}

def locale_text(lang, key):
    return I18N.get(lang, I18N["en"]).get(key, I18N["en"].get(key, key))
