import os
import json
import ssl
import socket
import math
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

USER_AGENT = os.environ.get("USER_AGENT", "MetridexBot/QuickScan (+https://metridex.com)")
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "10.0"))  # bump to 10s by default
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

def http_get_text(url):
    try:
        _dbg(f"GET {url}")
        r = requests.get(url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        _dbg(f"-> {r.status_code}")
        if r.status_code == 200:
            return r.text
        else:
            _dbg(f"Non-200: {r.text[:200]}")
    except Exception as e:
        _dbg(f"EXC {type(e).__name__}: {e}")
        return None
    return None

def rdap_domain(domain):
    try:
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
