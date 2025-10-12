import os, time
from urllib.parse import urlparse
from datetime import datetime, timezone, date
from typing import Any, Dict, Optional, List
import requests

RDAP_ENDPOINT = os.getenv("RDAP_ENDPOINT", "https://rdap.org")
RDAP_TIMEOUT = float(os.getenv("RDAP_TIMEOUT", "3.0"))
RDAP_CACHE_TTL = int(os.getenv("RDAP_CACHE_TTL", "3600"))
ENABLE_WHOIS_FALLBACK = os.getenv("ENABLE_WHOIS_FALLBACK", "1").lower() in ("1","true","yes")

try:
    import whois as _whois
except Exception:
    _whois = None

_cache: Dict[tuple, Dict[str, Any]] = {}

def _now() -> int:
    return int(time.time())

def _domain_from_url(site_url: str) -> Optional[str]:
    try:
        h = urlparse(site_url).hostname
    except Exception:
        return None
    if not h:
        return None
    parts = h.split(".")
    if len(parts) < 2:
        return h
    return ".".join(parts[-2:])

def _iso_date(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z","+00:00"))
        return dt.date().isoformat()
    except Exception:
        # last resort: just return original
        return s

def _fetch_rdap_json(domain: str) -> Optional[Dict[str, Any]]:
    url = f"{RDAP_ENDPOINT.rstrip('/')}/domain/{domain}"
    try:
        r = requests.get(url, timeout=RDAP_TIMEOUT, headers={"Accept":"application/rdap+json"})
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        return None
    return None

def _normalize_rdap(raw: Dict[str, Any]) -> Dict[str, Any]:
    def _get(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return default

    events = { (e.get("eventAction")): e.get("eventDate") for e in _get(raw, "events", []) if isinstance(e, dict) }
    created_raw = events.get("registration") or events.get("created")
    expires_raw = events.get("expiration")

    registrar = None
    for ent in _get(raw, "entities", []) or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [None, []])[1]
            for it in vcard:
                if it and it[0] == "fn":
                    registrar = it[3]
                    break

    ns = [n.get("ldhName") for n in _get(raw, "nameservers", []) or [] if isinstance(n, dict) and n.get("ldhName")]
    status = _get(raw, "status", []) or []

    country = None
    for ent in _get(raw, "entities", []) or []:
        if any(r in (ent.get("roles") or []) for r in ("registrant","administrative")):
            vcard = ent.get("vcardArray", [None, []])[1]
            for it in vcard:
                if it and it[0] == "adr" and isinstance(it[3], list) and len(it[3]) >= 7:
                    country = it[3][6]
                    break

    created_iso = _iso_date(created_raw)
    expires_iso = _iso_date(expires_raw)

    age_days = None
    try:
        if created_raw:
            dt = datetime.fromisoformat(created_raw.replace("Z","+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
    except Exception:
        pass

    flags: List[str] = []
    if age_days is not None and age_days < 90: flags.append("new_domain_lt_90d")
    if expires_iso: flags.append("has_expiry")
    if any(("clientHold" in s) or ("serverHold" in s) for s in status): flags.append("domain_on_hold")
    if not registrar: flags.append("registrar_unknown")

    return {
        "registrar": registrar,
        "created": created_iso,
        "expires": expires_iso,
        "status": status,
        "ns": ns,
        "country": country,
        "age_days": age_days,
        "flags": flags,
    }

def _normalize_whois(domain: str) -> Optional[Dict[str, Any]]:
    if not _whois:
        return None
    try:
        w = _whois.whois(domain)
    except Exception:
        return None

    def _pick(v):
        if isinstance(v, (list, tuple)) and v:
            return v[0]
        return v

    registrar = getattr(w, "registrar", None)
    created = _pick(getattr(w, "creation_date", None))
    expires = _pick(getattr(w, "expiration_date", None))

    def _to_date_str(v):
        try:
            if isinstance(v, (datetime,)):
                return v.astimezone().date().isoformat()
            if isinstance(v, date):
                return v.isoformat()
            return str(v) if v else None
        except Exception:
            return str(v) if v else None

    created_iso = _to_date_str(created)
    expires_iso = _to_date_str(expires)

    age_days = None
    try:
        if isinstance(created, (datetime,)) or isinstance(created, date):
            base = datetime.combine(created, datetime.min.time(), tzinfo=timezone.utc) if isinstance(created, date) else created
            age_days = (datetime.now(timezone.utc) - base).days
    except Exception:
        pass

    flags: List[str] = []
    if age_days is not None and age_days < 90: flags.append("new_domain_lt_90d")
    if expires_iso: flags.append("has_expiry")
    if not registrar: flags.append("registrar_unknown")

    return {
        "registrar": registrar,
        "created": created_iso,
        "expires": expires_iso,
        "status": [],
        "ns": [],
        "country": None,
        "age_days": age_days,
        "flags": flags,
    }

def lookup(site_url: str) -> Optional[Dict[str, Any]]:
    domain = _domain_from_url(site_url)
    if not domain: 
        return None
    key = ("rdap", domain)
    hit = _cache.get(key)
    if hit and hit["exp"] > _now():
        return hit["val"]

    raw = _fetch_rdap_json(domain)
    res = _normalize_rdap(raw) if raw else None

    if not res and ENABLE_WHOIS_FALLBACK:
        res = _normalize_whois(domain)

    if not res:
        return None

    _cache[key] = {"val": res, "exp": _now() + RDAP_CACHE_TTL}
    return res
