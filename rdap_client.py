# rdap_client.py
import os, time
from urllib.parse import urlparse
import requests

RDAP_ENDPOINT = os.getenv("RDAP_ENDPOINT", "https://rdap.org")
RDAP_TIMEOUT = float(os.getenv("RDAP_TIMEOUT", "3.0"))
RDAP_CACHE_TTL = int(os.getenv("RDAP_CACHE_TTL", "3600"))
_cache = {}

def _now(): return int(time.time())

def _domain_from_url(site_url: str):
    try:
        h = urlparse(site_url).hostname
    except Exception:
        return None
    if not h: return None
    parts = h.split(".")
    if len(parts) < 2: return h
    return ".".join(parts[-2:])

def _fetch_rdap_json(domain: str):
    url = f"{RDAP_ENDPOINT.rstrip('/')}/domain/{domain}"
    try:
        r = requests.get(url, timeout=RDAP_TIMEOUT, headers={"Accept":"application/rdap+json"})
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        return None
    return None

def lookup(site_url: str):
    domain = _domain_from_url(site_url)
    if not domain: return None
    key = ("rdap", domain)
    hit = _cache.get(key)
    if hit and hit["exp"] > _now(): return hit["val"]
    raw = _fetch_rdap_json(domain)
    if not raw: return None

    def _get(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return default

    events = { (e.get("eventAction")): e.get("eventDate") for e in _get(raw, "events", []) if isinstance(e, dict) }
    created = events.get("registration") or events.get("created")
    expires = events.get("expiration")

    registrar = None
    for ent in _get(raw, "entities", []):
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [None, []])[1]
            for it in vcard:
                if it and it[0] == "fn":
                    registrar = it[3]
                    break

    ns = [n.get("ldhName") for n in _get(raw, "nameservers", []) if isinstance(n, dict) and n.get("ldhName")]
    status = _get(raw, "status", []) or []

    country = None
    for ent in _get(raw, "entities", []):
        if any(r in (ent.get("roles") or []) for r in ("registrant","administrative")):
            vcard = ent.get("vcardArray", [None, []])[1]
            for it in vcard:
                if it and it[0] == "adr" and isinstance(it[3], list) and len(it[3]) >= 7:
                    country = it[3][6]
                    break

    age_days = None
    try:
        if created:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(created.replace("Z","+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
    except Exception:
        pass

    flags = []
    if age_days is not None and age_days < 90: flags.append("new_domain_lt_90d")
    if expires: flags.append("has_expiry")
    if any(("clientHold" in s) or ("serverHold" in s) for s in status): flags.append("domain_on_hold")
    if not registrar: flags.append("registrar_unknown")

    out = {
        "domain": domain,
        "registrar": registrar,
        "created": created,
        "expires": expires,
        "status": status,
        "ns": ns,
        "country": country,
        "age_days": age_days,
        "flags": flags,
    }
    _cache[key] = {"val": out, "exp": _now() + RDAP_CACHE_TTL}
    return out
