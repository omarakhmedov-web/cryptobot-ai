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

# ISO 3166-1 alpha-2 minimal map (extend as needed)
_ISO2_TO_NAME = {
    "US":"United States", "GB":"United Kingdom", "CA":"Canada", "DE":"Germany", "FR":"France",
    "NL":"Netherlands", "SE":"Sweden", "NO":"Norway", "CH":"Switzerland", "AE":"United Arab Emirates",
    "AU":"Australia", "SG":"Singapore", "HK":"Hong Kong", "JP":"Japan", "KR":"South Korea",
    "CN":"China", "IN":"India", "IE":"Ireland", "LT":"Lithuania", "LV":"Latvia", "EE":"Estonia",
    "PL":"Poland", "CZ":"Czech Republic", "SK":"Slovakia", "ES":"Spain", "IT":"Italy",
    "PT":"Portugal", "RU":"Russia", "UA":"Ukraine", "TR":"Turkey", "BR":"Brazil",
    "AR":"Argentina"
}
def _iso2_to_name(code: str | None) -> str | None:
    if not code: return None
    c = str(code).strip()
    if len(c) == 2 and c.isalpha():
        return _ISO2_TO_NAME.get(c.upper(), c.upper())
    # sometimes RDAP returns full country already
    return c if c else None

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

def _extract_registrar_info(entities: List[Dict[str, Any]]):
    registrar = None
    registrar_id = None
    for ent in entities or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            # name
            vcard = ent.get("vcardArray", [None, []])[1]
            for it in vcard:
                if it and it[0] == "fn":
                    registrar = it[3]
                    break
            # IANA id
            for pid in ent.get("publicIds", []) or []:
                t = (pid.get("type") or "").lower()
                if "iana" in t and "registrar" in t and pid.get("identifier"):
                    registrar_id = f"{pid.get('identifier')}"
                    break
            break
    return registrar, registrar_id

def _normalize_rdap(domain: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    def _get(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return default

    # Events -> created/expires
    events = {}
    for e in _get(raw, "events", []) or []:
        if not isinstance(e, dict): 
            continue
        act = e.get("eventAction")
        if act:
            events[act] = e.get("eventDate")

    created_raw = events.get("registration") or events.get("created")
    expires_raw = events.get("expiration")

    registrar, registrar_id = _extract_registrar_info(_get(raw, "entities", []) or [])

    # Nameservers, status
    ns = [n.get("ldhName") for n in (_get(raw, "nameservers", []) or []) if isinstance(n, dict) and n.get("ldhName")]
    status = _get(raw, "status", []) or []

    # Country from vcardArray/adr with role priority
    country = None
    try:
        role_priority = ("registrant","administrative","admin","tech","registrar")
        best_rank = 999
        for ent in (_get(raw, "entities", []) or []):
            roles = tuple(ent.get("roles") or [])
            # assess rank
            rank = None
            for idx, rr in enumerate(role_priority):
                if rr in roles:
                    rank = idx
                    break
            if rank is None or rank > best_rank:
                continue
            vcard = ent.get("vcardArray", [None, []])
            items = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
            found = None
            for it in items:
                try:
                    if it and it[0] == "adr" and isinstance(it[3], list) and len(it[3]) >= 7:
                        found = it[3][6]
                        break
                    if it and it[0] == "country" and len(it) > 3:
                        found = it[3]
                        break
                except Exception:
                    continue
            if found:
                country = _iso2_to_name(found)
                best_rank = rank
        if isinstance(country, str) and not country.strip():
            country = None
    except Exception:
        pass

    created_iso = _iso_date(created_raw)
    expires_iso = _iso_date(expires_raw)

    # Age in days
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
    try:
        if any(("clientHold" in s) or ("serverHold" in s) for s in (status or [])):
            flags.append("domain_on_hold")
    except Exception:
        pass
    if not registrar: flags.append("registrar_unknown")

    return {
        "domain": domain,
        "registrar": registrar,
        "registrar_id": registrar_id,
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
        "domain": domain,
        "registrar": registrar,
        "registrar_id": None,
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
    res = _normalize_rdap(domain, raw) if raw else None

    if not res and ENABLE_WHOIS_FALLBACK:
        res = _normalize_whois(domain)

    if not res:
        return None

    _cache[key] = {"val": res, "exp": _now() + RDAP_CACHE_TTL}
    return res
