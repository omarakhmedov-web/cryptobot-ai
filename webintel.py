import os, json, socket, ssl
from typing import Optional, Dict, Any, Tuple
import requests as _rq
from urllib.parse import urlparse

# --- Caching (optional) ------------------------------------------------------
try:
    from cache import cache_get, cache_set  # type: ignore
except Exception:
    def cache_get(_): return None
    def cache_set(*args, **kwargs): pass

try:
    from common import normalize_url  # type: ignore
except Exception:
    def normalize_url(u: str) -> str:
        if not isinstance(u, str) or not u:
            return ""
        if u.startswith(("http://", "https://")):
            return u
        return "https://" + u.lstrip("/")

TTL = int(os.getenv("CACHE_TTL_WEB_SEC", "172800"))
_WE_TIMEOUT = float(os.getenv("WEBINTEL_TIMEOUT_S", "1.0"))
_WE_HEAD_TIMEOUT = float(os.getenv("WEBINTEL_HEAD_TIMEOUT_S", "2.0"))
_WE_TLS_TIMEOUT = float(os.getenv("WEBINTEL_TLS_TIMEOUT_S", "4.0"))

# --- Helpers -----------------------------------------------------------------
def _rdap_ip_country(host: str) -> Optional[str]:
    try:
        ips = socket.gethostbyname_ex(host)[2]
        if not ips:
            return None
        ip = ips[0]
        r = _rq.get(f"https://rdap.org/ip/{ip}", timeout=_WE_TIMEOUT)
        if r.ok:
            j = r.json()
            c = j.get("country")
            if isinstance(c, str) and c.strip():
                return c.strip()
    except Exception:
        return None
    return None

def _rdap_whois(host: str) -> Dict[str, Any]:
    try:
        r = _rq.get(f"https://rdap.org/domain/{host}", timeout=_WE_TIMEOUT)
        if not r.ok:
            return {"created": None, "registrar": None, "country": None}
        j = r.json()
        created = None
        registrar = None
        country = j.get("country") if isinstance(j.get("country"), str) else None
        # created from events
        for ev in (j.get("events") or []):
            try:
                act = str(ev.get("eventAction") or "").lower()
                if act in ("registration","registered","creation"):
                    d = ev.get("eventDate") or ""
                    if isinstance(d, str) and len(d) >= 10:
                        created = d[:10]
                        break
            except Exception:
                pass
        # registrar from entities
        for ent in (j.get("entities") or []):
            try:
                roles = [str(x).lower() for x in (ent.get("roles") or [])]
                if any("registrar" in r for r in roles):
                    v = ent.get("vcardArray") or []
                    items = v[1] if isinstance(v, list) and len(v) > 1 else []
                    for it in items:
                        if it and it[0] == "fn" and len(it) > 3:
                            registrar = it[3]
                            raise StopIteration
            except StopIteration:
                break
            except Exception:
                pass
        return {"created": created, "registrar": registrar, "country": country}
    except Exception:
        return {"created": None, "registrar": None, "country": None}

def _ssl_info(host: str) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_WE_TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = ""
                try:
                    issuer_tuple = cert.get("issuer") or []
                    issuer = " ".join("=".join(x[0]) for x in issuer_tuple if x)
                except Exception:
                    issuer = None
                not_after = cert.get("notAfter")
                return True, not_after, issuer
    except Exception:
        return None, None, None

def _wayback_first(url: str) -> Optional[str]:
    try:
        r = _rq.get("https://web.archive.org/cdx/search/cdx", params={"url": url, "output": "json", "limit": "1"}, timeout=_WE_TIMEOUT)
        if r.ok:
            data = r.json()
            if isinstance(data, list) and len(data) > 1 and isinstance(data[1], list) and len(data[1]) > 1:
                ts = data[1][1]  # timestamp like 20210101123456
                return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        return None
    return None

def analyze_website(url: str) -> Dict[str, Any]:
    u = normalize_url(url or "")
    if not u:
        return {"whois": {"created": None, "registrar": None, "country": None},
                "ssl": {"ok": None, "expires": None, "issuer": None},
                "wayback": {"first": None},
                "country": None}

    cached = cache_get("webintel:" + u)
    if isinstance(cached, dict):
        return cached

    out = {"whois": {"created": None, "registrar": None, "country": None},
           "ssl": {"ok": None, "expires": None, "issuer": None},
           "wayback": {"first": None},
           "country": None}

    try:
        host = urlparse(u).hostname or ""
    except Exception:
        host = ""

    # WHOIS/RDAP
    if host:
        who = _rdap_whois(host)
        out["whois"]["created"] = who.get("created")
        out["whois"]["registrar"] = who.get("registrar")
        out["whois"]["country"] = who.get("country")
        # Country fallback via IP RDAP
        out["country"] = out["whois"]["country"] or _rdap_ip_country(host)

    # TLS
    if host:
        ok, exp, iss = _ssl_info(host)
        out["ssl"]["ok"] = ok
        out["ssl"]["expires"] = exp
        out["ssl"]["issuer"] = iss

    # Wayback
    try:
        out["wayback"]["first"] = _wayback_first(u)
    except Exception:
        pass

    cache_set("webintel:" + u, out, TTL)
    return out
