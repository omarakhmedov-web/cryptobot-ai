import os, json
from typing import Optional, Dict, Any
import requests as _rq
from urllib.parse import urlparse

from typing import Optional, Dict, Any
try:
    from cache import cache_get, cache_set
except Exception:
    def cache_get(_): return None
    def cache_set(*args, **kwargs): pass

try:
    from common import normalize_url
except Exception:
    def normalize_url(url: str) -> str:
        u = str(url or "").strip()
        if not u:
            return ""
        if u.startswith("http://") or u.startswith("https://"):
            return u
        return "https://" + u.lstrip("/")

from cache import cache_get, cache_set
from common import normalize_url

TTL = int(os.getenv("CACHE_TTL_WEB_SEC", "172800"))
_WE_TIMEOUT = float(os.getenv("WEBINTEL_TIMEOUT_S", "2.5"))
_WE_HEAD_TIMEOUT = float(os.getenv("WEBINTEL_HEAD_TIMEOUT_S", "2.0"))

def derive_domain(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        u = normalize_url(url).strip()
    except Exception:
        u = str(url).strip()
    try:
        p = urlparse(u)
        host = (p.netloc or p.path).strip().lstrip("*.").split("/")[0]
        if host.lower().startswith("www."):
            host = host[4:]
        return host or None
    except Exception:
        return None

def _rdap_whois(host: str) -> Dict[str, Any]:
    try:
        r = _rq.get(f"https://rdap.org/domain/{host}", timeout=_WE_TIMEOUT)
        if not r.ok:
            return {"created": None, "registrar": None}
        j = r.json()
        created = None
        registrar = None
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
        return {"created": created, "registrar": registrar}
    except Exception:
        return {"created": None, "registrar": None}

def _https_head_ok(host: str) -> Dict[str, Any]:
    ok = None; server = None; hsts = None
    try:
        r = _rq.head(f"https://{host}", allow_redirects=True, timeout=_WE_HEAD_TIMEOUT)
        ok = True if r is not None and r.ok else None
        if r is not None:
            server = r.headers.get("Server")
            hsts = r.headers.get("Strict-Transport-Security")
    except Exception:
        pass
    return {"ok": ok, "_server": server, "_hsts": hsts}

def _wayback_first(host: str) -> Optional[str]:
    try:
        r = _rq.get("https://web.archive.org/cdx/search/cdx", params={
            "url": host, "output": "json", "fl": "timestamp", "filter": "statuscode:200",
            "limit": "1", "from": "19960101", "to": "99991231", "sort": "ascending"
        }, timeout=_WE_TIMEOUT)
        if r.ok:
            j = r.json()
            if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and j[1]:
                ts = j[1][0]
                return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass
    return None

def analyze_website(url: Optional[str]) -> Dict[str, Any]:
    # Cache by normalized URL
    if not url:
        return {"whois": {"created": None, "registrar": None},
                "ssl": {"ok": None, "expires": None, "issuer": None},
                "wayback": {"first": None}}
    url_n = normalize_url(url)
    key = f"webintel:{url_n}"
    c = cache_get(key)
    if c:
        try:
            return json.loads(c)
        except Exception:
            pass

    host = derive_domain(url_n)
    out = {
        "whois": {"created": None, "registrar": None},
        "ssl": {"ok": None, "expires": None, "issuer": None},
        "wayback": {"first": None},
    }
    if host:
        # RDAP WHOIS (works for most TLDs)
        who = _rdap_whois(host)
        out["whois"] = {"created": who.get("created"), "registrar": who.get("registrar")}
        # HTTPS reachability + headers
        sslh = _https_head_ok(host)
        out["ssl"]["ok"] = sslh.get("ok")
        out["ssl"]["_server"] = sslh.get("_server")
        out["ssl"]["_hsts"] = sslh.get("_hsts")
        # Wayback earliest snapshot
        out["wayback"]["first"] = _wayback_first(host)

    cache_set(key, json.dumps(out), TTL)
    return out
