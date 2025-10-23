import os, json, socket, ssl
WEBINTEL_ENABLE_WHOIS = os.getenv('WEBINTEL_ENABLE_WHOIS', '0') == '1'
from typing import Optional, Dict, Any, Tuple
import requests as _rq
from urllib.parse import urlparse

# --- Caching & utils (tolerant to absence) -----------------------------------
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

TTL = int(os.getenv("CACHE_TTL_WEB_SEC", "172800"))
_WE_TIMEOUT = float(os.getenv("WEBINTEL_TIMEOUT_S", "1.0"))
_WE_HEAD_TIMEOUT = float(os.getenv("WEBINTEL_HEAD_TIMEOUT_S", "2.0"))
_WE_TLS_TIMEOUT = float(os.getenv("WEBINTEL_TLS_TIMEOUT_S", "4.0"))

# --- Helpers -----------------------------------------------------------------
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
    """Fetch basic WHOIS via RDAP aggregator; tolerant on failure."""
    try:
        r = _rq.get(f"https://rdap.org/domain/{host}", timeout=_WE_TIMEOUT)
        if not r.ok:
            return {"created": None, "registrar": None}
        j = r.json()
        created = None
        registrar = None
        # creation date from events
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
        # registrar from entities->vcardArray
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

def _https_head_probe(host: str) -> Dict[str, Any]:
    """Lightweight reachability + headers. Does not validate cert."""
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

def _https_tls_info(host: str) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    """Perform TLS handshake to obtain notAfter and issuer CN.
    Returns (ssl_ok, expires_iso, issuer_cn). All None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_WE_TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter"); raw_not_after = not_after
        issuer = cert.get("issuer")  # tuple of tuples like ((('countryName','US'),), (('organizationName','...'),), (('commonName','R3'),))
        issuer_cn = None
        if isinstance(issuer, tuple):
            for grp in issuer:
                if isinstance(grp, tuple):
                    for kv in grp:
                        try:
                            if len(kv) >= 2 and kv[0] == 'commonName':
                                issuer_cn = kv[1]
                                raise StopIteration
                        except StopIteration:
                            break
        expires_iso = None
        if not_after:
            raw_expires = not_after
            # e.g. 'Dec 16 14:26:31 2025 GMT'
            try:
                from datetime import datetime
                dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expires_iso = dt.date().isoformat()
            except Exception:
                expires_iso = raw_expires  # fallback to raw
        return True, expires_iso, issuer_cn
    except Exception:
        return None, None, None

def _wayback_first(host: str) -> Optional[str]:
    try:
        r = _rq.get("https://web.archive.org/cdx/search/cdx", params={
            "url": host, "output": "json", "fl": "timestamp",
            "filter": "statuscode:200", "limit": "1",
            "from": "19960101", "to": "99991231", "sort": "ascending",
        }, timeout=_WE_TIMEOUT)
        if r.ok:
            j = r.json()
            if isinstance(j, list) and len(j) >= 2 and isinstance(j[1], list) and j[1]:
                ts = j[1][0]
                return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass
    return None

def _merge_whois_fallback(out: Dict[str, Any], domain_block: Optional[Dict[str, Any]]) -> None:
    """If RDAP failed, copy created/registrar from a provided domain_block (if any)."""
    if not domain_block:
        return
    wi = out.get("whois") or {}
    if not wi.get("created") and domain_block.get("created"):
        wi["created"] = domain_block["created"]
    if not wi.get("registrar") and domain_block.get("registrar"):
        wi["registrar"] = domain_block["registrar"]
    out["whois"] = wi

# --- Public API ---------------------------------------------------------------
def analyze_website(url: Optional[str], *, domain_block: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return website intelligence with graceful fallbacks.
    Shape:
      {
        "whois": {"created": str|None, "registrar": str|None},
        "ssl": {"ok": bool|None, "expires": str|None, "issuer": str|None, "_server": str|None, "_hsts": str|None},
        "wayback": {"first": str|None},
      }
    """
    if not url:
        return {"whois": {"created": None, "registrar": None},
                "ssl": {"ok": None, "expires": None, "issuer": None},
                "wayback": {"first": None}}

    url_n = normalize_url(url)
    key = f"webintel:{url_n}"
    cached = cache_get(key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    host = derive_domain(url_n)
    out = {
        "whois": {"created": None, "registrar": None},
        "ssl": {"ok": None, "expires": None, "issuer": None},
        "wayback": {"first": None},
    }

    if host:
        # 1) RDAP WHOIS (best-effort)
        who = _rdap_whois(host)
        out["whois"]["created"] = who.get("created")
        out["whois"]["registrar"] = who.get("registrar")

        # 2) HEAD probe (reachability + headers)
        head = _https_head_probe(host)
        out["ssl"]["_server"] = head.get("_server")
        out["ssl"]["_hsts"] = head.get("_hsts")

        # 3) TLS handshake (cert details)
        ssl_ok, ssl_exp, issuer_cn = _https_tls_info(host)
        # prefer TLS result for ok; if unavailable, fallback to HEAD ok
        out["ssl"]["ok"] = ssl_ok if ssl_ok is not None else head.get("ok")
        out["ssl"]["expires"] = ssl_exp
        out["ssl"]["issuer"] = issuer_cn

        # 4) Wayback earliest snapshot
        wb = _wayback_first(host)
        if not wb:
            # Fallback to Wayback "available" endpoint
            try:
                import requests as _rq
                rr = _rq.get(f"https://archive.org/wayback/available?url={host}", timeout=6)
                if rr.ok:
                    jj = rr.json(); m = jj.get("archived_snapshots", {}).get("closest", {})
                    wb = (m.get("timestamp") or "")[:8] or None
            except Exception:
                wb = None
        out["wayback"]["first"] = wb

    # 5) Deterministic fallback from domain_block (if provided) to avoid 'n/a'
    _merge_whois_fallback(out, domain_block)

    cache_set(key, json.dumps(out), TTL)
    return out
