import os
import socket
from typing import Optional, Dict, Any
from common import normalize_url
from cache import cache_get, cache_set

TTL = int(os.getenv("CACHE_TTL_WEB_SEC","172800"))

def _whois_stub(domain: str) -> Dict[str, Any]:
    return {"created": None, "registrar": None}

def _ssl_stub(domain: str) -> Dict[str, Any]:
    return {"ok": True, "expires": None, "issuer": None}

def _wayback_stub(url: str) -> Dict[str, Any]:
    return {"first": None}

def analyze_website(url: Optional[str]) -> Dict[str, Any]:
    if not url:
        return {"whois": _whois_stub(""), "ssl": _ssl_stub(""), "wayback": _wayback_stub("")}
    url = normalize_url(url)
    key = f"webintel:{url}"
    c = cache_get(key)
    if c:
        import json
        try: return json.loads(c)
        except Exception: pass

    # Stubs; you can wire real services later
    try:
        domain = url.split("/")[2]
    except Exception:
        domain = None
    out = {
        "whois": _whois_stub(domain or ""),
        "ssl": _ssl_stub(domain or ""),
        "wayback": _wayback_stub(url),
    }

    import json
    cache_set(key, json.dumps(out), TTL)
    return out
