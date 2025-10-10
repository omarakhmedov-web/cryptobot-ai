import os, time, re
from datetime import datetime, timezone

def now_ts() -> int:
    return int(time.time())

def dt_utc_iso(ts: int | float | None = None) -> str:
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")

def parse_iso8601(s: str | None) -> int | None:
    if not s: return None
    try:
        if s.endswith("Z"): s = s[:-1] + "+00:00"
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return None

def getenv_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def chain_from_hint(hint: str | None) -> str:
    h = (hint or "ethereum").lower()
    if "bsc" in h or "bnb" in h: return "bsc"
    if "polygon" in h or "matic" in h: return "polygon"
    if "arb" in h: return "arbitrum"
    return "ethereum"

# ----- additions (free-first helpers) -----
import json as _json
from urllib.parse import urlparse, urlunparse

def normalize_url(url: str | None) -> str:
    """Normalize URL (scheme default https, strip fragments/query where appropriate)."""
    if not url:
        return ""
    try:
        u = url.strip()
        if not re.match(r'^https?://', u, re.I):
            u = "https://" + u
        p = urlparse(u)
        # Lowercase scheme/host
        scheme = (p.scheme or "https").lower()
        netloc = (p.netloc or "").lower()
        # Remove trailing slash-only paths
        path = p.path or "/"
        # Keep query only for explicit needs; default drop to stabilize cache keys
        return urlunparse((scheme, netloc, path, "", "", ""))
    except Exception:
        return url

def enabled_networks() -> list[str]:
    s = os.getenv("ENABLED_NETWORKS", "eth,bsc,polygon,base,arb,op,avax,ftm,sol")
    return [x.strip() for x in s.split(",") if x.strip()]

def two_source_required() -> bool:
    try:
        return int(os.getenv("TWO_SOURCE_RULE", "0")) == 1
    except Exception:
        return False

def load_providers_map() -> dict:
    """Load providers map from JSON (free-first). Controlled by PROVIDERS_FILE env."""
    path = os.getenv("PROVIDERS_FILE", "providers_free.json").strip() or "providers_free.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}
