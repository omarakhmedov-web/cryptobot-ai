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
