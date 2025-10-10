import os, time, json
from typing import Optional, Tuple, Dict, Any

_MEM: Dict[str, Tuple[float, str]] = {}
_REDIS = None

def _get_redis():
    global _REDIS
    if _REDIS is not None:
        return _REDIS
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        _REDIS = None
        return None
    try:
        import redis  # optional
        _REDIS = redis.from_url(url, decode_responses=True)
        return _REDIS
    except Exception:
        _REDIS = None
        return None

def cache_get(key: str) -> Optional[str]:
    r = _get_redis()
    if r:
        try:
            return r.get(f"mdx:{key}")
        except Exception:
            pass
    v = _MEM.get(key)
    if not v: return None
    expires_at, payload = v
    if time.time() > expires_at:
        _MEM.pop(key, None)
        return None
    return payload

def cache_set(key: str, value: str, ttl_sec: int = 300) -> None:
    r = _get_redis()
    if r:
        try:
            r.setex(f"mdx:{key}", ttl_sec, value)
            return
        except Exception:
            pass
    _MEM[key] = (time.time() + max(1, int(ttl_sec)), value)
