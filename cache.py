import os
import time
from typing import Optional, Any
from common import getenv_int

class _MemoryCache:
    def __init__(self):
        self._store = {}  # key -> (value, expires_at)
    def set(self, key: str, value: Any, ttl: int):
        self._store[key] = (value, time.time() + ttl)
    def get(self, key: str) -> Optional[Any]:
        v = self._store.get(key)
        if not v: return None
        val, exp = v
        if time.time() > exp:
            self._store.pop(key, None)
            return None
        return val

_redis = None
def _get_redis():
    global _redis
    if _redis is not None:
        return _redis
    url = os.getenv("REDIS_URL")
    if not url:
        _redis = None
        return None
    try:
        from redis import Redis
        _redis = Redis.from_url(url, decode_responses=True)
        _redis.ping()
        return _redis
    except Exception:
        _redis = None
        return None

_mem = _MemoryCache()

def cache_set(key: str, value: str, ttl: int) -> None:
    r = _get_redis()
    if r:
        try:
            r.setex(key, ttl, value)
            return
        except Exception:
            pass
    _mem.set(key, value, ttl)

def cache_get(key: str) -> Optional[str]:
    r = _get_redis()
    if r:
        try:
            v = r.get(key)
            if v is not None:
                return v
        except Exception:
            pass
    return _mem.get(key)
