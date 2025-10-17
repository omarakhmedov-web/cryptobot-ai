
"""
safe_cache.py — Idempotency TTL cache
-------------------------------------
Use: cache = TTLCache(ttl_seconds=30); if cache.hit(key): return  # skip duplicate
"""

import time
from typing import Dict

class TTLCache:
    def __init__(self, ttl_seconds: int = 30, max_size: int = 5000):
        self.ttl = ttl_seconds
        self.max = max_size
        self._store: Dict[str, float] = {}

    def _prune(self):
        now = time.time()
        expired = [k for k, ts in self._store.items() if (now - ts) >= self.ttl]
        for k in expired:
            self._store.pop(k, None)
        # Size cap (simple FIFO-ish)
        if len(self._store) > self.max:
            for k in list(self._store.keys())[: len(self._store) - self.max]:
                self._store.pop(k, None)

    def hit(self, key: str) -> bool:
        now = time.time()
        self._prune()
        if key in self._store:
            # duplicate within TTL
            return True
        self._store[key] = now
        return False
