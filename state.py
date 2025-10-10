
import os, time, json
from typing import Optional, Dict, Any
from cache import _get_redis

TTL_SECONDS = int(os.getenv("SCAN_BUNDLE_TTL_SEC", "900"))  # default 15 minutes

_mem_store: Dict[str, tuple[float, Dict[str, Any]]] = {}

def _key(chat_id: int, msg_id: int) -> str:
    return f"bundle:{chat_id}:{msg_id}"

def store_bundle(chat_id: int, msg_id: int, bundle: Dict[str, Any]) -> bool:
    key = _key(chat_id, msg_id)
    r = _get_redis()
    if r:
        try:
            r.setex(key, TTL_SECONDS, json.dumps(bundle, ensure_ascii=False))
            return True
        except Exception:
            pass
    _mem_store[key] = (time.time() + TTL_SECONDS, bundle)
    return True

def load_bundle(chat_id: int, msg_id: int) -> Optional[Dict[str, Any]]:
    key = _key(chat_id, msg_id)
    r = _get_redis()
    if r:
        try:
            raw = r.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    v = _mem_store.get(key)
    if not v:
        return None
    expires_at, bundle = v
    if time.time() > expires_at:
        _mem_store.pop(key, None)
        return None
    return bundle
