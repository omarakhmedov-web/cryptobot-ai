import json
from typing import Optional, Dict, Any
from cache import _get_redis

TTL_SECONDS = 15 * 60  # 15 minutes per-message bundle

def _key(chat_id: int, msg_id: int) -> str:
    return f"bundle:{chat_id}:{msg_id}"

def store_bundle(chat_id: int, msg_id: int, bundle: Dict[str, Any]) -> bool:
    r = _get_redis()
    if not r:
        return False
    try:
        r.setex(_key(chat_id, msg_id), TTL_SECONDS, json.dumps(bundle, ensure_ascii=False))
        return True
    except Exception:
        return False

def load_bundle(chat_id: int, msg_id: int) -> Optional[Dict[str, Any]]:
    r = _get_redis()
    if not r:
        return None
    try:
        v = r.get(_key(chat_id, msg_id))
        if not v:
            return None
        return json.loads(v)
    except Exception:
        return None
