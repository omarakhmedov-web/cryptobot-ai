import os
from typing import Tuple
from cache import _get_redis
from common import now_ts, dt_utc_iso, parse_iso8601, getenv_int

FREE_DAILY = getenv_int("FREE_DAILY_LIMIT", 2)
PRO_DAILY = getenv_int("PRO_DAILY_LIMIT", 10000)
TEAMS_DAILY = getenv_int("TEAMS_DAILY_LIMIT", 50000)

PASS_CODE = os.getenv("JUDGE_PASS_CODE","")
PASS_EXPIRES_AT = os.getenv("JUDGE_PASS_EXPIRES_AT","")
PASS_MAX_ACTIVE = getenv_int("JUDGE_PASS_MAX_ACTIVE", 5)

def _day_key(user_id: int) -> str:
    from time import gmtime, strftime
    d = strftime("%Y%m%d", gmtime())
    return f"scan:{user_id}:{d}"

def can_scan(user_id: int) -> Tuple[bool, str]:
    r = _get_redis()
    if not r:
        # memory-less fallback: allow
        return True, "ok"
    k = _day_key(user_id)
    n = int(r.get(k) or 0)
    # Judge pass?
    if is_judge_active(user_id):
        return True, "judge-pass"
    if n < FREE_DAILY:
        return True, "free"
    return False, "limit-reached"

def register_scan(user_id: int) -> None:
    r = _get_redis()
    if not r:
        return
    k = _day_key(user_id)
    p = r.pipeline()
    p.incr(k, 1)
    # expire in ~36h to be safe
    p.expire(k, 36*3600)
    p.execute()

def is_judge_active(user_id: int) -> bool:
    r = _get_redis()
    if not r: return False
    if not PASS_CODE: return False
    exp = parse_iso8601(PASS_EXPIRES_AT)
    if exp and now_ts() >= exp:
        return False
    return r.sismember("judge:active", str(user_id))

def try_activate_judge_pass(user_id: int, code: str) -> Tuple[bool, str]:
    if code.strip() != PASS_CODE or not PASS_CODE:
        return False, "Invalid code"
    exp = parse_iso8601(PASS_EXPIRES_AT)
    if exp and now_ts() >= exp:
        return False, "Code expired"
    r = _get_redis()
    if not r:
        return False, "No Redis for pass"
    # Limit active set size
    active = r.scard("judge:active")
    if active >= PASS_MAX_ACTIVE and not r.sismember("judge:active", str(user_id)):
        return False, "Limit reached for activations"
    r.sadd("judge:active", str(user_id))
    if exp:
        # Use a TTL that covers the expiry
        ttl = max(60, exp - now_ts())
        r.expire("judge:active", ttl)
    return True, "Activated"
