
# perf_guard.py — debounce & reentry guard for Metridex bot
import time, threading, traceback

_G = {}
_LOCK = threading.RLock()
IN_FLIGHT = {}       # {chat_id: ts}
LAST_CB = {}         # {(chat_id, msg_id, data): ts}

MIN_GAP_S = float(__import__("os").getenv("PERF_MIN_GAP_SECONDS", "1.0"))
CB_DEBOUNCE_S = float(__import__("os").getenv("PERF_CB_DEBOUNCE_SECONDS", "2.5"))

def _now(): return time.time()

def _busy(chat_id):
    with _LOCK:
        ts = IN_FLIGHT.get(chat_id, 0)
        return (_now() - ts) < MIN_GAP_S

def _mark(chat_id):
    with _LOCK:
        IN_FLIGHT[chat_id] = _now()

def _wrap_on_message(orig):
    def wrapper(msg: dict):
        try:
            chat_id = msg["chat"]["id"]
        except Exception:
            return orig(msg)
        if _busy(chat_id):
            # silently drop re-entrant triggers to avoid duplicate "Processing…" or double scans
            return _G.get("jsonify", lambda x: x)({"ok": True})
        _mark(chat_id)
        try:
            return orig(msg)
        finally:
            _mark(chat_id)  # reset timestamp to enforce minimal quiet period
    return wrapper

def _wrap_on_callback(orig):
    def wrapper(cb: dict):
        try:
            msg = cb.get("message") or {}
            chat_id = msg.get("chat", {}).get("id")
            msg_id  = msg.get("message_id")
            data    = (cb.get("data") or "")
        except Exception:
            return orig(cb)
        key = (chat_id, msg_id, data)
        with _LOCK:
            last = LAST_CB.get(key, 0)
            if (_now() - last) < CB_DEBOUNCE_S:
                # swallow fast repeat callbacks (e.g., double taps, Telegram retries)
                return _G.get("jsonify", lambda x: x)({"ok": True})
            LAST_CB[key] = _now()
        try:
            return orig(cb)
        finally:
            # do not clear immediately; debounce window handles repeats
            pass
    return wrapper

def install(g):
    global _G
    _G = g
    if "jsonify" not in g: g["jsonify"] = lambda x: x
    if "on_message" in g and callable(g["on_message"]):
        g["on_message"] = _wrap_on_message(g["on_message"])
    if "on_callback" in g and callable(g["on_callback"]):
        g["on_callback"] = _wrap_on_callback(g["on_callback"])
    return True
