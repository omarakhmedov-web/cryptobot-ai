import requests
from typing import Any, Dict, Tuple, List

# Timeouts and Telegram text chunking
TIMEOUT = (5, 10)  # connect, read
MAX_LEN = 3800     # safety margin under Telegram 4096

# --- SAFE9e glue (graceful fallbacks) ---
def _norm(x: Any) -> Any:
    try:
        from safe9e_stateful import normalize_consistent as _n
        return _n(x)
    except Exception:
        try:
            from safe9e_text_normalizer import normalize as _n2
            return _n2(x)
        except Exception:
            return x

def _canon_markup(markup: Any) -> Any:
    try:
        from safe9e_replycanon import canonicalize_reply_markup
        return canonicalize_reply_markup(markup, max_per_row=3)
    except Exception:
        return markup

def _prep_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload
    p = dict(payload)  # shallow copy
    if isinstance(p.get("text"), str):
        p["text"] = _norm(p["text"])
    if isinstance(p.get("caption"), str):
        p["caption"] = _norm(p["caption"])
    if isinstance(p.get("reply_markup"), dict):
        p["reply_markup"] = _canon_markup(p["reply_markup"])
    return p
# --- /SAFE9e glue ---

def _post(token: str, method: str, payload: dict, logger=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        payload = _prep_payload(payload)
        resp = requests.post(url, json=payload, timeout=TIMEOUT)
        status = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {"ok": False, "text": (resp.text or "")[:500]}
        if logger:
            logger.info(f"[TG] {method} -> {status} chat={payload.get('chat_id')} resp={body}")
        return status, body
    except Exception as e:
        if logger:
            logger.exception(f"[TG] {method} exception")
        return 0, {"ok": False, "error": str(e)}

def _split_text(text: str) -> List[str]:
    if len(text) <= MAX_LEN:
        return [text]
    parts = []
    t = text or ""
    while len(t) > MAX_LEN:
        cut = t.rfind("\n\n", 0, MAX_LEN)
        if cut < int(MAX_LEN * 0.7):
            cut = MAX_LEN
        parts.append(t[:cut])
        t = t[cut:]
    if t:
        parts.append(t)
    return parts

def tg_send_message(token: str, chat_id, text: str, reply_markup=None, parse_mode=None, logger=None):
    chunks = _split_text(text or "")
    last_status = None
    last_body = None
    for i, chunk in enumerate(chunks):
        payload = {
            "chat_id": chat_id,
            "text": _norm(chunk),
            "disable_web_page_preview": True,
            "allow_sending_without_reply": True,
        }
        # Показываем клавиатуру на первом чанке (как раньше) — уже канонизированную
        if i == 0 and reply_markup:
            payload["reply_markup"] = _canon_markup(reply_markup)
        if parse_mode:
            payload["parse_mode"] = parse_mode
        last_status, last_body = _post(token, "sendMessage", payload, logger=logger)
    return last_status, last_body

def tg_edit_message_text(token: str, chat_id, message_id, text: str, reply_markup=None, parse_mode=None, logger=None):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": _norm(text or ""),
        "disable_web_page_preview": True,
        "allow_sending_without_reply": True,
    }
    if reply_markup:
        payload["reply_markup"] = _canon_markup(reply_markup)
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return _post(token, "editMessageText", payload, logger=logger)

def tg_answer_callback(token: str, callback_query_id: str, text: str = "", logger=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = _norm(text)
        payload["show_alert"] = False
    return _post(token, "answerCallbackQuery", payload, logger=logger)
