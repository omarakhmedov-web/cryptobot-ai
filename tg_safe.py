import json
import time
import requests

TIMEOUT = (5, 10)  # connect, read

def _post(token: str, method: str, payload: dict, logger=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        resp = requests.post(url, json=payload, timeout=TIMEOUT)
        status = resp.status_code
        body = None
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:500]
        if logger:
            red = token[:8] + "…"
            logger.info(f"[TG] {method} -> {status} chat={payload.get('chat_id')} resp={body}")
        return status, body
    except Exception as e:
        if logger:
            logger.exception(f"[TG] {method} exception")
        return 0, {"ok": False, "error": str(e)}

def tg_send_message(token: str, chat_id, text: str, reply_markup=None, parse_mode=None, logger=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
        "allow_sending_without_reply": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return _post(token, "sendMessage", payload, logger=logger)

def tg_answer_callback(token: str, callback_query_id: str, text: str = "", logger=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
        payload["show_alert"] = False
    return _post(token, "answerCallbackQuery", payload, logger=logger)
