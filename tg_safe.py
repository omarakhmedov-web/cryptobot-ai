import requests

TIMEOUT = (5, 10)  # connect, read
MAX_LEN = 3800  # safety margin under Telegram 4096

def _post(token: str, method: str, payload: dict, logger=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        resp = requests.post(url, json=payload, timeout=TIMEOUT)
        status = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {"ok": False, "text": resp.text[:500]}
        if logger:
            logger.info(f"[TG] {method} -> {status} chat={payload.get('chat_id')} resp={body}")
        return status, body
    except Exception as e:
        if logger:
            logger.exception(f"[TG] {method} exception")
        return 0, {"ok": False, "error": str(e)}

def _split_text(text: str):
    if len(text) <= MAX_LEN:
        return [text]
    parts = []
    t = text
    while len(t) > MAX_LEN:
        cut = t.rfind("\n\n", 0, MAX_LEN)
        if cut < MAX_LEN * 0.7:
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
            "text": chunk,
            "disable_web_page_preview": True,
            "allow_sending_without_reply": True,
        }
        if i == 0 and reply_markup:
            payload["reply_markup"] = reply_markup
        if parse_mode:
            payload["parse_mode"] = parse_mode
        last_status, last_body = _post(token, "sendMessage", payload, logger=logger)
    return last_status, last_body

def tg_answer_callback(token: str, callback_query_id: str, text: str = "", logger=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
        payload["show_alert"] = False
    return _post(token, "answerCallbackQuery", payload, logger=logger)
