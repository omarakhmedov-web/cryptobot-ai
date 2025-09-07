# MetridexBot — minimal production-ready skeleton (Flask webhook)
# Focus: stable webhook, i18n, license stub, feature flags, no proxies.

import os
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests
from flask import Flask, request, jsonify, abort

# ----------------------------------------------------------------------------
# Environment
# ----------------------------------------------------------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN")
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET") or os.getenv("WEBHOOK_SECRET")
APP_BASE_URL = os.getenv("APP_BASE_URL", "")

if not BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN / TELEGRAM_TOKEN is not set")
if not WEBHOOK_SECRET:
    raise RuntimeError("TELEGRAM_WEBHOOK_SECRET / WEBHOOK_SECRET is not set")

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
REQUEST_TIMEOUT = 10  # seconds

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("metridex")

# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------
app = Flask(__name__)

# ----------------------------------------------------------------------------
# In-memory stores (MVP; replace with DB later)
# ----------------------------------------------------------------------------
USER_LOCALE: Dict[int, str] = {}          # user_id -> 'en' | 'ru'
ORG_BINDINGS: Dict[str, Dict[str, Any]] = {}  # org_key -> { plan, bind_mode, chat_id, users }
QUOTAS: Dict[str, Dict[str, int]] = {}        # org_key -> counters

# ----------------------------------------------------------------------------
# i18n (very small, extend later)
# ----------------------------------------------------------------------------
I18N = {
    "en": {
        "greet": "🤖 Metridex is online.\nType /help to see available commands.\nLanguage: /lang en | /lang ru",
        "help": "Commands:\n/start – welcome\n/lang en|ru – set language\n/license <KEY> – activate license\n/quota – show usage\nQuick buttons: QuickScan, Docs, Support",
        "license_ok": "✅ License activated. Your plan: PRO (demo).",
        "license_need": "Please provide a license key: /license YOUR-KEY",
        "quota": "Your quotas: QuickScan 0/∞, DeepReports 0/∞ (demo mode).",
        "unknown": "I didn't understand. Type /help.",
        "quickscan_stub": "🔎 QuickScan: send a token address / domain / t.me link.\n(Stub in MVP. Full scan will be enabled next.)",
        "changed_lang": "Language set to English.",
        "cb_ack": "Updated.",
    },
    "ru": {
        "greet": "🤖 Metridex запущен.\nКоманда /help покажет доступные команды.\nЯзык: /lang en | /lang ru",
        "help": "Команды:\n/start – приветствие\n/lang en|ru – выбрать язык\n/license <КЛЮЧ> – активировать лицензию\n/quota – текущие лимиты\nБыстрые кнопки: QuickScan, Docs, Support",
        "license_ok": "✅ Лицензия активирована. Ваш план: PRO (демо).",
        "license_need": "Укажите лицензионный ключ: /license ВАШ-КЛЮЧ",
        "quota": "Ваши лимиты: QuickScan 0/∞, DeepReports 0/∞ (демо).",
        "unknown": "Команда не распознана. Введите /help.",
        "quickscan_stub": "🔎 QuickScan: пришлите адрес токена / домен / ссылку t.me.\n(Заглушка в MVP. Полный скан включим далее.)",
        "changed_lang": "Язык переключен на русский.",
        "cb_ack": "Обновлено.",
    },
}

def t(user_id: Optional[int], key: str) -> str:
    lang = USER_LOCALE.get(user_id, "en")
    return I18N.get(lang, I18N["en"]).get(key, key)

# ----------------------------------------------------------------------------
# Utils
# ----------------------------------------------------------------------------
def send_message(chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        r = requests.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning("sendMessage non-200: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        log.exception("sendMessage failed: %s", e)

def answer_callback_query(callback_query_id: str, text: str = ""):
    try:
        r = requests.post(f"{TELEGRAM_API}/answerCallbackQuery", json={"callback_query_id": callback_query_id, "text": text}, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning("answerCallbackQuery non-200: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        log.exception("answerCallbackQuery failed: %s", e)

def edit_message_text(chat_id: int, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        r = requests.post(f"{TELEGRAM_API}/editMessageText", json=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning("editMessageText non-200: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        log.exception("editMessageText failed: %s", e)

def main_keyboard():
    return {
        "keyboard": [[{"text": "QuickScan"}], [{"text": "Docs"}, {"text": "Support"}]],
        "resize_keyboard": True,
        "one_time_keyboard": False,
    }

def inline_period_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "24h", "callback_data": "period:24h"},
             {"text": "7d", "callback_data": "period:7d"},
             {"text": "30d", "callback_data": "period:30d"}]
        ]
    }

# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return "ok", 200

@app.get("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "bot": "MetridexBot",
        "webhook": f"/webhook/{WEBHOOK_SECRET[:6]}…",
        "version": "0.1.0-skeleton"
    })

@app.post(f"/webhook/{WEBHOOK_SECRET}")
def webhook():
    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        abort(400)
    if not update:
        abort(400)

    # Handle updates
    try:
        if "message" in update:
            handle_message(update["message"])
        elif "edited_message" in update:
            # ignore silently or handle if needed
            pass
        elif "callback_query" in update:
            handle_callback(update["callback_query"])
        elif "my_chat_member" in update or "chat_member" in update:
            # membership changes
            pass
    except Exception as e:
        log.exception("Error handling update: %s", e)

    # Always ACK 200 quickly
    return "", 200

# ----------------------------------------------------------------------------
# Handlers
# ----------------------------------------------------------------------------
def handle_message(msg: Dict[str, Any]):
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    from_user = msg.get("from", {})
    user_id = from_user.get("id")
    text = msg.get("text") or ""

    if not chat_id or not user_id:
        return

    # language default
    USER_LOCALE.setdefault(user_id, "en")

    # Commands
    if text.startswith("/"):
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "/start":
            send_message(chat_id, t(user_id, "greet"), reply_markup=main_keyboard())
            return
        if cmd == "/help":
            send_message(chat_id, t(user_id, "help"))
            return
        if cmd == "/lang":
            lang = (arg or "").strip().lower()
            if lang in ("en", "ru"):
                USER_LOCALE[user_id] = lang
                send_message(chat_id, t(user_id, "changed_lang"))
            else:
                send_message(chat_id, "Usage: /lang en | /lang ru")
            return
        if cmd == "/license":
            key = (arg or "").strip()
            if not key:
                send_message(chat_id, t(user_id, "license_need"))
                return
            # Bind to org (demo): org_key = str(chat_id) or custom
            org_key = f"org:{chat_id}"
            ORG_BINDINGS[org_key] = {"plan": "PRO", "bind_mode": "chat", "chat_id": chat_id, "users": {user_id}}
            QUOTAS.setdefault(org_key, {"quickscan": 0, "deep": 0})
            send_message(chat_id, t(user_id, "license_ok"))
            return
        if cmd == "/quota":
            org_key = f"org:{chat_id}"
            q = QUOTAS.get(org_key, {"quickscan": 0, "deep": 0})
            send_message(chat_id, t(user_id, "quota") + f"\n(q:{q['quickscan']} d:{q['deep']})")
            return

        # Unknown command
        send_message(chat_id, t(user_id, "unknown"))
        return

    # Plain text
    lowered = text.strip().lower()
    if lowered == "quickscan":
        send_message(chat_id, t(user_id, "quickscan_stub"), reply_markup=inline_period_keyboard())
        return

    # Fallback
    send_message(chat_id, t(user_id, "unknown"))

def handle_callback(cb: Dict[str, Any]):
    cq_id = cb.get("id")
    data = cb.get("data", "")
    msg = cb.get("message", {})
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    message_id = msg.get("message_id")
    from_user = cb.get("from", {})
    user_id = from_user.get("id")

    if cq_id:
        answer_callback_query(cq_id, t(user_id, "cb_ack"))

    if data.startswith("period:"):
        period = data.split(":", 1)[1]
        new_text = f"📈 Period selected: <b>{period}</b>\n(Stub: data would refresh here.)"
        edit_message_text(chat_id, message_id, new_text, reply_markup=inline_period_keyboard())

# ----------------------------------------------------------------------------
# Gunicorn entrypoint
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
