# MetridexBot — minimal production-ready skeleton (Flask webhook)
# Focus: stable webhook, i18n, license stub, feature flags, no proxies.

import os
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests
from flask import Flask, request, jsonify, abort

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Environment
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN")
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET") or os.getenv("WEBHOOK_SECRET")
APP_BASE_URL = os.getenv("APP_BASE_URL", "")

if not BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN / TELEGRAM_TOKEN is not set")
if not WEBHOOK_SECRET:
    raise RuntimeError("TELEGRAM_WEBHOOK_SECRET / WEBHOOK_SECRET is not set")

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
REQUEST_TIMEOUT = 10  # seconds



# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Pricing & Limits (configurable via env)
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
FREE_LIFETIME = int(os.getenv("FREE_LIFETIME", "2"))  # total free QuickScan per Telegram user
PRO_MONTHLY = int(os.getenv("PRO_MONTHLY", "29"))
TEAMS_MONTHLY = int(os.getenv("TEAMS_MONTHLY", "99"))
DAY_PASS = int(os.getenv("DAY_PASS", "9"))
DEEP_REPORT = int(os.getenv("DEEP_REPORT", "3"))
PRO_OVERAGE_PER_100 = int(os.getenv("PRO_OVERAGE_PER_100", "5"))
SLOW_LANE_MS_FREE = int(os.getenv("SLOW_LANE_MS_FREE", "3000"))  # artificial delay for Free

USAGE_PATH = os.getenv("USAGE_PATH", "./usage.json")  # file-based storage by default

def _load_usage():
    try:
        with open(USAGE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_usage(data):
    try:
        with open(USAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        log.exception("Failed to save usage: %s", e)

def _get_user(telegram_user_id: int):
    db = _load_usage()
    key = str(telegram_user_id)
    rec = db.get(key) or {"plan":"free", "free_used":0, "pro_scans_m":0, "pro_month":"", "created_at": datetime.now(timezone.utc).isoformat()}
    return rec

def _set_user(telegram_user_id: int, rec: dict):
    db = _load_usage()
    db[str(telegram_user_id)] = rec
    _save_usage(db)

def plan_of(user_id: int) -> str:
    rec = _get_user(user_id)
    return rec.get("plan","free")

def free_left(user_id: int) -> int:
    rec = _get_user(user_id)
    return max(0, FREE_LIFETIME - int(rec.get("free_used",0)))

def inc_free(user_id: int):
    rec = _get_user(user_id)
    rec["free_used"] = int(rec.get("free_used",0)) + 1
    _set_user(user_id, rec)
    return rec["free_used"]
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Logging
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("metridex")

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# App
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
app = Flask(__name__)

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# In-memory stores (MVP; replace with DB later)
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
USER_LOCALE: Dict[int, str] = {}          # user_id -> 'en' | 'ru'
ORG_BINDINGS: Dict[str, Dict[str, Any]] = {}  # org_key -> { plan, bind_mode, chat_id, users }
QUOTAS: Dict[str, Dict[str, int]] = {}        # org_key -> counters

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# i18n (very small, extend later)
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
I18N = {
    "en": {
        "greet": "🤖 Metridex is online.
Type /help to see available commands.
Language: /lang en | /lang ru",
        "help": "Commands:
/start – welcome
/lang en|ru – set language
/help – this list
/upgrade – plans & prices
/limits – your limits
/report – Deep report (one-off)
/daypass – Pro for 24h
Quick buttons: QuickScan, Docs, Support",
        "license_ok": "✅ License activated. Your plan: PRO (demo).",
        "license_need": "Please provide a license key: /license YOUR-KEY",
        "quota": "Your quotas: QuickScan 0/∞, DeepReports 0/∞ (demo mode).",
        "unknown": "I didn't understand. Type /help.",
        "quickscan_stub": "🔎 QuickScan: send a token address / domain / t.me link.\n(Stub in MVP. Full scan will be enabled next.)",
        "changed_lang": "Language set to English.",
        "cb_ack": "Updated.",
    
        "upgrade": "Plans:\n• Free: 2 lifetime QuickScan (slow lane)\n• Pro: 300 scans/mo + Deep + export – $29/mo\n• Teams: 1500 scans/mo (5 seats) – $99/mo\n• Day-Pass: 24h of Pro – $9\n• Deep Report (one token): $3\nUpgrade via @MetridexBot web payments or contact support.", 
        "limits": "Usage: Free left: {free_left}/{free_total}. Plan: {plan}.", 
        "upsell_after_first": "You have 1 free QuickScan left. Unlock Deep, export and fast lane: Pro $29/mo or Day-Pass $9.", 
        "upsell_exhausted": "Free checks are over. Choose access:\n• Pro $29/mo – 300 scans + Deep + export\n• Day-Pass $9 – 24h of Pro\n• Deep Report $3 – one detailed report", 
        "slow_lane": "⏳ Free mode: slight queue (up to 3–5s)…", 
        "report_hint": "Send a token address/ticker and I’ll prepare a Deep Report. Price: $3 per token (one-off).", 
        "ok": "Done."},
    "ru": {
        "greet": "🤖 Metridex на связи.
Команда /help покажет список.
Язык: /lang en | /lang ru",
        "help": "Команды:
/start – приветствие
/lang en|ru – язык
/help – справка
/upgrade – тарифы и цены
/limits – ваши лимиты
/report – Deep‑отчёт (разовый)
/daypass – Pro на 24 часа
Быстрые кнопки: QuickScan, Docs, Support",
        "license_ok": "✅ Лицензия активирована. Ваш план: PRO (демо).",
        "license_need": "Укажите лицензионный ключ: /license ВАШ-КЛЮЧ",
        "quota": "Ваши лимиты: QuickScan 0/∞, DeepReports 0/∞ (демо).",
        "unknown": "Команда не распознана. Введите /help.",
        "quickscan_stub": "🔎 QuickScan: пришлите адрес токена / домен / ссылку t.me.\n(Заглушка в MVP. Полный скан включим далее.)",
        "changed_lang": "Язык переключен на русский.",
        "cb_ack": "Обновлено.",
    
        "upgrade": "Тарифы:\n• Free: 2 проверки навсегда (медленная очередь)\n• Pro: 300 проверок/мес + Deep + экспорт — $29/мес\n• Teams: 1500/мес (5 мест) — $99/мес\n• Day‑Pass: сутки Pro — $9\n• Deep Report (1 токен): $3\nОформление через @MetridexBot web‑платежи или поддержку.", 
        "limits": "Лимиты: Осталось Free: {free_left}/{free_total}. План: {plan}.", 
        "upsell_after_first": "Осталась 1 бесплатная проверка. Открой Deep, экспорт и быстрый доступ: Pro $29/мес или Day‑Pass $9.", 
        "upsell_exhausted": "Бесплатные проверки закончились. Доступ:\n• Pro $29/мес — 300 проверок + Deep + экспорт\n• Day‑Pass $9 — сутки Pro\n• Deep Report $3 — разовый отчёт", 
        "slow_lane": "⏳ Free‑режим: небольшая очередь (до 3–5 сек)…", 
        "report_hint": "Пришлите адрес токена/тикер — подготовлю Deep‑отчёт. Цена: $3 за токен (разово).", 
        "ok": "Готово."},
}

def t(user_id: Optional[int], key: str) -> str:
    lang = USER_LOCALE.get(user_id, "en")
    return I18N.get(lang, I18N["en"]).get(key, key)

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Utils
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
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

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Routes
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
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


def maybe_slow_lane(user_id: int):
    if plan_of(user_id) == "free" and SLOW_LANE_MS_FREE > 0:
        try:
            time.sleep(SLOW_LANE_MS_FREE/1000.0)
        except Exception:
            pass

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Handlers
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
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
    # Free-limit enforcement
    if plan_of(user_id) == "free":
        left = free_left(user_id)
        if left <= 0:
            send_message(chat_id, t(user_id, "upsell_exhausted"))
            return
        if left == 1:
            send_message(chat_id, t(user_id, "upsell_after_first"))
    # Simulate slow lane for free users
    maybe_slow_lane(user_id)
    # Count usage for free
    if plan_of(user_id) == "free":
        inc_free(user_id)
    send_message(chat_id, t(user_id, "quickscan_stub"), reply_markup=inline_period_keyboard())
    return

    # Plain token-like input triggers the same flow as QuickScan (stub)
if looks_like_token(text):
    if plan_of(user_id) == "free":
        left = free_left(user_id)
        if left <= 0:
            send_message(chat_id, t(user_id, "upsell_exhausted"))
            return
        if left == 1:
            send_message(chat_id, t(user_id, "upsell_after_first"))
    maybe_slow_lane(user_id)
    if plan_of(user_id) == "free":
        inc_free(user_id)
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

# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
# Gunicorn entrypoint
# --------------------

def looks_like_token(text: str) -> bool:
    t = text.strip()
    return t.startswith("0x") or t.startswith("$") or t.startswith("http")
--------------------------------------------------------
if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
