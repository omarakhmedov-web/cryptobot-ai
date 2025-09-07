import os
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, request, jsonify

from quickscan import quickscan_entrypoint, normalize_input, SafeCache
from utils import tg_send_message, tg_answer_callback, make_markdown_safe, locale_text as _

APP_VERSION = os.environ.get("APP_VERSION", "0.2.0-quickscan-mvp")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", WEBHOOK_SECRET)  # optional separate header secret
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "5.0"))
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))

app = Flask(__name__)

cache = SafeCache(ttl=CACHE_TTL_SECONDS)

def require_webhook_secret(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # If header secret configured, enforce X-Telegram-Bot-Api-Secret-Token
        if WEBHOOK_HEADER_SECRET:
            header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if header != WEBHOOK_HEADER_SECRET:
                return ("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat(), "version": APP_VERSION})

@app.route("/")
def root():
    return jsonify({"bot": BOT_USERNAME, "status": "ok", "time": datetime.utcnow().isoformat(), "version": APP_VERSION, "webhook": f"/webhook/{WEBHOOK_SECRET[:6]}…"}), 200

@app.route("/webhook/<secret>", methods=["POST"])
@require_webhook_secret
def webhook(secret):
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        return ("forbidden", 403)

    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        return ("bad json", 400)

    # Telegram "message" or "callback_query"
    if "callback_query" in update:
        cq = update["callback_query"]
        chat_id = cq["message"]["chat"]["id"]
        data = cq.get("data", "")
        lang = detect_lang(cq["from"])
        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
            return ("ok", 200)
        # handle quickscan refresh window buttons
        if data.startswith("qs:"):
            key = data.split(":", 1)[1]  # normalized input key
            cached = cache.get(f"qs:{key}")
            if not cached:
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], _("en","cache_miss"))
                return ("ok", 200)
            # re-render with requested window if provided
            window = None
            if "window=" in data:
                try:
                    window = data.split("window=",1)[1]
                except Exception:
                    window = None
            text, keyboard = quickscan_entrypoint(cached["raw_input"], lang=lang, force_reuse=cached, window=window)
            tg_send_message(TELEGRAM_TOKEN, chat_id, text, reply_markup=keyboard, parse_mode="Markdown")
            tg_answer_callback(TELEGRAM_TOKEN, cq["id"], _("en","updated"))
        return ("ok", 200)

    msg = update.get("message") or update.get("edited_message")
    if not msg:
        return ("ok", 200)

    chat_id = msg["chat"]["id"]
    if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
        return ("ok", 200)

    text = (msg.get("text") or "").strip()
    lang = detect_lang(msg.get("from", {}))

    if not text:
        tg_send_message(TELEGRAM_TOKEN, chat_id, _("en","empty"), parse_mode="Markdown")
        return ("ok", 200)

    if text.startswith("/"):
        cmd, *rest = text.split(maxsplit=1)
        arg = rest[0] if rest else ""
        if cmd in ("/start", "/help"):
            tg_send_message(TELEGRAM_TOKEN, chat_id, _("en","help").format(bot=BOT_USERNAME), parse_mode="Markdown")
        elif cmd in ("/lang",):
            # naive language switch
            if arg.lower().startswith("ru"):
                tg_send_message(TELEGRAM_TOKEN, chat_id, _("ru","lang_switched"))
            else:
                tg_send_message(TELEGRAM_TOKEN, chat_id, _("en","lang_switched"))
        elif cmd in ("/license",):
            tg_send_message(TELEGRAM_TOKEN, chat_id, "Metridex QuickScan MVP — MIT License")
        elif cmd in ("/quota",):
            tg_send_message(TELEGRAM_TOKEN, chat_id, "Free tier — 300 DexScreener req/min shared; be kind.")
        elif cmd in ("/quickscan", "/scan"):
            if not arg:
                tg_send_message(TELEGRAM_TOKEN, chat_id, _("en","scan_usage"))
            else:
                norm = normalize_input(arg)
                text, keyboard = quickscan_entrypoint(arg, lang=lang)
                tg_send_message(TELEGRAM_TOKEN, chat_id, text, reply_markup=keyboard, parse_mode="Markdown")
        else:
            tg_send_message(TELEGRAM_TOKEN, chat_id, _("en","unknown"))
        return ("ok", 200)

    # Implicit quickscan on raw address or URL
    if text:
        text_out, keyboard = quickscan_entrypoint(text, lang=lang)
        tg_send_message(TELEGRAM_TOKEN, chat_id, text_out, reply_markup=keyboard, parse_mode="Markdown")
        return ("ok", 200)

    return ("ok", 200)

def detect_lang(user):
    # very simple heuristic by Telegram "language_code"
    code = (user or {}).get("language_code", "en").lower()
    return "ru" if code.startswith("ru") else "en"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)