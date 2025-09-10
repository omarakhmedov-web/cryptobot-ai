
import os
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify

from quickscan import (
    quickscan_entrypoint,
    quickscan_pair_entrypoint,
    normalize_input,
    SafeCache,
)
from utils import locale_text  # only localization from original utils
from tg_safe import tg_send_message, tg_answer_callback  # robust Telegram sender with logging

APP_VERSION = os.environ.get("APP_VERSION", "0.2.9-quickscan-mvp+tglog")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", WEBHOOK_SECRET)
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))

# Safe alias for localization call
LOC = locale_text

app = Flask(__name__)

cache = SafeCache(ttl=CACHE_TTL_SECONDS)
seen_callbacks = SafeCache(ttl=300)

def require_webhook_secret(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
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

    # Parse update safely
    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        # Return 200 to prevent retries
        return ("ok", 200)

    try:
        # CALLBACKS (Δ buttons)
        if "callback_query" in update:
            cq = update["callback_query"]
            chat_id = cq["message"]["chat"]["id"]
            data = cq.get("data", "")
            lang = detect_lang(cq.get("from", {}))
            if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
                return ("ok", 200)

            # Deduplicate
            cqid = cq.get("id")
            if cqid and seen_callbacks.get(cqid):
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
                return ("ok", 200)
            if cqid:
                seen_callbacks.set(cqid, True)

            if data.startswith("qs2:"):
                payload = data.split(":", 1)[1]  # 'chain/pair?window=h1'
                path, _, window = payload.partition("?window=")
                window = window or "h24"
                chain, _, pair_addr = path.partition("/")
                text, keyboard = quickscan_pair_entrypoint(chain, pair_addr, window=window)
                tg_send_message(TELEGRAM_TOKEN, chat_id, text, reply_markup=keyboard, logger=app.logger)
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
                return ("ok", 200)

            if data.startswith("qs:"):
                payload = data.split(":", 1)[1]
                addr, _, window = payload.partition("?window=")
                window = window or "h24"
                text, keyboard = quickscan_entrypoint(addr, lang=lang, window=window, lean=True)
                tg_send_message(TELEGRAM_TOKEN, chat_id, text, reply_markup=keyboard, logger=app.logger)
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
                return ("ok", 200)

            return ("ok", 200)

        # MESSAGES
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            return ("ok", 200)

        # Ignore bot's own messages to prevent echo loops
        if (msg.get("from") or {}).get("is_bot"):
            return ("ok", 200)

        chat_id = msg["chat"]["id"]
        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
            return ("ok", 200)

        text = (msg.get("text") or "").strip()
        lang = detect_lang(msg.get("from", {}))

        if not text:
            tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "empty"), logger=app.logger)
            return ("ok", 200)

        if text.startswith("/"):
            cmd, *rest = text.split(maxsplit=1)
            arg = rest[0] if rest else ""

            if cmd in ("/start", "/help"):
                tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "help").format(bot=BOT_USERNAME), parse_mode="Markdown", logger=app.logger)

            elif cmd in ("/lang",):
                if arg.lower().startswith("ru"):
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("ru", "lang_switched"), logger=app.logger)
                else:
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "lang_switched"), logger=app.logger)

            elif cmd in ("/license",):
                tg_send_message(TELEGRAM_TOKEN, chat_id, "Metridex QuickScan MVP — MIT License", logger=app.logger)

            elif cmd in ("/quota",):
                tg_send_message(TELEGRAM_TOKEN, chat_id, "Free tier — 300 DexScreener req/min shared; be kind.", logger=app.logger)

            elif cmd in ("/quickscan", "/scan"):
                if not arg:
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "scan_usage"), logger=app.logger)
                else:
                    norm = normalize_input(arg)
                    text_out, keyboard = quickscan_entrypoint(arg, lang=lang)
                    tg_send_message(TELEGRAM_TOKEN, chat_id, text_out, reply_markup=keyboard, logger=app.logger)

            else:
                tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "unknown"), logger=app.logger)
            return ("ok", 200)

        # Implicit quickscan
        if text:
            text_out, keyboard = quickscan_entrypoint(text, lang=lang)
            tg_send_message(TELEGRAM_TOKEN, chat_id, text_out, reply_markup=keyboard, logger=app.logger)
            return ("ok", 200)

        return ("ok", 200)

    except Exception:
        # Always acknowledge to stop Telegram retries
        try:
            if "callback_query" in update:
                cq = update["callback_query"]
                tg_answer_callback(TELEGRAM_TOKEN, cq.get("id"), LOC("en", "error"), logger=app.logger)
        except Exception:
            pass
        return ("ok", 200)

def detect_lang(user):
    code = (user or {}).get("language_code", "en").lower()
    return "ru" if code.startswith("ru") else "en"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
