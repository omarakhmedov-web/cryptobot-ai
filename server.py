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
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback

APP_VERSION = os.environ.get("APP_VERSION", "0.3.3-quickscan-mvp+echo")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))

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
                app.logger.warning("[AUTH] bad header secret")
                return ("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
        "version": APP_VERSION,
        "allow_all_chats": (len(ALLOWED_CHAT_IDS) == 0),
        "header_secret_required": bool(WEBHOOK_HEADER_SECRET),
    })

@app.route("/debug")
def debug():
    whs = WEBHOOK_SECRET[:6] + "…" if WEBHOOK_SECRET else ""
    return jsonify({
        "version": APP_VERSION,
        "bot": BOT_USERNAME,
        "env": {
            "TELEGRAM_TOKEN_set": bool(TELEGRAM_TOKEN),
            "WEBHOOK_SECRET_hint": whs,
            "WEBHOOK_HEADER_SECRET_set": bool(WEBHOOK_HEADER_SECRET),
            "ALLOWED_CHAT_IDS_count": len(ALLOWED_CHAT_IDS),
            "CACHE_TTL_SECONDS": CACHE_TTL_SECONDS,
        }
    })

@app.route("/selftest")
def selftest():
    chat_id = request.args.get("chat_id")
    text = request.args.get("text", "ping")
    if not TELEGRAM_TOKEN or not chat_id:
        return jsonify({"ok": False, "error": "missing token or chat_id"}), 400
    st, body = tg_send_message(TELEGRAM_TOKEN, chat_id, f"[selftest] {text}", logger=app.logger)
    return jsonify({"ok": (st == 200 and (isinstance(body, dict) and body.get("ok"))), "status": st, "resp": body})

@app.route("/qs_preview")
def qs_preview():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"ok": False, "error": "missing q"}), 400
    try:
        text_out, keyboard = quickscan_entrypoint(q, lang="en", lean=True)
        return jsonify({"ok": True, "text": text_out, "keyboard": keyboard})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/webhook/<secret>", methods=["POST"])
@require_webhook_secret
def webhook(secret):
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        app.logger.warning("[AUTH] bad path secret")
        return ("forbidden", 403)

    try:
        update = request.get_json(force=True, silent=False)
    except Exception:
        app.logger.exception("[UPD] bad json")
        return ("ok", 200)

    try:
        # CALLBACKS (Δ)
        if "callback_query" in update:
            cq = update["callback_query"]
            chat_id = cq["message"]["chat"]["id"]
            data = cq.get("data", "")
            app.logger.info(f"[UPD] callback chat={chat_id} data={data}")

            if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
                app.logger.info(f"[UPD] callback ignored (not allowed) chat={chat_id}")
                return ("ok", 200)

            cqid = cq.get("id")
            if cqid and seen_callbacks.get(cqid):
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
                return ("ok", 200)
            if cqid:
                seen_callbacks.set(cqid, True)

            try:
                if data.startswith("qs2:"):
                    path, _, window = data.split(":", 1)[1].partition("?window=")
                    chain, _, pair_addr = path.partition("/")
                    window = window or "h24"
                    text, keyboard = quickscan_pair_entrypoint(chain, pair_addr, window=window)
                elif data.startswith("qs:"):
                    addr, _, window = data.split(":", 1)[1].partition("?window=")
                    window = window or "h24"
                    text, keyboard = quickscan_entrypoint(addr, lang="en", window=window, lean=True)
                else:
                    return ("ok", 200)

                app.logger.info(f"[QS] cb window={window} -> len={len(text)}")
                tg_send_message(TELEGRAM_TOKEN, chat_id, text, reply_markup=keyboard, logger=app.logger)
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "updated"), logger=app.logger)
            except Exception:
                app.logger.exception("[ERR] callback quickscan")
                tg_answer_callback(TELEGRAM_TOKEN, cq["id"], LOC("en", "error"), logger=app.logger)
            return ("ok", 200)

        # MESSAGES
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            app.logger.info("[UPD] no message/callback")
            return ("ok", 200)

        if (msg.get("from") or {}).get("is_bot"):
            app.logger.info("[UPD] from bot, ignore")
            return ("ok", 200)

        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()
        app.logger.info(f"[UPD] message chat={chat_id} text={text[:80]}")

        if ALLOWED_CHAT_IDS and str(chat_id) not in ALLOWED_CHAT_IDS:
            app.logger.info(f"[UPD] message ignored (not allowed) chat={chat_id}")
            return ("ok", 200)

        if not text:
            tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "empty"), logger=app.logger)
            return ("ok", 200)

        if text.startswith("/"):
            cmd, *rest = text.split(maxsplit=1)
            arg = rest[0] if rest else ""
            app.logger.info(f"[CMD] {cmd} arg={arg}")

            if cmd in ("/start", "/help"):
                tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "help").format(bot=BOT_USERNAME), parse_mode="Markdown", logger=app.logger)
                return ("ok", 200)

            if cmd == "/lang":
                if arg.lower().startswith("ru"):
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("ru", "lang_switched"), logger=app.logger)
                else:
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "lang_switched"), logger=app.logger)
                return ("ok", 200)

            if cmd == "/license":
                tg_send_message(TELEGRAM_TOKEN, chat_id, "Metridex QuickScan MVP — MIT License", logger=app.logger)
                return ("ok", 200)

            if cmd == "/quota":
                tg_send_message(TELEGRAM_TOKEN, chat_id, "Free tier — 300 DexScreener req/min shared; be kind.", logger=app.logger)
                return ("ok", 200)

            if cmd in ("/quickscan", "/scan"):
                if not arg:
                    tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "scan_usage"), logger=app.logger)
                else:
                    try:
                        text_out, keyboard = quickscan_entrypoint(arg, lang="en", lean=True)
                        app.logger.info(f"[QS] cmd -> len={len(text_out)}")
                        tg_send_message(TELEGRAM_TOKEN, chat_id, text_out, reply_markup=keyboard, logger=app.logger)
                    except Exception:
                        app.logger.exception("[ERR] cmd quickscan")
                        tg_send_message(TELEGRAM_TOKEN, chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
                return ("ok", 200)

            tg_send_message(TELEGRAM_TOKEN, chat_id, LOC("en", "unknown"), logger=app.logger)
            return ("ok", 200)

        # Implicit quickscan (plain address, pair URL, etc.)
        # New: immediate echo to prove receipt
        tg_send_message(TELEGRAM_TOKEN, chat_id, "Processing…", logger=app.logger)
        try:
            text_out, keyboard = quickscan_entrypoint(text, lang="en", lean=True)
            app.logger.info(f"[QS] implicit -> len={len(text_out)}")
            tg_send_message(TELEGRAM_TOKEN, chat_id, text_out, reply_markup=keyboard, logger=app.logger)
        except Exception:
            app.logger.exception("[ERR] implicit quickscan")
            tg_send_message(TELEGRAM_TOKEN, chat_id, "Temporary error while scanning. Please try again.", logger=app.logger)
        return ("ok", 200)

    except Exception:
        app.logger.exception("[ERR] webhook handler (outer)")
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
