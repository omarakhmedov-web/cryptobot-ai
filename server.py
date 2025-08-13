# server.py
import os
import re
from flask import Flask, request
from telegram import Bot
from groq import Groq

app = Flask(__name__)

# === ENV ===
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
MODEL          = os.getenv("MODEL", "llama-3.1-8b-instant")   # безопасный дефолт
PORT           = int(os.environ.get("PORT", 10000))

bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # ВАЖНО: без proxies и без позиционных kwargs

# --- очень простой, устойчивый детектор языка (по юникод-диапазонам) ---
LANG_RE = {
    "ru": r"[\u0400-\u04FF]",        # кириллица
    "zh": r"[\u4E00-\u9FFF]",        # китайские иероглифы
    "ar": r"[\u0600-\u06FF]",        # арабское письмо
    "tr": r"[çğıöşüİĞÖŞÜ]",          # турецкие буквы
}
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip().lower()
    for code, pat in LANG_RE.items():
        if re.search(pat, t):
            return code
    # латиница: если много ascii – считаем английским
    ascii_ratio = sum(1 for ch in t if 'a' <= ch <= 'z') / max(1, len(t))
    return "en" if ascii_ratio > 0.5 else "en"

WELCOME = {
    "en": "Hello! I'm CryptoGuard, your Web3 security assistant. Send a contract address or token address and say what you want to check.",
    "ru": "Привет! Я CryptoGuard — помощник по безопасности в Web3. Отправьте адрес контракта или токена и напишите, что проверить.",
    "tr": "Merhaba! Ben CryptoGuard. Bir sözleşme ya da token adresi gönderin ve neyi kontrol etmemi istediğinizi yazın.",
    "zh": "你好！我是 CryptoGuard。请发送合约或代币地址，并说明需要检查的内容。",
    "ar": "مرحبًا! أنا CryptoGuard. أرسل عنوان العقد أو الرمز وأخبرني بما تريد التحقق منه.",
}

SYSTEM_PROMPT = (
    "You are CryptoGuard, a Web3 security assistant. Be concise and practical. "
    "When the user provides a token/contract address, draft a risk-oriented checklist and explain findings. "
    "Cover: ownership/mint/fees/blacklist or pause; proxy/upgradability; deployer history & socials; "
    "liquidity locks & top holders; transfer anomalies; common Web3 red flags; simple next steps. "
    "If on-chain APIs are not available here, clearly say that data is not publicly available and list what is needed. "
    "Never invent on-chain facts."
)

def reply_text(chat_id: int, text: str) -> None:
    try:
        bot.send_message(chat_id=chat_id, text=text)
    except Exception as e:
        # не падаем из-за телеграм-сбоев
        print("Telegram send error:", e)

@app.route("/", methods=["GET"])
def index():
    return "ok"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg  = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return "ok"

    text = (msg.get("text") or msg.get("caption") or "").strip()

    # /start — приветствие
    if text.startswith("/start"):
        lang = "en"
        reply_text(chat_id, WELCOME.get(lang, WELCOME["en"]))
        return "ok"

    # авто-язык
    lang = detect_lang(text)
    welcome_fallback = WELCOME.get(lang, WELCOME["en"])

    # если пользователь прислал совсем короткое сообщение
    if not text or len(text) < 2:
        reply_text(chat_id, welcome_fallback)
        return "ok"

    # диалог для модели
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + f" Always reply in {lang}."},
        {"role": "user",   "content": text},
    ]

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.3,
        )
        # библиотека Groq возвращает message.content
        content = (resp.choices[0].message.content or "").strip()
        if not content:
            content = welcome_fallback
        reply_text(chat_id, content)
    except Exception as e:
        # показываем аккуратную ошибку пользователю и печатаем в логи
        print("LLM error:", e)
        reply_text(
            chat_id,
            WELCOME.get(lang, WELCOME["en"]) +
            ("\n\n— (Внутренняя ошибка модели; попробуйте повторить запрос через минуту.)" if lang == "ru"
             else "\n\n— (Internal model error; please try again in a minute.)")
        )

    return "ok"

if __name__ == "__main__":
    # локальный запуск (на Render используется gunicorn)
    app.run(host="0.0.0.0", port=PORT)
