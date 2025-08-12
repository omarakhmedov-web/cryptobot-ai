# server.py
import os
from flask import Flask, request
import telegram
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
PORT = int(os.environ.get("PORT", 10000))

bot = telegram.Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # ВАЖНО: без proxies и без позиционного ключа

# --- очень простой детектор языка по алфавиту ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    # если есть кириллица
    if any("а" <= ch <= "я" or "А" <= ch <= "Я" for ch in text):
        return "ru"
    # если есть арабская вязь
    if any("\u0600" <= ch <= "\u06FF" for ch in text):
        return "ar"
    # китайско-японские каны/кандзи
    if any("\u4e00" <= ch <= "\u9fff" or "\u3040" <= ch <= "\u30ff" for ch in text):
        return "zh"
    return "en"

# --- system prompt с веб3-помощником ---
SYSTEM_PROMPT = (
    "You are CryptoGuard, a careful Web3 assistant.\n"
    "- Be concise. If the user asks for details, expand.\n"
    "- Security first: never click unknown links; warn about common Web3 red flags.\n"
    "- When asked to review tokens, projects, or contracts, outline checks you CANNOT do from chat "
    "and what the user can verify (team transparency, audit history, liquidity locks, holders "
    "distribution, contract renounce status, deployer activity, unusual transfers, and risky functions).\n"
    "- If the user’s message is not in English, reply in that language."
)

WELCOME = {
    "en": "Hi! I’m CryptoGuard. Ask me about tokens, contracts, wallets, on-chain risks, or general crypto topics. "
          "I’ll answer briefly unless you ask for details.",
    "ru": "Привет! Я CryptoGuard. Спроси про токены, контракты, кошельки, риски в ончейне или общие темы по крипте. "
          "Отвечаю кратко, при необходимости дам детали.",
    "ar": "مرحباً! أنا CryptoGuard. اسألني عن التوكنات والعقود والمحافظ ومخاطر السلسلة أو مواضيع التشفير عامة. "
          "سأجيب بإيجاز ما لم تطلب التفاصيل.",
    "zh": "你好！我是 CryptoGuard。可以问我代币、合约、钱包、链上风险或一般加密问题。默认简明回答，需细节可再问。"
}

# --- маршруты ---
@app.route("/", methods=["GET"])
def root():
    return "Bot is running"

@app.route("/start", methods=["GET"])
def get_start():
    # Быстрый способ проверить локаль приветствия
    lang = request.args.get("lang", "en")
    return WELCOME.get(lang, WELCOME["en"])

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or data.get("edited_message")) or {}

    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text")

    if not (chat and text):
        return "ok"

    # /start -> короткое приветствие на языке пользователя
    if text.strip().lower().startswith("/start"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=WELCOME.get(lang, WELCOME["en"]))
        return "ok"

    lang = detect_lang(text)

    try:
        resp = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": text},
            ],
            temperature=0.7,
        )
        reply = (resp.choices[0].message.content or "").strip()
        # fallback на случай пустого ответа
        if not reply:
            reply = "Sorry, I couldn’t generate a reply. Try rephrasing." if lang == "en" else \
                    "Извини, не получилось сгенерировать ответ. Попробуй переформулировать." if lang == "ru" else \
                    "لم أتمكن من توليد رد. حاول إعادة الصياغة." if lang == "ar" else \
                    "抱歉，我没能生成回答，请尝试换种说法。"
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
