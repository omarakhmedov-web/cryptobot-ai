import os
from flask import Flask, request
import telegram
from openai import OpenAI

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
PORT           = int(os.environ.get("PORT", 10000))

# Telegram bot
bot = telegram.Bot(token=TELEGRAM_TOKEN)

# OpenAI client, но на Groq
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=GROQ_API_KEY,
)

# --- очень простой детектор языка по алфавиту ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip().lower()
    if any("а" <= ch <= "я" or ch == "ё" for ch in t):
        return "ru"
    if any("א" <= ch <= "ת" for ch in t):  # иврит
        return "he"
    if any("京" <= ch <= "龯" for ch in t) or any("一" <= ch <= "龯" for ch in t):
        return "zh"
    return "en"

SYSTEM_PROMPT = {
    "en": (
        "You are CryptoGuard, a Web3 assistant. Be concise. "
        "Capabilities: token/project checks (website, X/Twitter, Discord), team transparency, audits, on-chain basics, "
        "risk flags, DEX/liquidity basics. If the user sends a token CA, note it's not verified by you. "
        "Reply in the user's language."
    ),
    "ru": (
        "Ты CryptoGuard — ассистент по Web3. Отвечай кратко. "
        "Умеешь: проверять токены/проекты (сайт, X/Twitter, Discord), прозрачность команды, аудиты, базовую ончейн-аналитику, "
        "риски/красные флаги, основы DEX/ликвидности. Если прислали контракт токена — отметь, что ты его не верифицируешь. "
        "Отвечай на языке пользователя."
    ),
    "he": "את/ה CryptoGuard עוזר Web3. לענות בקצרה ובשפת המשתמש. ...",
    "zh": "你是CryptoGuard，一名Web3助手。请简洁并用用户的语言回答。 ..."
}

WELCOME = {
    "en": "Hi! I’m CryptoGuard. Ask me to vet a token/website or explain a Web3 topic.",
    "ru": "Привет! Я CryptoGuard. Могу помочь проверить токен/сайт или объяснить тему из Web3.",
    "he": "היי! כאן CryptoGuard. אפשר לבקש בדיקת טוקן/אתר או הסבר בנושא Web3.",
    "zh": "你好！我是 CryptoGuard。可以让我帮你检查代币/网站，或解释 Web3 话题。"
}

# --- Routes ---
@app.route("/")
def root():
    return "bot is running"

@app.route("/getMe")
def get_me():
    return WELCOME.get(detect_lang(request.args.get("l", "")),"en")

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg  = data.get("message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text") or ""

    if not (chat and text):
        return "ok"

    # /start -> приветствие
    if text.strip().lower().startswith("/start"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=WELCOME.get(lang, WELCOME["en"]))
        return "ok"

    lang = detect_lang(text)
    system = SYSTEM_PROMPT.get(lang, SYSTEM_PROMPT["en"])

    try:
        resp = client.chat.completions.create(
            # на Groq лучше всего сейчас модель llama-3.1-70b
            model="llama-3.1-70b-versatile",
            temperature=0.4,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": text},
            ],
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = "Sorry, I couldn't generate a reply."
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"
