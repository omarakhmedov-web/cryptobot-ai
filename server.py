# server.py
import os
import re
from flask import Flask, request
import telegram
from openai import OpenAI

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
PORT = int(os.environ.get("PORT", 10000))

# --- Clients ---
bot = telegram.Bot(token=TELEGRAM_TOKEN)
client = OpenAI(api_key=OPENAI_API_KEY)

# --- Helpers ---

def detect_lang(text: str) -> str:
    """
    Грубое локальное определение языка без внешних зависимостей.
    Возвращает ISO-код, который пойдёт в системный промпт.
    """
    t = text.strip()
    if not t:
        return "en"
    # Кириллица
    if any("\u0400" <= ch <= "\u04FF" for ch in t):
        return "ru"
    # Китайские иероглифы
    if any("\u4e00" <= ch <= "\u9fff" for ch in t):
        return "zh"
    # Арабская письменность
    if any("\u0600" <= ch <= "\u06FF" for ch in t):
        return "ar"
    # Испанский/итальянский/французский хак через буквы с диакритикой
    if re.search(r"[áéíóúñüàèìòùâêîôûç]", t.lower()):
        return "es"
    return "en"

SYSTEM_PROMPT = (
    "You are CryptoGuard — a Telegram assistant.\n"
    "Capabilities (Web3 & Safety):\n"
    "- Token/coin due diligence checklists: contract red flags (mint/pause/blacklist/upgradeability), "
    "holders distribution, liquidity/locks, audits, deployer history.\n"
    "- Website & social checks (Twitter/X, Discord, Zealy), team transparency, roadmap sanity.\n"
    "- Explain wallets, bridges, DeFi, L1/L2, gas, risks. Provide clear, actionable safety steps.\n"
    "- Never promise profits. Add risk reminders when user asks about investments.\n"
    "Language policy: Detect the user's language and reply in that language. "
    "Keep answers concise unless asked for details."
)

WELCOME = {
    "en": (
        "Hi! I’m CryptoGuard. I can analyze tokens and websites, spot common Web3 red flags, "
        "and explain DeFi in simple terms. Ask me anything. 🚀"
    ),
    "ru": (
        "Привет! Я CryptoGuard. Помогаю проверять токены и сайты, замечать типичные Web3-риски "
        "и простыми словами объясняю DeFi. Спрашивай что угодно. 🚀"
    ),
    "es": (
        "¡Hola! Soy CryptoGuard. Puedo analizar tokens y sitios, detectar riesgos comunes de Web3 "
        "y explicar DeFi de forma sencilla. Pregúntame lo que quieras. 🚀"
    ),
    "zh": "你好！我是 CryptoGuard。可以分析代币和网站，发现常见 Web3 风险，并用简单的话解释 DeFi。尽管来问。🚀",
    "ar": "مرحباً! أنا CryptoGuard. أستطيع تحليل التوكنات والمواقع، اكتشاف مخاطر Web3 الشائعة، وشرح DeFi ببساطة. اسألني أي شيء. 🚀",
}

def greet(lang: str) -> str:
    return WELCOME.get(lang, WELCOME["en"])

# --- Routes ---

@app.route("/")
def root():
    return "Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text") or ""

    if not chat:
        return "ok"

    # /start — короткое приветствие на языке пользователя
    if text.strip().lower() in ("/start", "start"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=greet(lang))
        return "ok"

    # Автоязык
    lang = detect_lang(text)

    messages = [
        {"role": "system", "content": f"{SYSTEM_PROMPT}\nUserLanguage: {lang}"},
        {"role": "user", "content": text},
    ]

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",  # можно заменить на другой, если нужно
            messages=messages,
            temperature=0.4,
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = greet(lang)
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"

if __name__ == "__main__":
    # локальный запуск (на Render используется gunicorn)
    app.run(host="0.0.0.0", port=PORT)
