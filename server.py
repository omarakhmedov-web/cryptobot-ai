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
client = Groq(api_key=GROQ_API_KEY)

# --- очень простой детектор языка по алфавиту ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip().lower()
    # немного хардкода: латиница/кириллица/араб/кит/яп/кор
    if any("а" <= ch <= "я" or "ё" == ch for ch in t):
        return "ru"
    if any("\u0600" <= ch <= "\u06FF" for ch in t):
        return "ar"
    if any("\u4e00" <= ch <= "\u9fff" for ch in t):
        return "zh"
    if any("\u3040" <= ch <= "\u30ff" for ch in t):
        return "ja"
    if any("\uac00" <= ch <= "\ud7af" for ch in t):
        return "ko"
    return "en"

# --- SYSTEM prompt: web3 помощь + отвечать на языке пользователя ---
SYSTEM_PROMPT = (
    "You are CryptoGuard, a helpful Web3 assistant.\n"
    "- Capabilities: basic token and website due‑diligence, social checks (Twitter/X, Discord), "
    "reading project docs/whitepapers (if pasted), wallet/tx reasoning at a high level.\n"
    "- Safety: no financial advice; warn about common Web3 red flags; encourage user to verify.\n"
    "- Language policy: detect the user's language and reply in that language."
)

WELCOME = {
    "en": (
        "Hi! I’m CryptoGuard.\n"
        "I can help with quick Web3 sanity checks (tokens, sites, docs) and common red flags.\n"
        "Send a question or paste text/links. /help for tips."
    ),
    "ru": (
        "Привет! Я CryptoGuard.\n"
        "Помогу с быстрыми проверками в Web3 (токены, сайты, документы) и подскажу типовые риски.\n"
        "Пиши вопрос или пришли текст/ссылки. Команда /help — для подсказок."
    ),
    "ar": "مرحبًا! أنا CryptoGuard. أساعدك في فحص Web3 السريع والتنبيهات الشائعة. أرسل سؤالك أو رابطًا.",
    "zh": "你好！我是 CryptoGuard。可帮助快速检查 Web3（代币、网站、文档）并提醒常见风险。发送问题或粘贴链接。",
    "ja": "こんにちは、CryptoGuardです。Web3の簡易チェックやよくあるリスクの注意喚起を手伝います。質問やリンクを送ってください。",
    "ko": "안녕하세요! CryptoGuard 입니다. Web3 빠른 점검과 일반적 위험 경고를 도와드려요. 질문이나 링크를 보내주세요."
}

def get_welcome(lang: str) -> str:
    return WELCOME.get(lang, WELCOME["en"])

# --- Routes ---
@app.route("/", methods=["GET"])
def root():
    return "Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg  = data.get("message") or data.get("edited_message") or {}

    chat = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or "").strip()

    if not chat:
        return "ok"

    # /start и /help — локализованные ответы
    if text.lower().startswith("/start") or text.lower().startswith("/help"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=get_welcome(lang))
        return "ok"

    if not text:
        bot.send_message(chat_id=chat, text=get_welcome("en"))
        return "ok"

    # язык по сообщению пользователя
    lang = detect_lang(text)

    try:
        resp = client.chat.completions.create(
            model="llama-3.1-70b-versatile",  # стабильная модель Groq
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": text},
            ],
            temperature=0.3,
        )
        reply = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply or get_welcome(lang))
    return "ok"
