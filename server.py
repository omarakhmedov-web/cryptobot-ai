# server.py
import os
import requests
from flask import Flask, request
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY = os.environ["GROQ_API_KEY"]
PORT = int(os.environ.get("PORT", 10000))

# Groq-клиент (ВАЖНО: без proxies)
client = Groq(api_key=GROQ_API_KEY)

# --- очень простой детектор языка (по алфавиту) ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    s = text.strip()
    # кириллица
    if any("а" <= ch <= "я" or "А" <= ch <= "Я" for ch in s):
        return "ru"
    # латиница
    if any("a" <= ch.lower() <= "z" for ch in s):
        return "en"
    return "en"

# --- системный промпт: кратко и по делу, умеет web3/крипто-проверки ---
SYSTEM_PROMPT = (
    "You are CryptoGuard, a helpful assistant for quick due diligence in crypto/Web3. "
    "Be concise (max 8–10 sentences unless user asks for details). "
    "If asked about tokens/projects/contracts, outline public checks: website, docs, GitHub, "
    "socials (Twitter/X, Discord, Telegram), explorer (holders, supply, deployer history), "
    "liquidity/locks, audits/KYC (if any), team transparency, contract renounce status, top holders, "
    "common Web3 red flags. Avoid financial advice; provide educational info only. "
    "Always reply in the user's language."
)

WELCOME = {
    "en": (
        "Hi! I’m CryptoGuard. I can analyze tokens and Web3 projects at a high level, "
        "spot common red flags, and explain next steps. Ask me anything."
    ),
    "ru": (
        "Привет! Я CryptoGuard. Помогу проверить токены и Web3‑проекты на базовом уровне, "
        "подсказать типичные риски и следующие шаги. Спрашивайте что угодно."
    ),
    "tr": (
        "Selam! Ben CryptoGuard. Tokenleri ve Web3 projelerini üst düzeyde analiz edebilirim, "
        "yaygın riskleri gösterebilirim ve sonraki adımları açıklayabilirim."
    ),
}

def welcome_for(text: str) -> str:
    lang = detect_lang(text)
    return WELCOME.get(lang, WELCOME["en"])

# --- routes ---
@app.route("/", methods=["GET"])
def root():
    return "Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or data.get("channel_post") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text", "")

    if not chat:
        return "ok"

    # ответ на /start – локализованное приветствие
    if text and text.strip().lower().startswith("/start"):
        reply = welcome_for(text)
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": chat, "text": reply},
            timeout=10,
        )
        return "ok"

    # обычные сообщения
    if not text:
        return "ok"

    user_lang = detect_lang(text)
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            temperature=0.4,
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = "Sorry, I couldn’t generate a reply." if user_lang == "en" else "Извините, не удалось сформировать ответ."
    except Exception as e:
        reply = f"Error: {e}"

    requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        json={"chat_id": chat, "text": reply},
        timeout=10,
    )
    return "ok"
