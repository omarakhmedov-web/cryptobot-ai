import os
from flask import Flask, request
from telegram import Bot
from groq import Groq

app = Flask(__name__)

# ==== ENV ====
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
PORT           = int(os.environ.get("PORT", 10000))

# ==== CLIENTS (ВАЖНО: без proxies, без session) ====
bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)

# ---- очень простой детектор языка (по алфавиту) ----
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip().lower()
    # кириллица
    if any('а' <= ch <= 'я' or ch == 'ё' for ch in t):
        return "ru"
    # арабская вязь
    if any('\u0600' <= ch <= '\u06FF' for ch in t):
        return "ar"
    # китайские иероглифы
    if any('\u4e00' <= ch <= '\u9fff' for ch in t):
        return "zh"
    # турецкие диакритики
    if any(ch in "çğıöşü" for ch in t):
        return "tr"
    return "en"

# ==== ПРИВЕТСТВИЕ ====
WELCOME = {
    "en": (
        "👋 Hi! I'm <b>CryptoGuard</b>.\n\n"
        "I can: \n"
        "• sanity-check smart contracts & tokens (read-only)\n"
        "• scan socials (Twitter/X, Discord) & GitHub activity\n"
        "• flag common Web3 red flags (honeypot signs, fake mints, admin risks)\n"
        "• explain risks in plain language and link to sources\n\n"
        "Send a token address/CA, website or question."
    ),
    "ru": (
        "👋 Привет! Я <b>CryptoGuard</b>.\n\n"
        "Что умею:\n"
        "• делать базовую проверку токенов/контрактов (только чтение)\n"
        "• смотреть соцсети (Twitter/X, Discord) и активность GitHub\n"
        "• отмечать типичные Web3-риски (honeypot, фейковые минта/админ-риски)\n"
        "• объяснять понятным языком и давать источники\n\n"
        "Пришли адрес токена/CA, сайт или вопрос."
    ),
    "tr": (
        "👋 Merhaba! Ben <b>CryptoGuard</b>.\n\n"
        "Neler yaparım:\n"
        "• token/kontrat için temel kontroller (salt okunur)\n"
        "• sosyal ağ taraması (Twitter/X, Discord), GitHub aktivitesi\n"
        "• yaygın Web3 risklerini işaretleme\n"
        "• açık dille riskleri anlatma ve kaynaklar\n\n"
        "Bir token adresi/CA, web sitesi veya sorunuzu gönderin."
    ),
    "ar": "👋 أهلاً! أنا <b>CryptoGuard</b>… أرسل عنوان العقد/الموقع أو سؤالك.",
    "zh": "👋 你好！我是 <b>CryptoGuard</b>。发送合约地址/网站或问题即可开始。",
}

def get_welcome(lang: str) -> str:
    return WELCOME.get(lang, WELCOME["en"])

# ==== СИСТЕМНЫЙ ПРОМПТ (мультиязык + Web3 компетенции) ====
SYSTEM_PROMPT = (
    "You are CryptoGuard, a Web3 risk assistant. "
    "Capabilities: liquidity/volume sanity-checks; social checks (Twitter/X, Discord); "
    "GitHub activity; contract/read-only audits; common Web3 red-flags. "
    "You DO NOT run transactions or give financial advice. "
    "When the user writes in some language, ALWAYS answer in that language. "
    "Be concise unless asked for details. If user sends a link or CA address, "
    "explain potential risks and what to verify (owner privileges, mint, taxes, liquidity locks), "
    "and suggest public sources (Etherscan/BscScan/Solscan, DexScreener, DEXTools, DeFiLlama, RugDoc)."
)

# ==== ROUTES ====
@app.route("/", methods=["GET"])
def root():
    return "ok"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get("message") or data.get("edited_message") or data.get("channel_post")
    if not msg:
        return "ok"

    chat_id = msg["chat"]["id"]
    user_lang = (msg.get("from") or {}).get("language_code", "en")[:2]
    text = (msg.get("text") or msg.get("caption") or "").strip()

    # /start
    if text.lower().startswith("/start"):
        lang = detect_lang(text) or (user_lang or "en")
        bot.send_message(chat_id=chat_id, text=get_welcome(lang), parse_mode="HTML")
        return "ok"

    # Определим язык из текста, если пусто — из профиля
    lang = detect_lang(text) or (user_lang or "en")

    # Подготавливаем сообщения для LLM
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": f"[language:{lang}] {text}"}
    ]

    try:
        resp = client.chat.completions.create(
            model="llama-3.1-70b-versatile",  # актуальная крупная модель Groq
            messages=messages,
            temperature=0.4,
            max_tokens=900,
            top_p=1.0,
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = "⚠️ Empty response. Try asking again."
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat_id, text=reply, parse_mode=None)
    return "ok"

if __name__ == "__main__":
    # локальный запуск (на Render запустит gunicorn)
    app.run(host="0.0.0.0", port=PORT, debug=False)
