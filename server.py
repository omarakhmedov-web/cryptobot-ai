import os
from flask import Flask, request, jsonify
import telegram  # python-telegram-bot v13.x
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
PORT           = int(os.environ.get("PORT", 10000))

bot    = telegram.Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)   # без proxies и лишних параметров

# --- очень простой детектор языка (по алфавиту) ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = (text or "").lower()
    # кириллица
    if any("а" <= ch <= "я" for ch in t):
        return "ru"
    # арабский
    if any("\u0600" <= ch <= "\u06FF" for ch in t):
        return "ar"
    # китайский/японский/корейский
    if any("\u4e00" <= ord(ch) <= 0x9FFF for ch in t) or any("\u3040" <= ord(ch) <= 0x30FF for ch in t):
        return "zh"
    # турецкий
    if any(ch in "çğıöşü" for ch in t):
        return "tr"
    # испанский
    if any(ch in "ñáéíóúü" for ch in t):
        return "es"
    # fallback
    return "en"

# --- приветствие на нескольких языках ---
WELCOME = {
    "en": (
        "Hello! I'm CryptoGuard, your Web3 security assistant. I can:\n"
        "• Analyze token contracts and holders\n"
        "• Check deployer history, socials (X/TG/Discord), docs & audits\n"
        "• Flag common Web3 red flags (mint/owner powers, honeypots, fees, trading locks)\n"
        "• Summarize on-chain activity and give risk recommendations\n\n"
        "Ask me anything or paste a token/tx/address/website."
    ),
    "ru": (
        "Привет! Я CryptoGuard — помощник по безопасности Web3. Я умею:\n"
        "• Анализировать контракты токенов и холдеров\n"
        "• Проверять историю деплойера, соцсети (X/TG/Discord), документацию и аудиты\n"
        "• Выявлять частые риски Web3 (права владельца/минта, honeypot, комиссии, блокировки)\n"
        "• Резюмировать ончейн-активность и давать рекомендации по рискам\n\n"
        "Задайте вопрос или пришлите токен/транзакцию/адрес/сайт."
    ),
    "es": "¡Hola! Soy CryptoGuard… (puedo analizar contratos, holders, redes sociales, auditorías y emitir alertas de riesgo).",
    "tr": "Merhaba! Ben CryptoGuard… (token sözleşmeleri, sahipler, sosyal hesaplar, risk işaretleri vb.).",
    "ar": "مرحبًا! أنا CryptoGuard… (تحليل العقود والحوامل، فحص التاريخ، الإبلاغ عن المخاطر).",
    "zh": "你好！我是 CryptoGuard…（可分析合约与持币、检查社媒与审计、提示常见风险）。",
}

# --- SYSTEM prompt: Web3/security и мульти-язычность ---
SYSTEM_PROMPT = """
You are CryptoGuard, a rigorous Web3 security assistant.
Capabilities: token-contract static review, deployer/holder analysis, on-chain tx reading,
social/docs/audit checks (descriptive, not browsing), risk flags (honeypot, mint/owner powers,
trading pause, blacklist/whitelist, high taxes/fees, proxy/upgradeability), and clear next steps.

Language policy: ALWAYS answer in the user's language. If user is mixed, prefer English.
Be concise, structured, and add small bullet points. If user sends an address/hash/url, infer intent.
If you are unsure, ask a brief clarifying question.
"""

def welcome_for(lang: str) -> str:
    return WELCOME.get(lang, WELCOME["en"])

# ---- routes ----
@app.route("/", methods=["GET"])
def health():
    return "OK", 200

@app.route("/set_webhook", methods=["GET"])
def set_webhook():
    # Render сам подставит правильный https-домен сервиса
    webhook_url = request.args.get("url")
    if not webhook_url:
        return jsonify({"ok": False, "error": "pass ?url=https://<your-app>.onrender.com/webhook"}), 400
    bot.set_webhook(webhook_url)
    return jsonify({"ok": True, "url": webhook_url})

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg  = (data.get("message") or data.get("edited_message") or {})
    chat = msg.get("chat", {})
    text = (msg.get("text") or "").strip()

    # /start -> приветствие на языке пользователя
    if text.lower().startswith("/start"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat["id"], text=welcome_for(lang))
        return "ok"

    lang = detect_lang(text) or "en"

    # соберём сообщение для модели
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",    "content": f"[language={lang}] {text}"},
    ]

    try:
        resp = client.chat.completions.create(
            model="llama-3.1-70b-instruct",   # актуальная мощная модель
            messages=messages,
            temperature=0.3,
            max_tokens=800,
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = "Sorry, I couldn't generate a reply."
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat.get("id"), text=reply)
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
