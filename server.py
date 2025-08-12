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

# --- very simple language detector (by alphabet) ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip()
    # cyrillic?
    if any("\u0400" <= ch <= "\u04FF" for ch in t):
        return "ru"
    # arabic?
    if any("\u0600" <= ch <= "\u06FF" for ch in t):
        return "ar"
    # chinese/japanese?
    if any("\u4e00" <= ch <= "\u9fff" for ch in t):
        return "zh"
    # spanish quick hint
    if any(ch in "¿¡ñáéíóúÑÁÉÍÓÚ" for ch in t):
        return "es"
    return "en"

# --- system prompt (multi‑lingual) ---
SYSTEM_PROMPT = {
    "en": (
        "You are CryptoGuard, a Web3 assistant. Be concise and safe.\n"
        "Core skills:\n"
        "• Token quick‑checks: contract, audit/kyc links, socials (Twitter/X, Discord, Telegram), "
        "liquidity/holders concentration and common red flags.\n"
        "• Site reputation checks (basic): WHOIS age, presence of audits/KYC, obvious scams/typosquatting.\n"
        "• Explain risks and give next steps. If data is missing, say so and suggest official sources.\n"
        "Language policy: reply in the user's language."
    ),
    "ru": (
        "Ты CryptoGuard — ассистент по Web3. Отвечай кратко и безопасно.\n"
        "Навыки:\n"
        "• Быстрые проверки токенов: контракт, ссылки на аудит/KYC, соцсети (Twitter/X, Discord, Telegram), "
        "ликвидность/концентрация холдеров и типичные красные флаги.\n"
        "• Базовая проверка сайтов: возраст домена (WHOIS), наличие аудитов/KYC, явные признаки скама/опечатки.\n"
        "• Объясняй риски и давай дальнейшие шаги. Если данных нет — так и говори, предлагай официальные источники.\n"
        "Политика языка: отвечай на языке пользователя."
    ),
    "es": (
        "Eres CryptoGuard, asistente Web3. Sé breve y seguro. "
        "Responde en el idioma del usuario."
    ),
    "zh": (
        "你是 CryptoGuard（Web3 助手）。简洁、稳妥，并用用户的语言回答。"
    ),
    "ar": (
        "أنت CryptoGuard، مساعد Web3. كن موجزًا وآمنًا وردّ بلغة المستخدم."
    ),
}

WELCOME = {
    "en": (
        "Hi! I’m CryptoGuard. I can analyze tokens and websites (basic Web3 checks), "
        "spot common red flags, and explain risks. Ask me anything."
    ),
    "ru": (
        "Привет! Я CryptoGuard. Могу делать базовую проверку токенов и сайтов (Web3), "
        "указывать типичные риски и «красные флаги». Спросите что угодно."
    ),
    "es": "¡Hola! Soy CryptoGuard. Puedo hacer comprobaciones básicas Web3.",
    "zh": "你好！我是 CryptoGuard。可做基础的 Web3 检查与风险提示。",
    "ar": "مرحبًا! أنا CryptoGuard. أُجري فحوصات Web3 الأساسية وأوضح المخاطر."
}

# --- routes ---
@app.route("/", methods=["GET"])
def root():
    # простая «живая» страница
    return WELCOME.get("en")

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text")

    if not (chat and text):
        return "ok"

    lang = detect_lang(text)
    sys_prompt = SYSTEM_PROMPT.get(lang, SYSTEM_PROMPT["en"])

    # формируем сообщения для LLM
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user",   "content": text},
    ]

    try:
        resp = client.chat.completions.create(
            model="llama-3.1-70b-versatile",   # модель Groq
            messages=messages,
            temperature=0.4,
        )
        reply = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        reply = f"Error: {e}"

    if not reply:
        reply = "…"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"
