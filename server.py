# server.py
import os
import json
import re
import requests
from flask import Flask, request, jsonify
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY = os.environ["GROQ_API_KEY"]
PORT = int(os.environ.get("PORT", 10000))

TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

# --- ЯЗЫКИ / ТЕКСТЫ ---

WELCOME = {
    "en": (
        "Hello! I'm *CryptoGuard*, your Web3 security assistant.\n\n"
        "I can:\n"
        "• Review token contracts (ownership, mint, fee, blacklist, honeypot, proxy, upgradability)\n"
        "• Analyze deployer history & socials (Twitter/X, Discord, Telegram)\n"
        "• Check liquidity locks, top holders, transfers & anomalies\n"
        "• Explain risks and suggest safe next steps\n\n"
        "_Send a contract address, token symbol, or ask anything about on-chain safety._"
    ),
    "ru": (
        "Привет! Я *CryptoGuard* — ваш помощник по безопасности в Web3.\n\n"
        "Я умею:\n"
        "• Проверять смарт-контракты токенов (владение, mint, комиссии, blacklist, honeypot, proxy, апгрейды)\n"
        "• Анализировать историю деплойера и соцсети (X/Twitter, Discord, Telegram)\n"
        "• Смотреть локи ликвидности, крупных держателей, переводы и аномалии\n"
        "• Объяснять риски и рекомендовать безопасные дальнейшие действия\n\n"
        "_Пришлите адрес контракта, символ токена или любой вопрос про ончейн-безопасность._"
    ),
    "es": (
        "¡Hola! Soy *CryptoGuard*, tu asistente de seguridad Web3.\n\n"
        "Puedo:\n"
        "• Auditar contratos de tokens (propiedad, mint, fee, blacklist, honeypot, proxy, upgradability)\n"
        "• Analizar historial del deployer y redes sociales (X/Twitter, Discord, Telegram)\n"
        "• Revisar locks de liquidez, mayores holders, transferencias y anomalías\n"
        "• Explicar riesgos y sugerir próximos pasos seguros\n\n"
        "_Envíame una dirección de contrato, símbolo del token o cualquier duda de seguridad on-chain._"
    ),
    "tr": (
        "Merhaba! Ben *CryptoGuard*, Web3 güvenlik asistanınız.\n\n"
        "Şunları yaparım:\n"
        "• Token sözleşmesi denetimi (sahiplik, mint, ücret, blacklist, honeypot, proxy, yükseltilebilirlik)\n"
        "• Dağıtıcı geçmişi ve sosyal hesaplar (X/Twitter, Discord, Telegram)\n"
        "• Likidite kilitleri, büyük tutucular, transferler ve anormallikler\n"
        "• Riskleri açıklar, güvenli sonraki adımlar öneririm\n\n"
        "_Sözleşme adresi, token sembolü gönderin ya da zincir üzeri güvenlikle ilgili soru sorun._"
    ),
    "ar": (
        "مرحباً! أنا *CryptoGuard*، مساعدك لأمان Web3.\n\n"
        "أستطيع:\n"
        "• تدقيق عقود التوكن (الملكية، السك، الرسوم، القائمة السوداء، honeypot، الوكيل، قابلية الترقية)\n"
        "• تحليل سجل الناشر وحسابات التواصل (X/Twitter، ديسكورد، تيليجرام)\n"
        "• فحص قفل السيولة، كبار الحائزين، التحويلات والشواذ\n"
        "• شرح المخاطر واقتراح خطوات آمنة لاحقاً\n\n"
        "_أرسل عنوان عقد، رمز توكن، أو أي سؤال حول أمان السلسلة._"
    ),
    "zh": (
        "你好！我是 *CryptoGuard*，你的 Web3 安全助手。\n\n"
        "我可以：\n"
        "• 审查代币合约（所有权、铸币、手续费、黑名单、诱捕池、代理、可升级性）\n"
        "• 分析部署者历史与社媒（X/Twitter、Discord、Telegram）\n"
        "• 检查流动性锁仓、大额持仓、转账与异常\n"
        "• 解释风险并给出安全建议\n\n"
        "_发送合约地址、代币符号，或直接提问链上安全问题。_"
    ),
}

HELP_CAPS = {
    "en": (
        "*What I can do (Web3 safety):*\n"
        "• Contract audit heuristics: ownership, mint, tax/fee, blacklist, honeypot, pausability, proxy, upgradeability\n"
        "• Deployer history & social signals (Twitter/X, Discord, Telegram)\n"
        "• Liquidity/LP: locks, burned LP, pool health, MEV risk\n"
        "• Holders & transfers: top holders, distribution skew, suspicious patterns\n"
        "• Risk explanation + safe next steps\n\n"
        "_Tip: send a contract address to start._"
    ),
    "ru": (
        "*Что я умею (безопасность Web3):*\n"
        "• Евристики аудита контрактов: владение, mint, налог/fee, blacklist, honeypot, пауза, proxy, апгрейды\n"
        "• История деплойера и сигналы соцсетей (X/Twitter, Discord, Telegram)\n"
        "• Ликвидность/LP: локи, сожжённый LP, здоровье пула, риск MEV\n"
        "• Держатели и переводы: топ-холдеры, перекос распределения, подозрительные паттерны\n"
        "• Объяснение рисков + безопасные шаги\n\n"
        "_Подсказка: пришлите адрес контракта для старта._"
    ),
}

SYSTEM_PROMPT_TEMPLATE = (
    "You are CryptoGuard, a pragmatic Web3 security assistant. "
    "Answer *in language code: {lang}*. "
    "Be concise, clear, and actionable. "
    "When user provides a token/contract, outline key risk checks:\n"
    "• Ownership, mint, fees/tax, blacklist/honeypot/pausable\n"
    "• Proxy/upgradability; deployer history & socials\n"
    "• Liquidity locks, top holders, transfer anomalies\n"
    "If data is missing, say what you *need* to proceed. "
    "Never promise on-chain actions. No financial advice."
)

# --- ПРОСТОЙ ДЕТЕКТОР ЯЗЫКА (исправлено) ---
def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = (text or "").lower()

    # кириллица
    if any(0x0430 <= ord(ch) <= 0x044F for ch in t):
        return "ru"
    # арабский
    if any(0x0600 <= ord(ch) <= 0x06FF for ch in t):
        return "ar"
    # китайский / японский
    if any(0x4E00 <= ord(ch) <= 0x9FFF for ch in t) or any(0x3040 <= ord(ch) <= 0x30FF for ch in t):
        return "zh"
    # турецкий
    if any(ch in "çğıöşü" for ch in t):
        return "tr"
    # испанский
    if any(ch in "ñáéíóúü" for ch in t):
        return "es"
    # по умолчанию
    return "en"

# --- КЛИЕНТ GROQ ---
client = Groq(api_key=GROQ_API_KEY)

def groq_reply(user_text: str, lang: str) -> str:
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.2,
            max_tokens=800,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_TEMPLATE.format(lang=lang)},
                {"role": "user", "content": user_text},
            ],
        )
        msg = resp.choices[0].message.content or ""
        # Телеграм ограничение 4096
        return msg[:4096]
    except Exception as e:
        if lang == "ru":
            return f"Ошибка ответа модели: {e}"
        return f"Model error: {e}"

# --- ВСПОМОГАТЕЛЬНОЕ ОТПРАВЛЕНИЕ В ТГ ---
def tg_send(chat_id: int, text: str, parse_mode: str = "Markdown"):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }
    try:
        requests.post(TELEGRAM_SEND_URL, json=payload, timeout=15)
    except Exception:
        pass

# --- ROUTES ---
@app.get("/")
def root():
    return jsonify(ok=True, service="cryptoguard", version="1.0")

@app.post("/webhook")
def webhook():
    update = request.get_json(silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text") or ""

    if not chat:
        return jsonify(ok=True)

    lang = detect_lang(text)

    # /start и помощь
    cmd = (text or "").strip().lower()
    if cmd in ("/start", "start", "/help"):
        tg_send(chat, WELCOME.get(lang, WELCOME["en"]))
        tg_send(chat, HELP_CAPS.get(lang, HELP_CAPS["en"]))
        return jsonify(ok=True)

    # Короткий хелп по ключевым словам
    if re.search(r"\b(help|помощ|справк|ayuda|yardım)\b", cmd):
        tg_send(chat, HELP_CAPS.get(lang, HELP_CAPS["en"]))
        return jsonify(ok=True)

    # Основной ответ модели на языке пользователя
    reply = groq_reply(text, lang)
    tg_send(chat, reply)
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
