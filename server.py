import os
import re
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

MODEL = "llama-3.1-8b-instant"  # стабильная и быстрая у Groq

# --- простой детектор языка ---
def detect_lang(text: str) -> str:
    if not text: return "en"
    t = text.lower()
    if any("а" <= ch <= "я" or ch == "ё" for ch in t): return "ru"
    if any("\u0600" <= ch <= "\u06FF" for ch in t):   return "ar"
    if any("\u4e00" <= ch <= "\u9fff" for ch in t):    return "zh"
    return "en"

# --- тексты / старт и /help ---
WELCOME = {
    "en": "Hi! I’m CryptoGuard. I do quick Web3 due-diligence, red-flags and safety tips. Use /help to see commands.",
    "ru": "Привет! Я CryptoGuard. Делаю экспресс-проверки Web3, подсвечиваю риски и даю советы по безопасности. Команда /help — список команд."
}
HELP = {
    "en": (
        "Available commands:\n"
        "• /help — this message\n"
        "• /check <contract_or_url> — quick checklist for a token (EVM 0x...) or a website\n\n"
        "Examples:\n"
        "/check 0x0000000000000000000000000000000000000000\n"
        "/check https://example.com\n\n"
        "Tip: I also answer free-form questions and keep replies concise by default."
    ),
    "ru": (
        "Доступные команды:\n"
        "• /help — это сообщение\n"
        "• /check <адрес_или_url> — экспресс-чеклист для токена (EVM 0x...) или сайта\n\n"
        "Примеры:\n"
        "/check 0x0000000000000000000000000000000000000000\n"
        "/check https://example.com\n\n"
        "Подсказка: Я отвечаю и на свободные вопросы; по умолчанию — кратко."
    ),
}

SYSTEM_PROMPT = {
    "en": (
        "You are CryptoGuard, a Web3 safety assistant. "
        "Capabilities: token/project checklists (docs, team, audits, vesting), socials sanity checks (X/Twitter, Discord, Telegram), "
        "on-chain 'how-to-check' steps (holders, deployer history, top holders, liquidity locks, renounce status), "
        "scam patterns (honeypot, fake airdrops, approval/security hygiene). "
        "No direct on-chain access; provide clear, actionable steps. Be concise."
    ),
    "ru": (
        "Ты CryptoGuard — ассистент по безопасности Web3. "
        "Возможности: чек-листы проверки токенов/проектов (доки, команда, аудит, вестинг), sanity-проверки соцсетей (X/Twitter, Discord, Telegram), "
        "пошаговые ончейн-проверки (холдеры, история деплойера, крупнейшие кошельки, локи ликвидности, статус renounce), "
        "схемы скама (honeypot, фейковые airdrop’ы, риски approvals/подписей). "
        "Прямого ончейн-доступа нет; давай ясные, практичные шаги. Пиши кратко."
    ),
}

# --- утилиты для /check ---
EVM_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
URL_RE = re.compile(r"^(https?://)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(/.*)?$")

def build_check_response(target: str, lang: str) -> str:
    is_evm = bool(EVM_RE.match(target))
    is_url = bool(URL_RE.match(target))
    if lang not in ("en", "ru"):
        lang = "en"

    if not (is_evm or is_url):
        return ("Invalid input. Send an EVM contract (0x...) or a URL."
                if lang == "en" else
                "Неверный ввод. Пришлите EVM-адрес контракта (0x...) или URL сайта.")

    if is_evm:
        return (
            f"{'Quick token checklist' if lang=='en' else 'Экспресс-чеклист токена'}: {target}\n"
            f"1) {'Explorer' if lang=='en' else 'Обозреватель'}: verify contract source, mint/burn/blacklist functions, trading limits.\n"
            f"2) Holders: top-10 concentration, team wallets; sudden spikes.\n"
            f"3) Liquidity: locks, LP ownership, renounce status.\n"
            f"4) Deployer: prior contracts, unusual transfers.\n"
            f"5) Docs & socials: website, whitepaper, X/Discord/Telegram; fake engagement signals.\n"
            f"6) Audits/KYC (if any); vesting/allocations clarity.\n"
            f"7) Test small tx; avoid unlimited approvals.\n"
        ) if lang == "en" else (
            f"Экспресс-чеклист токена: {target}\n"
            f"1) Обозреватель: исходник контракта, функции mint/burn/blacklist, лимиты.\n"
            f"2) Холдеры: концентрация топ-10, кошельки команды; резкие всплески.\n"
            f"3) Ликвидность: локи, владелец LP, статус renounce.\n"
            f"4) Деплойер: прошлые контракты, нетипичные переводы.\n"
            f"5) Документация и соцсети: сайт, whitepaper, X/Discord/Telegram; признаки накруток.\n"
            f"6) Аудит/KYC (если есть); прозрачность вестинга/распределения.\n"
            f"7) Тестируйте малой суммой; избегайте безлимитных approvals.\n"
        )
    else:  # is_url
        clean = target if target.startswith("http") else "https://" + target
        return (
            f"Website quick checks: {clean}\n"
            f"1) Domain age/WHOIS; mismatch between brand & registrant.\n"
            f"2) TLS valid; no mixed-content; redirects legit.\n"
            f"3) Official links consistency across docs/X/Discord.\n"
            f"4) Team/audit pages verifiable; no stock photos.\n"
            f"5) Wallet connect flows: spoof domains, fake signatures.\n"
            f"6) Airdrop/claim pages: require no seed/private key (ever!).\n"
            f"7) Use reputable scanners; cross-check in communities.\n"
        ) if lang == "en" else (
            f"Быстрые проверки сайта: {clean}\n"
            f"1) Возраст домена/WHOIS; нет ли несоответствий бренду.\n"
            f"2) Валидный TLS; без смешанного контента; корректные редиректы.\n"
            f"3) Согласованность «официальных ссылок» в доках/X/Discord.\n"
            f"4) Команда/аудит проверяемы; не стоковые фото.\n"
            f"5) Wallet-подключения: фишинговые домены/подписи.\n"
            f"6) Airdrop/claim: никогда не требуют сид/приватный ключ.\n"
            f"7) Пользуйтесь сканерами; перепроверяйте в сообществах.\n"
        )

# --- маршруты ---
@app.route("/", methods=["GET"])
def health():
    return "✅ CryptoGuard is running."

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg  = data.get("message") or data.get("edited_message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or "").strip()

    if not chat:
        return "ok"

    # /start и /help
    if text.lower().startswith("/start"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=WELCOME.get(lang, WELCOME["en"]))
        return "ok"

    if text.lower().startswith("/help"):
        lang = detect_lang(text)
        bot.send_message(chat_id=chat, text=HELP.get(lang, HELP["en"]))
        return "ok"

    # /check <target>
    if text.lower().startswith("/check"):
        lang = detect_lang(text)
        parts = text.split(maxsplit=1)
        if len(parts) == 1:
            msg_txt = "Send: /check <contract_or_url>" if lang == "en" else "Пришлите: /check <адрес_или_URL>"
            bot.send_message(chat_id=chat, text=msg_txt)
            return "ok"
        target = parts[1].strip()
        bot.send_message(chat_id=chat, text=build_check_response(target, lang))
        return "ok"

    # Обычная генерация через LLM
    lang = detect_lang(text)
    system = SYSTEM_PROMPT.get(lang, SYSTEM_PROMPT["en"])

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            temperature=0.4,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": text},
            ],
        )
        reply = (resp.choices[0].message.content or "").strip()
        if not reply:
            reply = "Sorry, I couldn’t generate an answer." if lang == "en" else "Не удалось сформировать ответ."
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"
