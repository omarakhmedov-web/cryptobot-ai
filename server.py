import os
import re
import json
from typing import Dict

from flask import Flask, request
import telegram
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
GROQ_MODEL     = os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile")
PORT           = int(os.environ.get("PORT", 10000))

bot = telegram.Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)

# --- простейшее «запоминание» языка (сбрасывается при рестарте) ---
USER_LANG_PREF: Dict[int, str] = {}

# --- определение языка по алфавиту + подсказки по словам ---
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
ARABIC   = re.compile(r"[\u0600-\u06FF]")
TURKIC_HINTS = {"bir", "bu", "ne", "sən", "siz", "daha", "bəli", "yox"}  # az/uz/tr общие слова

def detect_lang(text: str) -> str:
    if not text:
        return "en"
    t = text.strip()
    if CYRILLIC.search(t):
        # грубо: если много «ө,ұ,қ,ғ,ү» → каз/кирг; упрощаем до ru для диалогов
        return "ru"
    if ARABIC.search(t):
        return "ar"
    lo = t.lower()
    if any(w in lo.split() for w in TURKIC_HINTS):
        return "az"  # условно; всё равно ответим в этом языке
    # упрощённые еврозоны
    if any(ch in lo for ch in "ñáéíóúü¡¿"):
        return "es"
    if any(ch in lo for ch in "çàâêîôûëïüœ"):
        return "fr"
    if any(ch in lo for ch in "äöüß"):
        return "de"
    if any(ch in lo for ch in "ãõç"):
        return "pt"
    if any(ch in lo for ch in "。？！，、；："):
        return "zh"
    if any(ch in lo for ch in "。！？〜"):
        return "ja"
    if any(ch in lo for ch in "가나다라마바사아자차카타파하"):
        return "ko"
    return "en"

# --- локализованные приветствия/подсказки ---
WELCOME = {
    "en": (
        "Hello! I'm **CryptoGuard**, your Web3 security assistant. "
        "Send me a token/contract/tx hash or project site, and I'll run checks "
        "and explain risks in clear terms. Type /help for features."
    ),
    "ru": (
        "Привет! Я **CryptoGuard** — ваш ассистент по безопасности Web3. "
        "Пришлите адрес токена/контракта/tx или сайт проекта — запущу проверки "
        "и по-человечески объясню риски. Команда /help — список возможностей."
    ),
    "es": "¡Hola! Soy **CryptoGuard**, tu asistente de seguridad Web3…",
    "fr": "Salut ! Je suis **CryptoGuard**, votre assistant sécurité Web3…",
    "de": "Hallo! Ich bin **CryptoGuard**, dein Web3-Sicherheitsassistent…",
    "pt": "Olá! Eu sou o **CryptoGuard**, seu assistente de segurança Web3…",
    "az": "Salam! Mən **CryptoGuard** — Web3 təhlükəsizlik köməkçinizəm…",
    "ar": "مرحبًا! أنا **CryptoGuard**، مساعدك لأمان الويب٣…",
    "zh": "你好！我是 **CryptoGuard**，你的 Web3 安全助手…",
    "ja": "こんにちは！**CryptoGuard**、Web3 セキュリティ助手です…",
    "ko": "안녕하세요! 저는 **CryptoGuard** 웹3 보안 도우미입니다…",
}

CAPABILITIES = {
    "en": (
        "I can:\n"
        "• sanity-check token contracts (ownership, mint/blacklist, fees)\n"
        "• scan socials/sites for red flags & impersonations\n"
        "• summarize on-chain activity and top holders\n"
        "• explain risks in plain language and suggest next steps\n"
        "Ask in any language — I’ll reply in the same."
    ),
    "ru": (
        "Я умею:\n"
        "• проверять смарт-контракты токенов (владелец, mint/blacklist, комиссии)\n"
        "• искать на сайтах/соцсетях «красные флаги» и фейки\n"
        "• кратко разбирать ончейн-активность и крупных держателей\n"
        "• объяснять риски простым языком и давать рекомендации\n"
        "Пишите на любом языке — отвечу на нём же."
    )
}

def localize(lang: str, table: Dict[str, str], fallback="en") -> str:
    return table.get(lang) or table.get(lang.split("-")[0]) or table.get(fallback)

# --- системный промпт на нужном языке (микро-локализация тональности) ---
def system_prompt(lang: str) -> str:
    base_en = (
        "You are CryptoGuard, a Web3 security assistant. Be concise, friendly, and practical. "
        "Analyze tokens, contracts, websites, socials, and on-chain activity. "
        "Explain risks with simple language and concrete next steps. "
        "Policy: never fabricate on-chain facts; state uncertainty; ask for missing hashes/links. "
        f"Always respond in {lang}."
    )
    if lang == "ru":
        return (
            "Ты CryptoGuard — ассистент по безопасности Web3. Отвечай кратко, дружелюбно и по делу. "
            "Проверяй токены/контракты/сайты/соцсети и ончейн-активность. Объясняй риски простым языком "
            "и предлагай конкретные шаги. Правило: не выдумывай ончейн-факты; честно говори об "
            "неопределённости; запрашивай недостающие хэши/ссылки. "
            f"Всегда отвечай на языке: {lang}."
        )
    return base_en

# --- утилита вызова модели ---
def llm_reply(user_text: str, lang: str) -> str:
    messages = [
        {"role": "system", "content": system_prompt(lang)},
        {"role": "user", "content": user_text},
    ]
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=0.4,
        max_tokens=800,
    )
    return (resp.choices[0].message.content or "").strip()

# --- маршруты ---
@app.route("/", methods=["GET"])
def root():
    return "ok"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    if not chat_id or not text:
        return "ok"

    # команда выбора языка: /lang ru  |  /lang en
    if text.lower().startswith("/lang"):
        parts = text.split()
        if len(parts) >= 2:
            USER_LANG_PREF[chat_id] = parts[1].lower()
            bot.send_message(chat_id, f"✔ Язык сохранён: {USER_LANG_PREF[chat_id]}")
        else:
            bot.send_message(chat_id, "Пример: /lang en  или  /lang ru")
        return "ok"

    # /start и /help
    if text.lower().startswith("/start"):
        lang = USER_LANG_PREF.get(chat_id) or detect_lang(text)
        bot.send_message(chat_id, localize(lang, WELCOME))
        return "ok"

    if text.lower().startswith("/help"):
        lang = USER_LANG_PREF.get(chat_id) or detect_lang(text)
        bot.send_message(chat_id, localize(lang, CAPABILITIES))
        return "ok"

    # обычное сообщение
    lang = USER_LANG_PREF.get(chat_id) or detect_lang(text)
    try:
        reply = llm_reply(text, lang)
        if not reply:
            reply = localize(lang, {"en": "I couldn’t generate a reply.", "ru": "Не удалось сгенерировать ответ."})
        bot.send_message(chat_id, reply, parse_mode="Markdown")
    except Exception as e:
        bot.send_message(chat_id, f"Error: {type(e).__name__}: {e}")
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
