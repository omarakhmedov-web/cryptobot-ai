import os
import re
import json
from flask import Flask, request
from telegram import Bot
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
MODEL          = os.getenv("MODEL", "llama-3.1-8b-instant")  # безопасная замена
PORT           = int(os.environ.get("PORT", 10000))

bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # ВАЖНО: без proxies и без позиционного kwargs

# --- простой, устойчивый детектор языка (по юникод-диапазонам) ---
LANG_RE = {
    "ru": r"[\u0400-\u04FF]",       # кириллица
    "zh": r"[\u4E00-\u9FFF]",       # китайские иероглифы
    "ja": r"[\u3040-\u30FF]",       # японские хирагана/катакана
    "ko": r"[\uAC00-\uD7AF]",       # корейский
    "ar": r"[\u0600-\u06FF]",       # арабский
    "he": r"[\u0590-\u05FF]",       # иврит
}

def detect_lang(text: str) -> str:
    s = text or ""
    for code, pattern in LANG_RE.items():
        if re.search(pattern, s):
            return code
    return "en"

# --- приветствия ---
WELCOME = {
    "en": ("Hello! I'm CryptoGuard, your Web3 security assistant.\n"
           "Send me a token/contract address or ask anything about crypto.\n"
           "I’ll analyze risks (ownership, mint, taxes, blacklist/pausable), "
           "proxy/upgradability, deployer history, socials, liquidity locks, "
           "top holders & transfer anomalies. I reply in your language."),
    "ru": ("Привет! Я CryptoGuard — ваш помощник по безопасности в Web3.\n"
           "Пришлите адрес токена/контракта или задайте вопрос о крипте.\n"
           "Проверяю риски (владение, минт, налоги, blacklist/pausable), "
           "прокси/обновляемость, деплойера и соцсети, блокировки ликвидности, "
           "топ-холдеров и аномалии переводов. Отвечаю на вашем языке."),
    "zh": "你好！我是 CryptoGuard，你的 Web3 安全助手……我会用你的语言回复。",
    "ja": "こんにちは！CryptoGuard です。Web3 セキュリティを手伝います。あなたの言語で返信します。",
    "ko": "안녕하세요! 저는 CryptoGuard, Web3 보안 도우미입니다. 사용자의 언어로 답합니다.",
    "ar": "مرحبًا! أنا CryptoGuard مساعدك لأمن Web3. سأرد بلغتك.",
    "he": "היי! אני CryptoGuard, עוזר אבטחת Web3. אענה בשפתך.",
}

def system_prompt(lang: str) -> str:
    # компактный, но «на максималках»: multi-lingual + Web3 чек-лист
    return (
        "You are CryptoGuard, a Web3 security assistant.\n"
        f"Always answer in the user's language (lang='{lang}').\n"
        "When given a token/contract address or name, produce a concise risk report:\n"
        "1) Ownership & Mint; Fees/Tax; Blacklist/Honeypot/Pausable.\n"
        "2) Proxy/Upgradability; Deployer history; Socials.\n"
        "3) Liquidity locks; Top holders; Transfer anomalies.\n"
        "Note: You do NOT have on-chain access here; clearly state when data is not publicly available.\n"
        "Be helpful, structured with short bullets, avoid speculation, and add next-step suggestions."
    )

def llm_reply(text: str, lang: str) -> str:
    resp = client.chat.completions.create(
        model=MODEL,
        temperature=0.4,
        max_tokens=800,
        messages=[
            {"role": "system", "content": system_prompt(lang)},
            {"role": "user",   "content": text},
        ],
    )
    return resp.choices[0].message.content.strip()

# --- routes ---
@app.route("/", methods=["GET"])
def health():
    return "OK", 200

@app.route("/webhook", methods=["POST"])
def webhook():
    upd = request.get_json(force=True, silent=True) or {}
    msg = (upd.get("message") or upd.get("edited_message")) or {}
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    text = msg.get("text", "") or ""

    if not chat_id:
        return "ok", 200

    lang = detect_lang(text)
    try:
        if text.strip().lower().startswith("/start"):
            bot.send_message(chat_id=chat_id, text=WELCOME.get(lang, WELCOME["en"]))
            return "ok", 200

        reply = llm_reply(text, lang)
        bot.send_message(chat_id=chat_id, text=reply)
    except Exception as e:
        bot.send_message(chat_id=chat_id, text=f"Error: {e}")
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
