import os, re, json
from flask import Flask, request
from telegram import Bot
from groq import Groq
import requests

app = Flask(__name__)

# ========= ENV =========
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY   = os.environ["GROQ_API_KEY"]
ETHERSCAN_KEY  = os.getenv("ETHERSCAN_API_KEY", "")  # обязательный для ончейн-проверки

# Модель для краткого ИИ-резюме
GROQ_MODEL = "llama-3.1-8b-instant"

bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)

# ========= Мультиязычность =========
LANG_RE = {
    "ar": re.compile(r"[\u0600-\u06FF]"),
    "ru": re.compile(r"[\u0400-\u04FF]"),
}
WELCOME = {
    "en": "Welcome to CryptoGuard. Send me a contract address (0x...) and I’ll run a basic on-chain check (Etherscan).",
    "ru": "Добро пожаловать в CryptoGuard. Отправьте адрес контракта (0x...), и я выполню базовую ончейн-проверку (Etherscan).",
    "ar": "مرحبًا بك في CryptoGuard. أرسل عنوان عقد (0x...) وسأجري فحصًا أساسيًا على السلسلة (Etherscan).",
}
FALLBACK = {
    "en": "Please send a contract address (0x...).",
    "ru": "Пожалуйста, отправьте адрес контракта (0x...).",
    "ar": "من فضلك أرسل عنوان عقد (0x...).",
}
REPORT_LABELS = {
    "en": {
        "network": "Network",
        "address": "Address",
        "name": "Contract name",
        "verified": "Source verified",
        "proxy": "Proxy",
        "impl": "Implementation",
        "compiler": "Compiler",
        "funcs": "Detected functions",
        "error": "Could not fetch data from Etherscan. Check ETHERSCAN_API_KEY and the address.",
    },
    "ru": {
        "network": "Сеть",
        "address": "Адрес",
        "name": "Имя контракта",
        "verified": "Исходник верифицирован",
        "proxy": "Proxy",
        "impl": "Implementation",
        "compiler": "Компилятор",
        "funcs": "Обнаруженные функции",
        "error": "Не удалось получить данные с Etherscan. Проверьте ETHERSCAN_API_KEY и адрес.",
    },
    "ar": {
        "network": "الشبكة",
        "address": "العنوان",
        "name": "اسم العقد",
        "verified": "المصدر مُوثَّق",
        "proxy": "بروكسي",
        "impl": "العنوان التنفيذي",
        "compiler": "المترجم",
        "funcs": "الدوال المكتشفة",
        "error": "تعذر جلب البيانات من Etherscan. تحقق من ETHERSCAN_API_KEY والعنوان.",
    },
}

def pick_lang(text: str, tg_lang_code: str | None) -> str:
    # 1) язык профиля Telegram, если есть
    if tg_lang_code:
        if tg_lang_code.startswith("ru"): return "ru"
        if tg_lang_code.startswith("ar"): return "ar"
    # 2) по символам
    if text:
        if LANG_RE["ar"].search(text): return "ar"
        if LANG_RE["ru"].search(text): return "ru"
    # 3) по умолчанию
    return "en"

# ========= Ончейн-проверка (Etherscan) =========
ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

def etherscan_call(action: str, params: dict) -> dict:
    if not ETHERSCAN_KEY:
        return {"ok": False, "error": "ETHERSCAN_API_KEY is not set"}
    base = "https://api.etherscan.io/api"
    query = {"module": "contract", "action": action, "apikey": ETHERSCAN_KEY, **params}
    try:
        r = requests.get(base, params=query, timeout=15)
        r.raise_for_status()
        data = r.json()
        # Etherscan возвращает status="1" при успехе
        if data.get("status") == "1":
            return {"ok": True, "result": data.get("result")}
        return {"ok": False, "error": data.get("message", "etherscan error"), "raw": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def detect_capabilities_from_abi(abi_json: str) -> dict:
    caps = {
        "has_owner": False, "has_transfer_ownership": False,
        "has_pause": False, "has_blacklist": False,
        "has_mint": False, "has_burn": False,
    }
    try:
        abi = json.loads(abi_json)
    except Exception:
        return caps

    def has(fname: str) -> bool:
        f = fname.lower()
        for item in abi:
            if item.get("type") != "function": 
                continue
            if item.get("name", "").lower() == f:
                return True
        return False

    caps["has_owner"]              = has("owner") or has("getOwner")
    caps["has_transfer_ownership"] = has("transferOwnership")
    caps["has_pause"]              = has("pause") or has("paused") or has("unpause")
    caps["has_blacklist"]          = has("blacklist") or has("isBlacklisted")
    caps["has_mint"]               = has("mint")
    caps["has_burn"]               = has("burn")
    return caps

def analyze_eth_contract(address: str) -> dict:
    facts = {"network": "ethereum", "address": address}

    src = etherscan_call("getsourcecode", {"address": address})
    if src["ok"] and src["result"]:
        info = src["result"][0]
        facts["contractName"]    = info.get("ContractName") or ""
        facts["isProxy"]         = (info.get("Proxy") == "1")
        facts["implementation"]  = info.get("Implementation") or ""
        facts["sourceVerified"]  = bool(info.get("SourceCode"))
        facts["compilerVersion"] = info.get("CompilerVersion") or ""
    else:
        facts["error_source"] = src.get("error", "unknown")

    abi = etherscan_call("getabi", {"address": address})
    if abi["ok"]:
        caps = detect_capabilities_from_abi(abi["result"])
        facts["abi_present"] = True
        facts.update(caps)
    else:
        facts["error_abi"] = abi.get("error", "unknown")

    return facts

def format_report(facts: dict, lang: str) -> str:
    L = REPORT_LABELS.get(lang, REPORT_LABELS["en"])
    # Если оба провалились
    if "error_source" in facts and "error_abi" in facts:
        return L["error"]

    lines = []
    lines.append(f"🔎 {L['network']}: {facts.get('network','?')}  |  {L['address']}: `{facts['address']}`")
    if facts.get("contractName"):
        lines.append(f"• {L['name']}: **{facts['contractName']}**")
    if "sourceVerified" in facts:
        lines.append(f"• {L['verified']}: **{'yes' if lang=='en' else ('да' if lang=='ru' else 'نعم') if facts['sourceVerified'] else ('no' if lang=='en' else ('нет' if lang=='ru' else 'لا'))}**")
    if "isProxy" in facts:
        lines.append(f"• {L['proxy']}: **{'yes' if lang=='en' else ('да' if lang=='ru' else 'نعم') if facts['isProxy'] else ('no' if lang=='en' else ('нет' if lang=='ru' else 'لا'))}**")
    if facts.get("implementation"):
        lines.append(f"• {L['impl']}: `{facts['implementation']}`")
    if facts.get("compilerVersion"):
        lines.append(f"• {L['compiler']}: {facts['compilerVersion']}")

    # функции
    caps = []
    if facts.get("has_owner"): caps.append("owner")
    if facts.get("has_transfer_ownership"): caps.append("transferOwnership")
    if facts.get("has_pause"): caps.append("pause")
    if facts.get("has_blacklist"): caps.append("blacklist")
    if facts.get("has_mint"): caps.append("mint")
    if facts.get("has_burn"): caps.append("burn")
    if caps:
        lines.append(f"• {L['funcs']}: " + ", ".join(caps))

    return "\n".join(lines)

def reply_text(chat_id: int, text: str):
    try:
        bot.send_message(chat_id=chat_id, text=text, parse_mode="Markdown")
    except Exception:
        bot.send_message(chat_id=chat_id, text=text)

SYSTEM_PROMPT = (
    "You are CryptoGuard, a Web3 security assistant. "
    "User may speak English, Russian or Arabic. Reply in user's language. "
    "Use the provided on-chain facts to write a short, cautious summary. "
    "If data is missing, say so. Never invent specifics."
)

# ========= Routes =========
@app.route("/", methods=["GET"])
def index():
    return "ok"

@app.route("/webhook", methods=["POST"])
def webhook():
    data     = request.get_json(force=True, silent=True) or {}
    msg      = data.get("message") or data.get("edited_message") or {}
    chat     = msg.get("chat") or {}
    chat_id  = chat.get("id")
    text     = (msg.get("text") or msg.get("caption") or "").strip()
    from_obj = msg.get("from") or {}
    tg_lang  = from_obj.get("language_code")

    if not chat_id:
        return "ok"

    lang = pick_lang(text, tg_lang)

    # адрес контракта?
    m = ADDR_RE.search(text)
    if m:
        addr   = m.group(0)
        facts  = analyze_eth_contract(addr)
        report = format_report(facts, lang)

        # краткое резюме ИИ на нужном языке
        try:
            # Подсказываем модели язык.
            lang_hint = {"en": "English", "ru": "Russian", "ar": "Arabic"}[lang]
            prompt = (
                f"Language: {lang_hint}.\n"
                f"Summarize for a user these on-chain facts and highlight obvious risks if any:\n\n{report}"
            )
            summary = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=220,
            ).choices[0].message.content.strip()
            reply_text(chat_id, report + "\n\n" + "—" * 20 + "\n" + summary)
        except Exception:
            reply_text(chat_id, report)
        return "ok"

    # /start
    if text.startswith("/start"):
        reply_text(chat_id, WELCOME.get(lang, WELCOME["en"]))
        return "ok"

    # Общий диалог через Groq (в языке пользователя)
    try:
        lang_hint = {"en": "English", "ru": "Russian", "ar": "Arabic"}[lang]
        prompt = f"Language: {lang_hint}. Answer briefly and helpfully.\nUser: {text or 'hi'}"
        out = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=300,
        ).choices[0].message.content.strip()
        reply_text(chat_id, out)
    except Exception:
        reply_text(chat_id, FALLBACK.get(lang, FALLBACK["en"]))
    return "ok"
