import os, re, json, logging
from flask import Flask, request, jsonify
import requests
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from groq import Groq

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ========= ENV =========
TELEGRAM_TOKEN     = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY       = os.environ["GROQ_API_KEY"]
ETHERSCAN_API_KEY  = os.getenv("ETHERSCAN_API_KEY", "")
MODEL              = os.getenv("MODEL", "llama-3.1-8b-instant")
WEBHOOK_SECRET     = os.getenv("WEBHOOK_SECRET", "").strip()

# Донаты (можно задать ENV — иначе берутся значения по умолчанию)
ETH_DONATE_ADDRESS = os.getenv("ETH_DONATE_ADDRESS", "0x212f595E42B93646faFE7Fdfa3c330649FA7407E")
TON_DONATE_ADDRESS = os.getenv("TON_DONATE_ADDRESS", "UQBoAzy9RkbfasGEYwHVRNbWzYNU7JszD0WG9lz8ReFFtESP")
KOFI_LINK          = os.getenv("KOFI_LINK", "https://ko-fi.com/CryptoNomad")

bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)   # без proxies

# ========= ЯЗЫК/ТЕКСТЫ =========
LANG_RE = {
    "ru": re.compile(r"[А-Яа-яЁё]"),
    "ar": re.compile(r"[\u0600-\u06FF]"),
}
WELCOME = {
    "en": "Welcome to CryptoGuard. Send me a contract address (0x…) and I’ll run a basic on-chain check (Etherscan).",
    "ru": "Добро пожаловать в CryptoGuard. Отправь адрес контракта (0x…), и я выполню базовую ончейн-проверку (Etherscan).",
    "ar": "مرحبًا في CryptoGuard. أرسل عنوان العقد (0x…) وسأجري فحصًا أساسيًا على السلسلة (Etherscan).",
}
FALLBACK = {
    "en": "Please send a contract address (0x…).",
    "ru": "Пожалуйста, отправь адрес контракта (0x…).",
    "ar": "من فضلك أرسل عنوان عقد (0x…).",
}
REPORT_LABELS = {
    "en": {
        "network": "Network",
        "address": "Address",
        "name": "Contract name",
        "sourceverified": "Source verified",
        "impl": "Implementation",
        "proxy": "Proxy",
        "compiler": "Compiler",
        "funcs": "Detected functions",
        "error": "Could not fetch data from Etherscan. Check ETHERSCAN_API_KEY and the address.",
    },
    "ru": {
        "network": "Сеть",
        "address": "Адрес",
        "name": "Имя контракта",
        "sourceverified": "Исходник верифицирован",
        "impl": "Реализация",
        "proxy": "Прокси",
        "compiler": "Компайлер",
        "funcs": "Обнаруженные функции",
        "error": "Не удалось получить данные Etherscan. Проверь ETHERSCAN_API_KEY и адрес.",
    },
    "ar": {
        "network": "الشبكة",
        "address": "العنوان",
        "name": "اسم العقد",
        "sourceverified": "المصدر مُتحقق",
        "impl": "Implementation",
        "proxy": "Proxy",
        "compiler": "Compiler",
        "funcs": "الوظائف المكتشفة",
        "error": "تعذّر جلب بيانات Etherscan. تحقّق من ETHERSCAN_API_KEY والعنوان.",
    },
}

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

SYSTEM_PROMPT = (
    "You are CryptoBot AI — a Web3 security assistant. "
    "User may speak English/Russian/Arabic; reply in user's language. "
    "You can provide on-chain insights, but do not invent specifics. "
    "If data is missing, say so. Never invent specific on-chain facts."
)

def detect_lang(text: str, tg_lang: str | None) -> str:
    # Приоритет: указанный язык Telegram → автоопределение по символам → en
    if tg_lang:
        if tg_lang.startswith("ru"): return "ru"
        if tg_lang.startswith("ar"): return "ar"
        if tg_lang.startswith("en"): return "en"
    if text:
        if LANG_RE["ru"].search(text): return "ru"
        if LANG_RE["ar"].search(text): return "ar"
    return "en"

# ========= DONATE =========
def build_donate_keyboard() -> InlineKeyboardMarkup:
    eth_url = f"https://etherscan.io/address/{ETH_DONATE_ADDRESS}"
    ton_url = f"https://tonviewer.com/{TON_DONATE_ADDRESS}"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💎 Ethereum (ETH)", url=eth_url)],
        [InlineKeyboardButton("🔵 TON", url=ton_url)],
        [InlineKeyboardButton("☕ Ko-fi", url=KOFI_LINK)],
    ])

def send_donate_message(chat_id: int, lang: str):
    texts = {
        "en": (
            "Support the project:\n\n"
            f"ETH: `{ETH_DONATE_ADDRESS}`\n"
            f"TON: `{TON_DONATE_ADDRESS}`\n\n"
            "Or use Ko-fi via the button below."
        ),
        "ru": (
            "Поддержать проект:\n\n"
            f"ETH: `{ETH_DONATE_ADDRESS}`\n"
            f"TON: `{TON_DONATE_ADDRESS}`\n\n"
            "Либо Ko-fi — кнопка ниже."
        ),
        "ar": (
            "لدعم المشروع:\n\n"
            f"ETH: `{ETH_DONATE_ADDRESS}`\n"
            f"TON: `{TON_DONATE_ADDRESS}`\n\n"
            "أو عبر Ko-fi من الزر أدناه."
        ),
    }
    bot.send_message(
        chat_id=chat_id,
        text=texts.get(lang, texts["en"]),
        reply_markup=build_donate_keyboard(),
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )

# ========= ETHERSCAN =========
def etherscan_call(action: str, params: dict) -> dict:
    if not ETHERSCAN_API_KEY:
        return {"ok": False, "error": "ETHERSCAN_API_KEY is not set"}
    base = "https://api.etherscan.io/api"
    query = {"module": "contract", "action": action, "apikey": ETHERSCAN_API_KEY}
    query.update(params)
    try:
        r = requests.get(base, params=query, timeout=15)
        data = r.json()
        if str(data.get("status")) != "1":
            return {"ok": False, "error": f"etherscan error", "raw": data}
        return {"ok": True, "data": data.get("result")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def has_fn(abi: list, name: str) -> bool:
    for item in abi or []:
        if item.get("type") != "function": 
            continue
        if item.get("name", "").lower() == name.lower():
            return True
    return False

def detect_caps_from_abi(abi_json: str) -> dict:
    try:
        abi = json.loads(abi_json or "[]")
    except Exception:
        return {"ok": False, "caps": {}}
    caps = {
        "has_owner": has_fn(abi, "owner"),
        "has_transferownership": has_fn(abi, "transferOwnership"),
        "has_pause": (has_fn(abi, "pause") or has_fn(abi, "unpause")),
        "has_blacklist": (has_fn(abi, "blacklist") or has_fn(abi, "unblacklist")),
        "has_mint": has_fn(abi, "mint"),
        "has_burn": has_fn(abi, "burn"),
    }
    return {"ok": True, "caps": caps}

def analyze_eth_contract(address: str) -> dict:
    facts = {"network": "ethereum", "address": address}
    # 1) исходники/метаданные
    res = etherscan_call("getsourcecode", {"address": address})
    if not res.get("ok"):
        facts["error"] = res.get("error")
        return facts

    info = (res["data"] or [{}])[0]
    facts["name"] = info.get("ContractName") or info.get("Proxy") or "unknown"
    facts["sourceverified"] = bool(info.get("SourceCode"))
    facts["impl"] = info.get("Implementation") or ""
    facts["proxy"] = (info.get("Proxy") == "1")
    facts["compilerVersion"] = info.get("CompilerVersion") or ""
    abi_json = info.get("ABI") or "[]"

    # 2) капабилити из ABI
    caps_res = detect_caps_from_abi(abi_json)
    facts["caps"] = (caps_res.get("caps") or {})
    facts["abi_present"] = bool(abi_json and abi_json != "Contract source code not verified")
    return facts

def format_report(facts: dict, lang: str) -> str:
    L = REPORT_LABELS.get(lang, REPORT_LABELS["en"])
    if "error" in facts and not facts.get("abi_present"):
        return L["error"]

    lines = []
    lines.append(f"🧭 {L['network']}: {facts.get('network')}")
    lines.append(f"🔗 {L['address']}: {facts.get('address')}")
    if facts.get("name"):           lines.append(f"🏷️ {L['name']}: {facts.get('name')}")
    if facts.get("sourceverified"): lines.append(f"✅ {L['sourceverified']}: ✅")
    if facts.get("proxy"):          lines.append(f"🧩 {L['proxy']}: ✅")
    if facts.get("impl"):           lines.append(f"🧷 {L['impl']}: {facts.get('impl')}")
    if facts.get("compilerVersion"):lines.append(f"🧪 {L['compiler']}: {facts.get('compilerVersion')}")

    caps = facts.get("caps") or {}
    funcs_line = []
    if caps.get("has_owner"):               funcs_line.append("owner()")
    if caps.get("has_transferownership"):   funcs_line.append("transferOwnership()")
    if caps.get("has_pause"):               funcs_line.append("pause()/unpause()")
    if caps.get("has_blacklist"):           funcs_line.append("blacklist()")
    if caps.get("has_mint"):                funcs_line.append("mint()")
    if caps.get("has_burn"):                funcs_line.append("burn()")
    if funcs_line:
        lines.append(f"🧰 {L['funcs']}: " + ", ".join(funcs_line))
    return "\n".join(lines)

# ========= GROQ =========
def ai_reply(user_text: str) -> str:
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_text},
            ],
            temperature=0.3,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        app.logger.exception(f"Groq error: {e}")
        return "Internal model error, please try again in a minute."

# ========= ROUTES =========
@app.route("/", methods=["GET"])
def index():
    return "ok"

@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    if request.method == "GET":
        return "ok"

    if WEBHOOK_SECRET:
        header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if header_secret != WEBHOOK_SECRET:
            return jsonify({"ok": False, "error": "bad secret"}), 403

    update = request.get_json(force=True, silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return "ok"

    text = (msg.get("text") or msg.get("caption") or "").strip()
    tg_lang = (msg.get("from", {}) or {}).get("language_code")
    lang = detect_lang(text, tg_lang)

    t_low = text.lower()

    # ----- команды /start и /donate -----
    if t_low in ("/start", "start"):
        bot.send_message(chat_id=chat_id, text=WELCOME.get(lang, WELCOME["en"]))
        send_donate_message(chat_id, lang)
        return "ok"

    if t_low in ("/donate", "donate", "донат", "/tip", "tip"):
        send_donate_message(chat_id, lang)
        return "ok"

    # ----- если прислали адрес контракта — делаем etherscan отчёт -----
    m = ADDR_RE.search(text)
    if m:
        address = m.group(0)
        facts = analyze_eth_contract(address)
        report = format_report(facts, lang)
        bot.send_message(chat_id=chat_id, text=report)
        return "ok"

    # ----- обычный AI ответ -----
    if not text:
        bot.send_message(chat_id=chat_id, text=FALLBACK.get(lang, FALLBACK["en"]))
        return "ok"

    answer = ai_reply(text)
    bot.send_message(chat_id=chat_id, text=answer)
    return "ok"

# локальный запуск
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
