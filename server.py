import os, re, json, logging, io, time, pathlib
from collections import deque, defaultdict
from datetime import datetime

from flask import Flask, request, jsonify
import requests
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from groq import Groq
import qrcode

# -------------------- App / Logging --------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------- ENV --------------------
TELEGRAM_TOKEN     = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY       = os.environ["GROQ_API_KEY"]
ETHERSCAN_API_KEY  = os.getenv("ETHERSCAN_API_KEY", "")
SERPAPI_KEY        = os.getenv("SERPAPI_KEY", "")          # для онлайн-поиска
MODEL              = os.getenv("MODEL", "llama-3.1-8b-instant")
WEBHOOK_SECRET     = os.getenv("WEBHOOK_SECRET", "").strip()

# Язык по умолчанию и приоритет
DEFAULT_LANG       = os.getenv("DEFAULT_LANG", "en").lower()  # en by default

# Донаты / Кнопки
ETH_DONATE_ADDRESS = os.getenv("ETH_DONATE_ADDRESS", "0x212f595E42B93646faFE7Fdfa3c330649FA7407E")
TON_DONATE_ADDRESS = os.getenv("TON_DONATE_ADDRESS", "UQBoAzy9RkbfasGEYwHVRNbWzYNU7JszD0WG9lz8ReFFtESP")
KOFI_LINK_BASE     = os.getenv("KOFI_LINK", "https://ko-fi.com/CryptoNomad")
KOFI_UTM_SOURCE    = os.getenv("KOFI_UTM_SOURCE", "telegram_bot")
DONATE_STICKY      = os.getenv("DONATE_STICKY", "1") in ("1", "true", "True")

# Память
HIST_MAX           = int(os.getenv("HISTORY_MAX", "6"))  # короткая диалоговая память
DATA_DIR           = os.getenv("DATA_DIR", "/tmp/cryptobot_data")  # Render: временное хранилище ок
MEMORY_FILE        = os.getenv("MEMORY_FILE", "memory.json")

# Готовим каталог и файл памяти
pathlib.Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
MEMORY_PATH = pathlib.Path(DATA_DIR) / MEMORY_FILE

# -------------------- Clients --------------------
bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # НИКАКИХ proxies

# -------------------- Language / Texts --------------------
EN_RE = re.compile(r"[A-Za-z]")
LANG_RE = {
    "ru": re.compile(r"[А-Яа-яЁё]"),
    "ar": re.compile(r"[\u0600-\u06FF]"),
}
WELCOME = {
    "en": "Welcome to CryptoGuard. Send a contract address (0x…) and I’ll run a basic on-chain check (Etherscan).",
    "ru": "Добро пожаловать в CryptoGuard. Отправь адрес контракта (0x…), и я выполню базовую ончейн-проверку (Etherscan).",
    "ar": "مرحبًا في CryptoGuard. أرسل عنوان العقد (0x…) وسأجري فحصًا أساسيًا على السلسلة (Etherscan).",
}
FALLBACK = {
    "en": "Please send a contract address (0x…) or ask a question.",
    "ru": "Отправьте адрес контракта (0x…) или задайте вопрос.",
    "ar": "أرسل عنوان عقد (0x…) أو اطرح سؤالًا.",
}
REPORT_LABELS = {
    "en": {"network":"Network","address":"Address","name":"Contract name","sourceverified":"Source verified",
           "impl":"Implementation","proxy":"Proxy","compiler":"Compiler","funcs":"Detected functions",
           "error":"Could not fetch data from Etherscan. Check ETHERSCAN_API_KEY and the address."},
    "ru": {"network":"Сеть","address":"Адрес","name":"Имя контракта","sourceverified":"Исходник верифицирован",
           "impl":"Реализация","proxy":"Прокси","compiler":"Компайлер","funcs":"Обнаруженные функции",
           "error":"Не удалось получить данные Etherscan. Проверь ETHERSCAN_API_KEY и адрес."},
    "ar": {"network":"الشبكة","address":"العنوان","name":"اسم العقد","sourceverified":"المصدر مُتحقق",
           "impl":"Implementation","proxy":"Proxy","compiler":"Compiler","funcs":"الوظائف المكتشفة",
           "error":"تعذّر جلب بيانات Etherscan. تحقّق من ETHERSCAN_API_KEY والعنوان."},
}

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

SYSTEM_PROMPT_BASE = (
    "You are CryptoBot AI — a concise Web3 assistant.\n"
    "RULES:\n"
    "1) If user sends an Ethereum address (0x...), do NOT guess — run an Etherscan check and summarize.\n"
    "2) For general questions, answer briefly and practically.\n"
    "3) If data is missing (chain, address, explorer), say what is needed in ONE short line.\n"
    "4) Never invent on-chain facts or metrics.\n"
    "5) If fresh web snippets are provided, rely on them and cite time (e.g., 'as of <date>')."
)

def detect_lang(text: str, _tg_lang: str | None) -> str:
    """Приоритет: латиница → en; иначе ru/ar по алфавиту; иначе DEFAULT_LANG."""
    t = text or ""
    if EN_RE.search(t): return "en"
    if LANG_RE["ru"].search(t): return "ru"
    if LANG_RE["ar"].search(t): return "ar"
    return DEFAULT_LANG

# -------------------- Donate UI --------------------
def kofi_link_with_utm() -> str:
    sep = "&" if "?" in KOFI_LINK_BASE else "?"
    return f"{KOFI_LINK_BASE}{sep}utm_source={KOFI_UTM_SOURCE}"

def build_donate_keyboard() -> InlineKeyboardMarkup:
    eth_url = f"https://etherscan.io/address/{ETH_DONATE_ADDRESS}"
    ton_url = f"https://tonviewer.com/{TON_DONATE_ADDRESS}"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💎 Ethereum (ETH)", url=eth_url)],
        [InlineKeyboardButton("🔵 TON", url=ton_url)],
        [InlineKeyboardButton("☕ Ko-fi", url=kofi_link_with_utm())],
        [
            InlineKeyboardButton("📷 QR ETH", callback_data="qr_eth"),
            InlineKeyboardButton("📷 QR TON", callback_data="qr_ton"),
        ],
        [
            InlineKeyboardButton("📋 ETH", callback_data="addr_eth"),
            InlineKeyboardButton("📋 TON", callback_data="addr_ton"),
        ],
    ])

def send_donate_message(chat_id: int, lang: str):
    texts = {
        "en": ("Support the project:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n\n"
               "Ko-fi via the button below."),
        "ru": ("Поддержать проект:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n\n"
               "Ko-fi — кнопка ниже."),
        "ar": ("لدعم المشروع:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n\n"
               "Ko-fi من الزر أدناه."),
    }
    bot.send_message(
        chat_id=chat_id,
        text=texts.get(lang, texts["en"]),
        reply_markup=build_donate_keyboard(),
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )

def send_qr(chat_id: int, label: str, value: str):
    img = qrcode.make(value)
    bio = io.BytesIO()
    bio.name = f"{label}.png"
    img.save(bio, format="PNG")
    bio.seek(0)
    bot.send_photo(chat_id=chat_id, photo=bio, caption=f"{label}: `{value}`", parse_mode="Markdown")

# -------------------- Persistent Memory --------------------
# Структура файла: {"chats": { "<chat_id>": {"history":[["user","..."],["assistant","..."], ...] }}}
memory_cache = {"chats": {}}

def load_memory():
    global memory_cache
    try:
        if MEMORY_PATH.exists():
            memory_cache = json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
            if "chats" not in memory_cache:
                memory_cache["chats"] = {}
    except Exception as e:
        app.logger.warning(f"load_memory error: {e}")
        memory_cache = {"chats": {}}

def save_memory():
    try:
        MEMORY_PATH.write_text(json.dumps(memory_cache, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        app.logger.warning(f"save_memory error: {e}")

def get_history(chat_id: int) -> deque:
    load_memory()
    node = memory_cache["chats"].setdefault(str(chat_id), {"history": []})
    # гарантируем ограничение длины
    dq = deque(node.get("history", []), maxlen=HIST_MAX)
    node["history"] = list(dq)
    return dq

def remember(chat_id: int, role: str, content: str):
    dq = get_history(chat_id)
    dq.append([role, content])
    memory_cache["chats"][str(chat_id)]["history"] = list(dq)
    save_memory()

# -------------------- Etherscan --------------------
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
            return {"ok": False, "error": "etherscan error", "raw": data}
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
    res = etherscan_call("getsourcecode", {"address": address})
    if not res.get("ok"):
        facts["error"] = res.get("error")
        return facts

    info = (res["data"] or [{}])[0]
    facts["name"]            = info.get("ContractName") or info.get("Proxy") or "unknown"
    facts["sourceverified"]  = bool(info.get("SourceCode"))
    facts["impl"]            = info.get("Implementation") or ""
    facts["proxy"]           = (info.get("Proxy") == "1")
    facts["compilerVersion"] = info.get("CompilerVersion") or ""
    abi_json                 = info.get("ABI") or "[]"

    caps_res = detect_caps_from_abi(abi_json)
    facts["caps"]        = (caps_res.get("caps") or {})
    facts["abi_present"] = bool(abi_json and abi_json != "Contract source code not verified")
    return facts

def format_report(facts: dict, lang: str) -> str:
    L = REPORT_LABELS.get(lang, REPORT_LABELS["en"])
    if "error" in facts and not facts.get("abi_present"):
        return L["error"]

    lines = []
    lines.append(f"🧭 {L['network']}: {facts.get('network')}")
    lines.append(f"🔗 {L['address']}: {facts.get('address')}")
    if facts.get("name"):            lines.append(f"🏷️ {L['name']}: {facts.get('name')}")
    if facts.get("sourceverified"):  lines.append(f"✅ {L['sourceverified']}: ✅")
    if facts.get("proxy"):           lines.append(f"🧩 {L['proxy']}: ✅")
    if facts.get("impl"):            lines.append(f"🧷 {L['impl']}: {facts.get('impl')}")
    if facts.get("compilerVersion"): lines.append(f"🧪 {L['compiler']}: {facts.get('compilerVersion')}")

    caps = facts.get("caps") or {}
    funcs = []
    if caps.get("has_owner"):              funcs.append("owner()")
    if caps.get("has_transferownership"):  funcs.append("transferOwnership()")
    if caps.get("has_pause"):              funcs.append("pause()/unpause()")
    if caps.get("has_blacklist"):          funcs.append("blacklist()")
    if caps.get("has_mint"):               funcs.append("mint()")
    if caps.get("has_burn"):               funcs.append("burn()")
    if funcs:
        lines.append(f"🧰 {L['funcs']}: " + ", ".join(funcs))
    return "\n".join(lines)

# -------------------- Fresh Web Search (SerpAPI) --------------------
# Включается, если SERPAPI_KEY присутствует и запрос «требует свежести».
FRESH_TRIGGERS = re.compile(
    r"\b(today|now|latest|news|price|prices|update|updated|2024|2025|rate|inflation|btc|eth)\b",
    re.IGNORECASE
)

def needs_fresh_search(text: str) -> bool:
    return bool(text) and bool(FRESH_TRIGGERS.search(text))

def serpapi_search(query: str, lang: str) -> list:
    """Возвращает список кратких сниппетов: [{'title':..,'link':..,'snippet':..}]"""
    if not SERPAPI_KEY:
        return []
    try:
        params = {
            "engine": "google",
            "q": query,
            "api_key": SERPAPI_KEY,
            "hl": "en" if lang == "en" else ("ru" if lang == "ru" else "ar"),
            "num": "5",
        }
        resp = requests.get("https://serpapi.com/search.json", params=params, timeout=20)
        data = resp.json()
        results = []
        for item in (data.get("organic_results") or [])[:5]:
            results.append({
                "title": item.get("title"),
                "link": item.get("link"),
                "snippet": item.get("snippet"),
            })
        return results
    except Exception as e:
        app.logger.warning(f"serpapi_search error: {e}")
        return []

def compose_snippets_text(snips: list, lang: str) -> str:
    if not snips:
        return ""
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    header = {
        "en": f"Fresh web snippets (UTC {date_str}):",
        "ru": f"Свежие сниппеты из веба (UTC {date_str}):",
        "ar": f"ملخصات حديثة من الويب (UTC {date_str}):",
    }.get(lang, f"Fresh web snippets (UTC {date_str}):")
    lines = [header]
    for s in snips:
        t = s.get("title") or ""
        l = s.get("link") or ""
        p = s.get("snippet") or ""
        lines.append(f"- {t} — {p} ({l})")
    return "\n".join(lines)

# -------------------- AI --------------------
def ai_reply(user_text: str, lang: str, chat_id: int) -> str:
    try:
        # Строго фиксируем язык
        system_for_lang = SYSTEM_PROMPT_BASE + f" Always reply ONLY in {lang.upper()}. Do not translate or duplicate in other languages."

        msgs = [{"role": "system", "content": system_for_lang}]

        # Подмешиваем краткую историю (из файла памяти)
        hist = get_history(chat_id)
        for role, content in hist:
            msgs.append({"role": role, "content": content})

        # Если нужны свежие данные и есть SERPAPI_KEY — добавляем контекст
        if needs_fresh_search(user_text) and SERPAPI_KEY:
            snips = serpapi_search(user_text, lang)
            snippets_text = compose_snippets_text(snips, lang)
            if snippets_text:
                msgs.append({"role": "system", "content": snippets_text})

        # Текущее сообщение
        msgs.append({"role": "user", "content": user_text})

        resp = client.chat.completions.create(
            model=MODEL,
            messages=msgs,
            temperature=0.15,
            max_tokens=650,
        )
        content = (resp.choices[0].message.content or "").strip()
        remember(chat_id, "user", user_text)
        remember(chat_id, "assistant", content)
        return content
    except Exception as e:
        app.logger.exception(f"Groq error: {e}")
        return "Internal model error, please try again in a minute."

# -------------------- Routes --------------------
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

    # Callback кнопки
    if "callback_query" in update:
        cq = update["callback_query"]
        data = cq.get("data") or ""
        chat_id = cq.get("message", {}).get("chat", {}).get("id")
        # язык по умолчанию (кнопки нейтральные)
        try:
            if data == "qr_eth":
                send_qr(chat_id, "ETH", ETH_DONATE_ADDRESS)
                bot.answer_callback_query(cq.get("id"), text="QR ETH sent")
            elif data == "qr_ton":
                send_qr(chat_id, "TON", TON_DONATE_ADDRESS)
                bot.answer_callback_query(cq.get("id"), text="QR TON sent")
            elif data == "addr_eth":
                bot.send_message(chat_id=chat_id, text=f"ETH: `{ETH_DONATE_ADDRESS}`", parse_mode="Markdown")
                bot.answer_callback_query(cq.get("id"), text="ETH address sent")
            elif data == "addr_ton":
                bot.send_message(chat_id=chat_id, text=f"TON: `{TON_DONATE_ADDRESS}`", parse_mode="Markdown")
                bot.answer_callback_query(cq.get("id"), text="TON address sent")
            else:
                bot.answer_callback_query(cq.get("id"))
        except Exception as e:
            app.logger.exception(f"callback error: {e}")
        return "ok"

    # Обычные сообщения
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return "ok"

    text = (msg.get("text") or msg.get("caption") or "").strip()
    # игнорируем системный язык Telegram; детектим по тексту
    lang = detect_lang(text, None)
    t_low = (text or "").lower()

    # Команды
    if t_low in ("/start", "start"):
        start_lang = DEFAULT_LANG
        bot.send_message(
            chat_id=chat_id,
            text=WELCOME.get(start_lang, WELCOME["en"]),
            reply_markup=build_donate_keyboard() if DONATE_STICKY else None
        )
        if not DONATE_STICKY:
            send_donate_message(chat_id, start_lang)
        return "ok"

    if t_low in ("/donate", "donate", "донат", "/tip", "tip"):
        send_donate_message(chat_id, lang)
        return "ok"

    # Адрес контракта → отчёт Etherscan
    m = ADDR_RE.search(text)
    if m:
        address = m.group(0)
        facts = analyze_eth_contract(address)
        report = format_report(facts, lang)
        bot.send_message(chat_id=chat_id, text=report,
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Пусто
    if not text:
        bot.send_message(chat_id=chat_id, text=FALLBACK.get(lang, FALLBACK["en"]),
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Обычный AI-ответ (с онлайн-поиском при необходимости и персистентной памятью)
    answer = ai_reply(text, lang, chat_id)
    bot.send_message(chat_id=chat_id, text=answer,
                     reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
    return "ok"

# -------------------- Local run --------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
