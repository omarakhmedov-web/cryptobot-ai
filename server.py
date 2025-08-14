import os, re, json, logging, io, pathlib, html, time, uuid
from collections import deque
from datetime import datetime

from flask import Flask, request, jsonify, Response
import requests
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from groq import Groq
import qrcode

APP_START_TS = time.time()

# -------------------- App / Logging --------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------- ENV --------------------
TELEGRAM_TOKEN     = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY       = os.environ["GROQ_API_KEY"]
ETHERSCAN_API_KEY  = os.getenv("ETHERSCAN_API_KEY", "")
SERPAPI_KEY        = os.getenv("SERPAPI_KEY", "")          # если нет — используем DuckDuckGo fallback
MODEL              = os.getenv("MODEL", "llama-3.1-8b-instant")
WEBHOOK_SECRET     = os.getenv("WEBHOOK_SECRET", "").strip()

# Язык по умолчанию (приоритет английский)
DEFAULT_LANG       = os.getenv("DEFAULT_LANG", "en").lower()

# Донаты / Кнопки
ETH_DONATE_ADDRESS = os.getenv("ETH_DONATE_ADDRESS", "0x212f595E42B93646faFE7Fdfa3c330649FA7407E")
TON_DONATE_ADDRESS = os.getenv("TON_DONATE_ADDRESS", "UQBoAzy9RkbfasGEYwHVRNbWzYNU7JszD0WG9lz8ReFFtESP")
KOFI_LINK_BASE     = os.getenv("KOFI_LINK", "https://ko-fi.com/CryptoNomad")
KOFI_UTM_SOURCE    = os.getenv("KOFI_UTM_SOURCE", "telegram_bot")
DONATE_STICKY      = os.getenv("DONATE_STICKY", "1") in ("1", "true", "True")
SOL_DONATE_ADDRESS = os.getenv("SOL_DONATE_ADDRESS", "X8HAPHLbh7gF2kHCepCixsHkRwix4M34me8gNzhak1z")

# Память (персистентная на диск)
HIST_MAX           = int(os.getenv("HISTORY_MAX", "6"))
DATA_DIR           = os.getenv("DATA_DIR", "/tmp/cryptobot_data")
MEMORY_FILE        = os.getenv("MEMORY_FILE", "memory.json")
pathlib.Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
MEMORY_PATH = pathlib.Path(DATA_DIR) / MEMORY_FILE

# -------------------- Clients --------------------
bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # без proxies

# -------------------- Language / Texts --------------------
EN_RE = re.compile(r"[A-Za-z]")
LANG_RE = {"ru": re.compile(r"[А-Яа-яЁё]"), "ar": re.compile(r"[\u0600-\u06FF]")}
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

# -------------------- Persistent Memory --------------------
# Структура: {
#   "chats": {"<chat_id>":{"history":[...], "lang_override":"en|ru|ar"}},
#   "price_tokens":{"<chat_id>":{"<token>":[ids...]}}
# }
memory_cache = {"chats": {}, "price_tokens": {}}

def load_memory():
    global memory_cache
    try:
        if MEMORY_PATH.exists():
            memory_cache = json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
            memory_cache.setdefault("chats", {})
            memory_cache.setdefault("price_tokens", {})
    except Exception as e:
        app.logger.warning(f"load_memory error: {e}")
        memory_cache = {"chats": {}, "price_tokens": {}}

def save_memory():
    try:
        MEMORY_PATH.write_text(json.dumps(memory_cache, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        app.logger.warning(f"save_memory error: {e}")

def get_history(chat_id: int) -> deque:
    load_memory()
    node = memory_cache["chats"].setdefault(str(chat_id), {"history": []})
    dq = deque(node.get("history", []), maxlen=HIST_MAX)
    node["history"] = list(dq)
    return dq

def remember(chat_id: int, role: str, content: str):
    dq = get_history(chat_id)
    dq.append([role, content])
    memory_cache["chats"][str(chat_id)]["history"] = list(dq)
    save_memory()

def set_lang_override(chat_id: int, lang: str | None):
    load_memory()
    node = memory_cache["chats"].setdefault(str(chat_id), {"history": []})
    if lang:
        node["lang_override"] = lang
    else:
        node.pop("lang_override", None)
    save_memory()

def get_lang_override(chat_id: int) -> str | None:
    load_memory()
    return memory_cache.get("chats", {}).get(str(chat_id), {}).get("lang_override")

# --------- Mapping для коротких callback токенов ---------
def _prune_tokens(tokens_by_chat: dict, keep_last: int = 25):
    if len(tokens_by_chat) > keep_last:
        drop = list(tokens_by_chat.keys())[:-keep_last]
        for k in drop:
            tokens_by_chat.pop(k, None)

def store_price_ids(chat_id: int, ids: list[str]) -> str:
    load_memory()
    chat_key = str(chat_id)
    price_root = memory_cache.setdefault("price_tokens", {})
    tokens_by_chat = price_root.setdefault(chat_key, {})
    token = uuid.uuid4().hex[:10]
    tokens_by_chat[token] = ids
    _prune_tokens(tokens_by_chat, keep_last=25)
    save_memory()
    return token

def resolve_price_ids(chat_id: int, token: str) -> list[str]:
    load_memory()
    return (memory_cache.get("price_tokens", {})
                         .get(str(chat_id), {})
                         .get(token, []))

# -------------------- Language detect with override --------------------
def detect_lang(text: str, _tg_lang: str | None, chat_id: int | None = None) -> str:
    if chat_id is not None:
        over = get_lang_override(chat_id)
        if over in ("en", "ru", "ar"):
            return over
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
    sol_url = f"https://solscan.io/account/{SOL_DONATE_ADDRESS}"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💎 Ethereum (ETH)", url=eth_url)],
        [InlineKeyboardButton("🔵 TON", url=ton_url)],
        [InlineKeyboardButton("🟣 Solana (SOL)", url=sol_url)],
        [InlineKeyboardButton("☕ Ko-fi", url=kofi_link_with_utm())],
        [
            InlineKeyboardButton("📷 QR ETH", callback_data="qr_eth"),
            InlineKeyboardButton("📷 QR TON", callback_data="qr_ton"),
            InlineKeyboardButton("📷 QR SOL", callback_data="qr_sol"),
        ],
        [
            InlineKeyboardButton("📋 ETH", callback_data="addr_eth"),
            InlineKeyboardButton("📋 TON", callback_data="addr_ton"),
            InlineKeyboardButton("📋 SOL", callback_data="addr_sol"),
        ],
    ])

def send_donate_message(chat_id: int, lang: str):
    texts = {
        "en": ("Support the project:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n"
               f"SOL: `{SOL_DONATE_ADDRESS}`\n\n"
               "Ko-fi via the button below."),
        "ru": ("Поддержать проект:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n"
               f"SOL: `{SOL_DONATE_ADDRESS}`\n\n"
               "Ko-fi — кнопка ниже."),
        "ar": ("لدعم المشروع:\n\n"
               f"ETH: `{ETH_DONATE_ADDRESS}`\n"
               f"TON: `{TON_DONATE_ADDRESS}`\n"
               f"SOL: `{SOL_DONATE_ADDRESS}`\n\n"
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

# -------------------- Fresh Web Search --------------------
FRESH_TRIGGERS = re.compile(
    r"\b(today|now|latest|news|price|prices|update|updated|2024|2025|rate|inflation|btc|eth|ton|market)\b",
    re.IGNORECASE
)
def needs_fresh_search(text: str) -> bool:
    return bool(text) and bool(FRESH_TRIGGERS.search(text))

def serpapi_search(query: str, lang: str) -> list:
    if not SERPAPI_KEY:
        return []
    try:
        params = {"engine": "google", "q": query, "api_key": SERPAPI_KEY,
                  "hl": "en" if lang == "en" else ("ru" if lang == "ru" else "ar"), "num": "5"}
        resp = requests.get("https://serpapi.com/search.json", params=params, timeout=20)
        data = resp.json()
        results = []
        for item in (data.get("organic_results") or [])[:5]:
            results.append({"title": item.get("title"), "link": item.get("link"), "snippet": item.get("snippet")})
        return results
    except Exception as e:
        app.logger.warning(f"serpapi_search error: {e}")
        return []

def duckduckgo_fallback(query: str) -> list:
    try:
        url = "https://html.duckduckgo.com/html/"
        resp = requests.post(url, data={"q": query}, timeout=20, headers={"User-Agent":"Mozilla/5.0"})
        html_text = resp.text
        results = []
        link_pat = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I|re.S)
        # FIX: корректный флаг re.S
        snip_pat = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.I|re.S)
        links = link_pat.findall(html_text)[:5]
        snips = snip_pat.findall(html_text)[:5]
        for i, (href, title_html) in enumerate(links):
            title = html.unescape(re.sub("<.*?>", "", title_html)).strip()
            snippet = ""
            if i < len(snips):
                snippet = html.unescape(re.sub("<.*?>", "", snips[i])).strip()
            results.append({"title": title, "link": href, "snippet": snippet})
        return results
    except Exception as e:
        app.logger.warning(f"duckduckgo_fallback error: {e}")
        return []

def compose_snippets_text(snips: list, lang: str) -> str:
    if not snips: return ""
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    header = {"en": f"Fresh web snippets (UTC {date_str}):",
              "ru": f"Свежие сниппеты из веба (UTC {date_str}):",
              "ar": f"ملخصات حديثة من الويب (UTC {date_str}):"}.get(lang, f"Fresh web snippets (UTC {date_str}):")
    lines = [header]
    for s in snips:
        t = s.get("title") or ""; l = s.get("link") or ""; p = s.get("snippet") or ""
        lines.append(f"- {t} — {p} ({l})")
    return "\n".join(lines)

# -------------------- [PRICE] CoinGecko + /price + Refresh --------------------
PRICE_TRIGGERS = re.compile(
    r"(?:\b|_)(?:price|prices|rate|quote|update\s*price)\b"
    r"|(?:\b|_)(?:курс|котировк|котировки|цена|цены|стоимость|сколько\s+стоит|сколько\s+сейчас)\b"
    r"|(?:\b|_)(?:сейчас|на\s+данный\s+момент|прямо\s+сейчас|now|at\s+the\s+moment)\b",
    re.IGNORECASE
)
SYMBOL_TO_CG = {
    "BTC":"bitcoin","XBT":"bitcoin", "ETH":"ethereum", "SOL":"solana", "TON":"the-open-network",
    "USDT":"tether","USDC":"usd-coin","BNB":"binancecoin","ARB":"arbitrum","OP":"optimism",
    "ADA":"cardano","XRP":"ripple","AVAX":"avalanche-2","TRX":"tron","DOGE":"dogecoin",
    "MATIC":"matic-network","SUI":"sui","APT":"aptos",
}
TICKER_RE = re.compile(
    r"(?:(?<=\$)|\b)([A-Z]{2,6}|btc|eth|sol|ton|usdt|usdc|bnb|arb|op|ada|xrp|avax|trx|doge|matic|sui|apt)\b",
    re.IGNORECASE
)
def is_price_query(text: str) -> bool:
    if not text: return False
    return bool(PRICE_TRIGGERS.search(text)) or bool(TICKER_RE.search(text))

def _cg_ids_from_text(text: str) -> list[str]:
    t = (text or "").lower()
    ask_all = any(w in t for w in ("все", "всё", "all"))
    default_top = [
        "bitcoin","ethereum","solana","the-open-network",
        "tether","usd-coin","binancecoin","ripple","cardano","dogecoin"
    ]
    syms = set(m.group(1).upper() for m in TICKER_RE.finditer(text or ""))
    if ask_all and not syms:
        return default_top
    if not syms:
        return ["bitcoin","ethereum","solana","the-open-network"]
    ids, seen = [], set()
    for s in syms:
        cid = SYMBOL_TO_CG.get(s) or next((v for k,v in SYMBOL_TO_CG.items() if k.lower()==s.lower()), None)
        if cid and cid not in seen:
            seen.add(cid); ids.append(cid)
    return ids

# кэш 60 секунд
_cg_cache = {"t":0, "key":"", "data":{}}
def _cg_cache_get(key: str):
    if time.time() - _cg_cache["t"] < 60 and _cg_cache["key"] == key:
        return _cg_cache["data"]
    return None
def _cg_cache_set(key: str, data: dict):
    _cg_cache.update({"t": time.time(), "key": key, "data": data})

def coingecko_prices(coin_ids: list[str], vs="usd") -> dict:
    coin_ids = [c for c in coin_ids if c] or ["bitcoin","ethereum"]
    coin_ids_str = ",".join(coin_ids)
    cache_key = f"{coin_ids_str}:{vs}"
    cached = _cg_cache_get(cache_key)
    if cached is not None:
        return cached
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {"ids": coin_ids_str, "vs_currencies": vs, "include_24hr_change": "true", "include_last_updated_at": "true"}
    try:
        r = requests.get(url, params=params, timeout=15, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
        data = r.json() or {}
        _cg_cache_set(cache_key, data)
        return data
    except Exception as e:
        return {"error": str(e)}

def format_prices_message(data: dict, lang: str = "en", vs="usd") -> str:
    if "error" in data:
        return {"en":"Price fetch error.","ru":"Ошибка получения цены.","ar":"خطأ بجلب السعر."}.get(lang, "Price fetch error.")
    name_map = {
        "bitcoin":"BTC","ethereum":"ETH","solana":"SOL","the-open-network":"TON",
        "tether":"USDT","usd-coin":"USDC","binancecoin":"BNB","arbitrum":"ARB","optimism":"OP",
        "cardano":"ADA","ripple":"XRP","avalanche-2":"AVAX","tron":"TRX","dogecoin":"DOGE","matic-network":"MATIC",
        "sui":"SUI","apt":"APT"
    }
    lines = {"en":["🔔 Spot prices (USD):"],"ru":["🔔 Спот-цены (USD):"],"ar":["🔔 الأسعار الفورية (USD):"]}.get(lang, ["🔔 Spot prices (USD):"])
    order = ["bitcoin","ethereum","solana","the-open-network","tether","usd-coin"]
    for k in order + [k for k in data.keys() if k not in order]:
        if k not in data: continue
        item = data[k]
        price = item.get(vs)
        if price is None:
            continue
        sym = name_map.get(k, k)
        chg = item.get(f"{vs}_24h_change")
        chg_s = ""
        if isinstance(chg, (int,float)):
            sign = "▲" if chg >= 0 else "▼"
            chg_s = f"  {sign}{abs(chg):.2f}%/24h"
        lines.append(f"{sym}: ${price:,.4f}{chg_s}")
    if len(lines) == 1:
        return {"en":"No price data.","ru":"Нет данных по ценам.","ar":"لا توجد بيانات أسعار."}.get(lang, "No price data.")
    try:
        all_ts = [v.get("last_updated_at") for v in data.values() if isinstance(v, dict) and v.get("last_updated_at")]
        if all_ts:
            dt = datetime.utcfromtimestamp(max(all_ts)).strftime("%Y-%m-%d %H:%M UTC")
            lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}.","ar":f"\nحتى {dt}."}.get(lang, f"\nAs of {dt}."))
    except Exception:
        pass
    return "\n".join(lines)

# UI для цен
def _t_refresh(lang: str) -> str:
    return {"en":"🔄 Refresh","ru":"🔄 Обновить","ar":"🔄 تحديث"}.get(lang, "🔄 Refresh")

def build_price_keyboard(chat_id: int, ids: list[str], lang: str) -> InlineKeyboardMarkup:
    token = store_price_ids(chat_id, ids)
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data=f"prf:{token}")]])

# -------------------- TOP-10 --------------------
def coingecko_top_market(cap_n: int = 10) -> list[dict]:
    try:
        url = "https://api.coingecko.com/api/v3/coins/markets"
        params = {
            "vs_currency": "usd",
            "order": "market_cap_desc",
            "per_page": str(cap_n),
            "page": "1",
            "price_change_percentage": "24h"
        }
        r = requests.get(url, params=params, timeout=15, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
        return r.json() or []
    except Exception as e:
        app.logger.warning(f"coingecko_top_market error: {e}")
        return []

def format_top10(mkts: list[dict], lang: str = "en") -> tuple[str, list[str]]:
    if not mkts:
        return (
            {"en":"No market data.","ru":"Нет рыночных данных.","ar":"لا توجد بيانات سوق."}.get(lang, "No market data."),
            []
        )
    lines = {
        "en": ["🏆 Top-10 by market cap (USD):"],
        "ru": ["🏆 Топ-10 по капитализации (USD):"],
        "ar": ["🏆 أعلى 10 بالقيمة السوقية (USD):"],
    }.get(lang, ["🏆 Top-10 by market cap (USD):"])
    ids = []
    for i, c in enumerate(mkts, start=1):
        sym = (c.get("symbol") or "").upper()
        price = c.get("current_price")
        chg = c.get("price_change_percentage_24h")
        chg_s = ""
        if isinstance(chg, (int, float)):
            sign = "▲" if chg >= 0 else "▼"
            chg_s = f"  {sign}{abs(chg):.2f}%/24h"
        lines.append(f"{i}. {sym}: ${price:,.4f}{chg_s}")
        ids.append(c.get("id"))
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}.","ar":f"\nحتى {dt}."}.get(lang, f"\nAs of {dt}."))
    return ("\n".join(lines), ids)

def build_top10_keyboard(chat_id: int, ids: list[str], lang: str) -> InlineKeyboardMarkup:
    token = store_price_ids(chat_id, ids)
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data=f"prf:{token}")]])

# -------------------- GAS / F&G / BTC DOM --------------------
def fetch_gas_etherscan() -> dict | None:
    if not ETHERSCAN_API_KEY:
        return None
    try:
        url = "https://api.etherscan.io/api"
        params = {"module": "gastracker", "action": "gasoracle", "apikey": ETHERSCAN_API_KEY}
        r = requests.get(url, params=params, timeout=10)
        j = r.json()
        res = j.get("result") or {}
        return {
            "source": "etherscan",
            "safe": float(res.get("SafeGasPrice")),
            "propose": float(res.get("ProposeGasPrice")),
            "fast": float(res.get("FastGasPrice")),
            "base": float(res.get("suggestedBaseFee", 0))
        }
    except Exception:
        return None

def fetch_gas_ethgasstation() -> dict | None:
    try:
        url = "https://ethgasstation.info/json/ethgasAPI.json"
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        j = r.json()
        return {
            "source": "ethgasstation",
            "safe": float(j.get("safeLow", 0))/10.0,
            "propose": float(j.get("average", 0))/10.0,
            "fast": float(j.get("fast", 0))/10.0,
            "base": float(j.get("average", 0))/10.0
        }
    except Exception:
        return None

def fetch_gas_etherchain() -> dict | None:
    try:
        url = "https://etherchain.org/api/gasnow"
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        j = r.json().get("data", {})
        to_gwei = lambda wei: float(wei)/1e9 if wei is not None else None
        return {
            "source": "etherchain",
            "safe": to_gwei(j.get("slow")),
            "propose": to_gwei(j.get("standard")),
            "fast": to_gwei(j.get("rapid")),
            "base": to_gwei(j.get("standard"))
        }
    except Exception:
        return None

def get_eth_gas() -> dict:
    for fn in (fetch_gas_etherscan, fetch_gas_ethgasstation, fetch_gas_etherchain):
        data = fn()
        if data and data.get("propose"):
            return data
    return {"error": "gas_unavailable"}

def format_gas_message(data: dict, lang: str) -> str:
    if "error" in data:
        return {"en":"Gas data unavailable.","ru":"Данные по газу недоступны.","ar":"بيانات الغاز غير متاحة."}.get(lang, "Gas data unavailable.")
    src = data.get("source", "n/a")
    lines = {
        "en": ["⛽ Ethereum gas (gwei):"],
        "ru": ["⛽ Газ Ethereum (gwei):"],
        "ar": ["⛽ غاز إيثريوم (gwei):"],
    }.get(lang, ["⛽ Ethereum gas (gwei):"])
    lines.append(f"Safe: {data.get('safe'):.1f}")
    lines.append(f"Propose: {data.get('propose'):.1f}")
    lines.append(f"Fast: {data.get('fast'):.1f}")
    if data.get("base") is not None:
        lines.append(f"Base fee: {data.get('base'):.1f}")
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines.append({"en":f"\nSource: {src}. As of {dt}.",
                  "ru":f"\nИсточник: {src}. По состоянию на {dt}.",
                  "ar":f"\nالمصدر: {src}. حتى {dt}."}.get(lang, f"\nSource: {src}. As of {dt}."))
    return "\n".join(lines)

def build_gas_keyboard(lang: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data="gas:r")]])

def fetch_fear_greed() -> dict:
    try:
        r = requests.get("https://api.alternative.me/fng/", timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        j = r.json()
        item = (j.get("data") or [{}])[0]
        return {
            "value": item.get("value"),
            "classification": item.get("value_classification"),
            "timestamp": item.get("timestamp")
        }
    except Exception:
        return {"error": "fng_unavailable"}

def format_fear_greed(d: dict, lang: str) -> str:
    if "error" in d or not d.get("value"):
        return {"en":"Fear & Greed data unavailable.",
                "ru":"Индекс страха и жадности недоступен.",
                "ar":"بيانات مؤشر الخوف والطمع غير متاحة."}.get(lang, "Fear & Greed data unavailable.")
    val = d["value"]
    cls = d.get("classification","")
    try:
        ts = int(d.get("timestamp") or 0)
        dt = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    hdr = {"en":"😨/😎 Crypto Fear & Greed Index:",
           "ru":"😨/😎 Индекс страха и жадности:",
           "ar":"😨/😎 مؤشر الخوف والطمع:"}.get(lang, "😨/😎 Crypto Fear & Greed Index:")
    return f"{hdr}\n{val} ({cls})\n\n" + {"en":f"As of {dt}.","ru":f"По состоянию на {dt}.","ar":f"حتى {dt}."}.get(lang, f"As of {dt}.")

def build_fng_keyboard(lang: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data="fng:r")]])

def fetch_btc_dominance() -> dict:
    try:
        r = requests.get("https://api.coingecko.com/api/v3/global", timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        j = r.json().get("data", {})
        dom = (j.get("market_cap_percentage") or {}).get("btc")
        mcap = (j.get("total_market_cap") or {}).get("usd")
        return {"dominance": dom, "mcap_usd": mcap}
    except Exception:
        return {"error": "btcdom_unavailable"}

def format_btc_dominance(d: dict, lang: str) -> str:
    if "error" in d or d.get("dominance") is None:
        return {"en":"BTC dominance unavailable.",
                "ru":"Доминация BTC недоступна.",
                "ar":"هيمنة BTC غير متاحة."}.get(lang, "BTC dominance unavailable.")
    dom = float(d["dominance"])
    mcap = d.get("mcap_usd")
    lines = {
        "en": [f"🟧 BTC dominance: {dom:.2f}%"],
        "ru": [f"🟧 Доминация BTC: {dom:.2f}%"],
        "ar": [f"🟧 هيمنة BTC: {dom:.2f}%"],
    }.get(lang, [f"🟧 BTC dominance: {dom:.2f}%"])
    if isinstance(mcap, (int, float)):
        lines.append({"en":f"Total crypto mcap: ${mcap:,.0f}",
                      "ru":f"Общая капитализация рынка: ${mcap:,.0f}",
                      "ar":f"القيمة السوقية الإجمالية: ${mcap:,.0f}"}[lang])
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}.","ar":f"\nحتى {dt}."}.get(lang, f"\nAs of {dt}."))
    return "\n".join(lines)

def build_btcdom_keyboard(lang: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data="bdm:r")]])

# -------------------- AI --------------------
def ai_reply(user_text: str, lang: str, chat_id: int) -> str:
    try:
        system_for_lang = SYSTEM_PROMPT_BASE + f" Always reply ONLY in {lang.upper()}. Do not translate or duplicate in other languages."
        msgs = [{"role": "system", "content": system_for_lang}]
        hist = get_history(chat_id)
        for role, content in hist:
            msgs.append({"role": role, "content": content})
        if needs_fresh_search(user_text):
            snips = serpapi_search(user_text, lang)
            if not snips:
                snips = duckduckgo_fallback(user_text)
            snippets_text = compose_snippets_text(snips, lang)
            if snippets_text:
                msgs.append({"role": "system", "content": snippets_text})
        msgs.append({"role": "user", "content": user_text})
        resp = client.chat.completions.create(model=MODEL, messages=msgs, temperature=0.15, max_tokens=650)
        content = (resp.choices[0].message.content or "").strip()
        remember(chat_id, "user", user_text)
        remember(chat_id, "assistant", content)
        return content
    except Exception as e:
        app.logger.exception(f"Groq error: {e}")
        return "Internal model error, please try again in a minute."

# -------------------- Warm-up / Health --------------------
@app.route("/", methods=["GET", "HEAD"])
def index():
    # быстрый ответ для пингеров
    return Response("ok", status=200, mimetype="text/plain")

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "since": int(APP_START_TS), "uptime_sec": int(time.time() - APP_START_TS)})

@app.route("/uptime", methods=["GET"])
def uptime():
    return Response(str(int(time.time() - APP_START_TS)), status=200, mimetype="text/plain")

# -------------------- Telegram Webhook --------------------
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
        try:
            if data == "qr_eth":
                send_qr(chat_id, "ETH", ETH_DONATE_ADDRESS); bot.answer_callback_query(cq.get("id"), text="QR ETH sent")
            elif data == "qr_ton":
                send_qr(chat_id, "TON", TON_DONATE_ADDRESS); bot.answer_callback_query(cq.get("id"), text="QR TON sent")
            elif data == "qr_sol":
                send_qr(chat_id, "SOL", SOL_DONATE_ADDRESS); bot.answer_callback_query(cq.get("id"), text="QR SOL sent")
            elif data == "addr_eth":
                bot.send_message(chat_id=chat_id, text=f"ETH: `{ETH_DONATE_ADDRESS}`", parse_mode="Markdown"); bot.answer_callback_query(cq.get("id"), text="ETH address sent")
            elif data == "addr_ton":
                bot.send_message(chat_id=chat_id, text=f"TON: `{TON_DONATE_ADDRESS}`", parse_mode="Markdown"); bot.answer_callback_query(cq.get("id"), text="TON address sent")
            elif data == "addr_sol":
                bot.send_message(chat_id=chat_id, text=f"SOL: `{SOL_DONATE_ADDRESS}`", parse_mode="Markdown"); bot.answer_callback_query(cq.get("id"), text="SOL address sent")

            elif data.startswith("prf:"):
                token = data.split(":", 1)[1].strip()
                ids = resolve_price_ids(chat_id, token) or ["bitcoin","ethereum","solana","the-open-network"]
                lang_cq = get_lang_override(chat_id) or DEFAULT_LANG
                data_now = coingecko_prices(ids, vs="usd")
                msg_now = format_prices_message(data_now, lang=lang_cq, vs="usd")
                try:
                    bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=cq.get("message", {}).get("message_id"),
                        text=msg_now,
                        reply_markup=build_price_keyboard(chat_id, ids, lang_cq)
                    )
                except Exception:
                    bot.send_message(chat_id=chat_id, text=msg_now, reply_markup=build_price_keyboard(chat_id, ids, lang_cq))
                bot.answer_callback_query(cq.get("id"), text="Updated")

            elif data == "gas:r":
                lang_cq = get_lang_override(chat_id) or DEFAULT_LANG
                gas = get_eth_gas()
                msg = format_gas_message(gas, lang_cq)
                try:
                    bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=cq.get("message", {}).get("message_id"),
                        text=msg,
                        reply_markup=build_gas_keyboard(lang_cq)
                    )
                except Exception:
                    bot.send_message(chat_id=chat_id, text=msg, reply_markup=build_gas_keyboard(lang_cq))
                bot.answer_callback_query(cq.get("id"), text="Updated")

            elif data == "fng:r":
                lang_cq = get_lang_override(chat_id) or DEFAULT_LANG
                d = fetch_fear_greed()
                msg = format_fear_greed(d, lang_cq)
                try:
                    bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=cq.get("message", {}).get("message_id"),
                        text=msg,
                        reply_markup=build_fng_keyboard(lang_cq)
                    )
                except Exception:
                    bot.send_message(chat_id=chat_id, text=msg, reply_markup=build_fng_keyboard(lang_cq))
                bot.answer_callback_query(cq.get("id"), text="Updated")

            elif data == "bdm:r":
                lang_cq = get_lang_override(chat_id) or DEFAULT_LANG
                d = fetch_btc_dominance()
                msg = format_btc_dominance(d, lang_cq)
                try:
                    bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=cq.get("message", {}).get("message_id"),
                        text=msg,
                        reply_markup=build_btcdom_keyboard(lang_cq)
                    )
                except Exception:
                    bot.send_message(chat_id=chat_id, text=msg, reply_markup=build_btcdom_keyboard(lang_cq))
                bot.answer_callback_query(cq.get("id"), text="Updated")

            else:
                bot.answer_callback_query(cq.get("id"))
        except Exception as e:
            app.logger.exception(f"callback error: {e}")
            try:
                bot.answer_callback_query(cq.get("id"), text="Error", show_alert=False)
            except Exception:
                pass
        return "ok"

    # Обычные сообщения
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return "ok"

    text = (msg.get("text") or msg.get("caption") or "").strip()
    t_low = (text or "").lower()

    # Команды /start
    if t_low in ("/start", "start"):
        start_lang = get_lang_override(chat_id) or DEFAULT_LANG
        bot.send_message(chat_id=chat_id, text=WELCOME.get(start_lang, WELCOME["en"]),
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        if not DONATE_STICKY:
            send_donate_message(chat_id, start_lang)
        return "ok"

    # Принудительная установка языка: /lang en|ru|ar
    if t_low.startswith("/lang"):
        parts = t_low.split()
        if len(parts) >= 2 and parts[1] in ("en","ru","ar"):
            set_lang_override(chat_id, parts[1])
            bot.send_message(chat_id=chat_id, text={"en":"Language set.","ru":"Язык установлен.","ar":"تم ضبط اللغة."}.get(parts[1], "Language set."))
        else:
            bot.send_message(chat_id=chat_id, text="Usage: /lang en | ru | ar")
        return "ok"

    # Донаты
    lang = detect_lang(text, None, chat_id)
    if t_low in ("/donate", "donate", "донат", "/tip", "tip"):
        send_donate_message(chat_id, lang)
        return "ok"

    # /price BTC ETH SOL ...
    if t_low.startswith("/price"):
        tail = text.split(None, 1)[1] if len(text.split()) > 1 else ""
        query_text = tail or "BTC ETH SOL TON"
        ids = _cg_ids_from_text(query_text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, lang))
        return "ok"

    # /top10
    if t_low.startswith("/top10"):
        mkts = coingecko_top_market(10)
        msg_out, ids = format_top10(mkts, lang=lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_top10_keyboard(chat_id, ids, lang))
        return "ok"

    # /gas
    if t_low.startswith("/gas") or t_low == "gas":
        msg_out = format_gas_message(get_eth_gas(), lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_gas_keyboard(lang))
        return "ok"

    # /feargreed | /fng
    if t_low.startswith("/feargreed") or t_low == "/fng" or t_low == "feargreed" or t_low == "fng":
        d = fetch_fear_greed()
        msg_out = format_fear_greed(d, lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_fng_keyboard(lang))
        return "ok"

    # /btcdom
    if t_low.startswith("/btcdom") or t_low == "btcdom":
        d = fetch_btc_dominance()
        msg_out = format_btc_dominance(d, lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_btcdom_keyboard(lang))
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

    # Быстрый ответ цен через CoinGecko
    if is_price_query(text):
        ids = _cg_ids_from_text(text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, lang))
        return "ok"

    # Пусто
    if not text:
        bot.send_message(chat_id=chat_id, text=FALLBACK.get(lang, FALLBACK["en"]),
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Обычный AI-ответ
    answer = ai_reply(text, lang, chat_id)
    bot.send_message(chat_id=chat_id, text=answer,
                     reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
    return "ok"

# -------------------- Local run --------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
