import os, re, json, logging, io, pathlib, html, time, uuid
from collections import deque
from datetime import datetime
from decimal import Decimal

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
TELEGRAM_TOKEN       = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY         = os.environ["GROQ_API_KEY"]
ETHERSCAN_API_KEY    = os.getenv("ETHERSCAN_API_KEY", "").strip()
POLYGONSCAN_API_KEY  = os.getenv("POLYGONSCAN_API_KEY", "").strip()
BSCSCAN_API_KEY      = os.getenv("BSCSCAN_API_KEY", "").strip()
ALCHEMY_API_KEY      = os.getenv("ALCHEMY_API_KEY", "").strip()   # <— NEW: for balances/txs
SERPAPI_KEY          = os.getenv("SERPAPI_KEY", "")          # если нет — используем DuckDuckGo fallback
MODEL                = os.getenv("MODEL", "llama-3.1-8b-instant")
WEBHOOK_SECRET       = os.getenv("WEBHOOK_SECRET", "").strip()

# Язык по умолчанию
DEFAULT_LANG         = os.getenv("DEFAULT_LANG", "en").lower()

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
LANG_RE = {"ru": re.compile(r"[А-Яа-яЁё]")}

# Универсальное приветствие (полная версия для /start)
WELCOME = {
    "en": (
        "🤖 Welcome to GuardexBot — your compact Web3 assistant.\n\n"
        "I can:\n"
        "• Answer crypto/Web3 questions.\n"
        "• Show live prices, top-10 coins, gas fees, BTC dominance, Fear & Greed.\n"
        "• Contract checks via block explorers (Etherscan/PolygonScan/BscScan) — auto-selected.\n"
        "• Balances & recent transactions via Alchemy.\n\n"
        "💎 Support the project so it can grow, improve, and stay online 24/7 for everyone’s benefit.\n"
        "Your help adds new features, integrations, and smarter answers. Every contribution matters! ☕💙"
    ),
    "ru": (
        "🤖 Добро пожаловать в GuardexBot — вашего компактного помощника в мире Web3.\n\n"
        "Я умею:\n"
        "• Отвечать на вопросы о криптовалютах и Web3.\n"
        "• Показывать цены в реальном времени, топ-10 монет, газ, доминацию BTC, индекс страха и жадности.\n"
        "• Проверять контракты через блок-эксплореры (Etherscan/PolygonScan/BscScan) — автоматический выбор.\n"
        "• Показывать баланс и последние транзакции через Alchemy.\n\n"
        "💎 Поддержите проект, чтобы он развивался, совершенствовался и всегда был на связи 24/7 на благо людей.\n"
        "Ваша помощь добавит новые функции, интеграции и сделает ответы умнее. Каждый вклад важен! ☕💙"
    ),
}

# Мотивирующий текст для /donate (без списка возможностей)
DONATE_TEXT = {
    "en": (
        "💎 Support GuardexBot so it can grow, improve, and stay online 24/7 for everyone’s benefit.\n\n"
        "Your donation helps to:\n"
        "• Keep the bot running reliably without downtime.\n"
        "• Add new features and integrations (Etherscan/PolygonScan/BscScan, Alchemy analytics, alerts).\n"
        "• Make answers smarter and more useful for the crypto community.\n\n"
        "Every contribution matters — thank you! ☕💙"
    ),
    "ru": (
        "💎 Поддержите GuardexBot, чтобы он развивался, совершенствовался и всегда был на связи 24/7 на благо людей.\n\n"
        "Ваш вклад помогает:\n"
        "• Обеспечивать стабильную работу бота без простоев.\n"
        "• Добавлять новые функции и интеграции (Etherscan/PolygonScan/BscScan, Alchemy аналитика, уведомления).\n"
        "• Делать ответы умнее и полезнее для крипто-сообщества.\n\n"
        "Каждый вклад важен — спасибо! ☕💙"
    ),
}

REPORT_LABELS = {
    "en": {"network":"Network","address":"Address","name":"Contract name","sourceverified":"Source verified",
           "impl":"Implementation","proxy":"Proxy","compiler":"Compiler","funcs":"Detected functions",
           "via":"Data source","error":"Could not fetch data from explorers. Add API keys or check the address."},
    "ru": {"network":"Сеть","address":"Адрес","name":"Имя контракта","sourceverified":"Исходник верифицирован",
           "impl":"Реализация","proxy":"Прокси","compiler":"Компайлер","funcs":"Обнаруженные функции",
           "via":"Источник","error":"Не удалось получить данные у блок-эксплореров. Добавьте API ключи или проверьте адрес."},
}
ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

SYSTEM_PROMPT_BASE = (
    "You are GuardexBot — a concise Web3 assistant.\n"
    "RULES:\n"
    "1) If user sends an Ethereum address (0x...), do NOT guess — run an explorer check and summarize.\n"
    "2) For general questions, answer briefly and practically.\n"
    "3) If data is missing (chain, address, explorer), say what is needed in ONE short line.\n"
    "4) Never invent on-chain facts or metrics.\n"
    "5) If fresh web snippets are provided, rely on them and cite time (e.g., 'as of <date>')."
)

# -------------------- Persistent Memory --------------------
# Структура: {
#   "chats": {"<chat_id>":{"history":[...], "lang_override":"en|ru"}},
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
        if over in ("en", "ru"):
            return over
    t = text or ""
    if EN_RE.search(t): return "en"
    if LANG_RE["ru"].search(t): return "ru"
    return DEFAULT_LANG

def maybe_set_language_from_text(t_low: str) -> str | None:
    """
    Возвращает 'en' | 'ru' | None на основе свободной фразы пользователя.
    """
    if not t_low:
        return None
    # Английский
    if re.search(r"\b(set|switch|change)\s+(the\s+)?language\s+to\s+english\b", t_low):
        return "en"
    if re.search(r"\blanguage\s*:\s*en\b", t_low) or re.search(r"\blang\s*en\b", t_low):
        return "en"
    if re.search(r"\benglish\b", t_low) and not re.search(r"\brussian|русск", t_low):
        return "en"
    if t_low.strip() in ("en", "eng", "english please", "please english"):
        return "en"
    if re.search(r"\bна\s+английск\w*\b", t_low) or re.search(r"\bсделай\s+английск\w*\b", t_low):
        return "en"

    # Русский
    if re.search(r"\b(set|switch|change)\s+(the\s+)?language\s+to\s+russian\b", t_low):
        return "ru"
    if re.search(r"\blanguage\s*:\s*ru\b", t_low) or re.search(r"\blang\s*ru\b", t_low):
        return "ru"
    if re.search(r"\bрусск\w*\b", t_low) or re.search(r"\bна\s+русском\b", t_low) or re.search(r"\bсделай\s+русск\w*\b", t_low):
        return "ru"
    if t_low.strip() in ("ru", "russian", "по русски", "по-русски"):
        return "ru"

    return None

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
    text = DONATE_TEXT.get(lang, DONATE_TEXT["en"])
    bot.send_message(
        chat_id=chat_id,
        text=text,
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

# -------------------- Explorers (auto select) --------------------
EXPLORERS = [
    {"name": "Etherscan", "base": "https://api.etherscan.io/api", "key": ETHERSCAN_API_KEY, "module": "contract"},
    {"name": "PolygonScan", "base": "https://api.polygonscan.com/api", "key": POLYGONSCAN_API_KEY, "module": "contract"},
    {"name": "BscScan", "base": "https://api.bscscan.com/api", "key": BSCSCAN_API_KEY, "module": "contract"},
]

def pick_explorer() -> dict | None:
    for ex in EXPLORERS:
        if ex["key"]:
            return ex
    return None

def explorer_getsourcecode(address: str) -> dict:
    """
    Try explorers in order. Returns dict:
    {ok:bool, data:<result or None>, source:<name or None>, error:<str or None>, raw:<raw json>}
    """
    for ex in EXPLORERS:
        if not ex["key"]:
            continue
        try:
            q = {"module": ex["module"], "action": "getsourcecode", "address": address, "apikey": ex["key"]}
            r = requests.get(ex["base"], params=q, timeout=15)
            j = r.json()
            if str(j.get("status")) == "1":
                return {"ok": True, "data": (j.get("result") or [{}])[0], "source": ex["name"], "raw": j}


def resolve_proxy_impl(address: str) -> str:
    """
    Try to resolve implementation via getsourcecode meta, then fallback to EIP-1967 slot.
    """
    try:
        meta = etherscan_getsourcecode_flat(address) or {}
    except Exception:
        meta = {}
    impl = (meta.get("Implementation") or "").strip()
    if impl and re.match(r"^0x[a-fA-F0-9]{40}$", impl):
        return impl
    # Fallback: EIP-1967 implementation slot
    slot_hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbb"
    url = get_alchemy_rpc_url()
    if not url:
        return ""
    try:
        payload = {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[address, slot_hex, "latest"]}
        r = requests.post(url, json=payload, timeout=12)
        j = r.json() if r is not None else {}
        word = (j or {}).get("result", "") if isinstance(j, dict) else ""
        if isinstance(word, str) and word.startswith("0x"):
            h = word[2:].rjust(64, "0")
            cand = "0x" + h[-40:]
            if re.match(r"^0x[a-fA-F0-9]{40}$", cand) and cand.lower() != "0x" + "0"*40:
                return cand
    except Exception:
        pass
    return ""
        except Exception as e:
            app.logger.warning(f"explorer_getsourcecode error via {ex['name']}: {e}")
    return {"ok": False, "error": "no_explorer_ok", "source": None, "raw": None}

# -------------------- Alchemy helpers --------------------
# ----- Guardex minimal helpers -----
import os

# ===== Guardex: caching, retries, and RPC helpers =====
import time, random, json

class _TTLCache:
    def __init__(self):
        self._d = {}
    def get(self, key):
        v = self._d.get(key)
        if not v: return None
        val, exp = v
        if exp < time.time():
            self._d.pop(key, None)
            return None
        return val
    def set(self, key, val, ttl):
        self._d[key] = (val, time.time() + ttl)

_GX_CACHE = _TTLCache()

def _http_get(url, params=None, timeout=12, retries=3, base_sleep=0.5):
    for i in range(retries):
        try:
            r = requests.get(url, params=params, timeout=timeout)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        time.sleep(base_sleep * (2**i) + random.random()*0.2)
    return requests.get(url, params=params, timeout=timeout)

def _http_post(url, json_payload=None, timeout=12, retries=3, base_sleep=0.5):
    for i in range(retries):
        try:
            r = requests.post(url, json=json_payload, timeout=timeout)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        time.sleep(base_sleep * (2**i) + random.random()*0.2)
    return requests.post(url, json=json_payload, timeout=timeout)

def gx_eth_call(address: str, data_hex: str) -> str:
    """Minimal eth_call via Alchemy; cached for 5 minutes."""
    try:
        url = get_alchemy_rpc_url()
    except Exception:
        url = None
    if not url:
        return "0x"
    key = ("eth_call", address.lower(), data_hex.lower())
    cached = _GX_CACHE.get(key)
    if cached is not None:
        return cached
    payload = {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":address, "data":data_hex}, "latest"]}
    try:
        r = _http_post(url, json_payload=payload, timeout=12)
        res = (r.json() or {}).get("result", "0x")
    except Exception:
        res = "0x"
    _GX_CACHE.set(key, res, ttl=300)
    return res

def _hex_to_int(x: str) -> int:
    try:
        return int(x, 16)
    except Exception:
        return 0

def _word(hexstr: str, idx: int) -> str:
    """Return 32-byte word (as hex string without 0x) at index idx from a hex-encoded ABI output."""
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    start = idx*64
    end = start + 64
    return h[start:end].ljust(64, "0")

def _decode_uint(hexstr: str) -> int:
    w = _word(hexstr, 0)
    return _hex_to_int(w)

def _decode_bool(hexstr: str) -> bool:
    return bool(_decode_uint(hexstr))

def _decode_address(hexstr: str) -> str:
    w = _word(hexstr, 0)
    return "0x" + w[-40:]

def _try_decode_string(hexstr: str) -> str:
    """Try to decode dynamic string; fallback to bytes32 -> ascii; else return ''."""
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    if len(h) < 64:
        return ""
    try:
        off = _hex_to_int(h[0:64])
        if off == 32:
            length = _hex_to_int(h[64:128])
            data_start = 128
            data_end = data_start + ((length + 31)//32)*64
            data_hex = h[data_start:data_end]
            data_bytes = bytes.fromhex(data_hex[:length*2])
            return data_bytes.decode("utf-8", errors="ignore").strip("\x00")
    except Exception:
        pass
    try:
        b = bytes.fromhex(h[:64])
        s = b.decode("utf-8", errors="ignore").strip("\x00")
        if any(c.isalnum() for c in s):
            return s
    except Exception:
        pass
    return ""

# Common ERC20 selectors
SEL_NAME        = "0x06fdde03"
SEL_SYMBOL      = "0x95d89b41"
SEL_DECIMALS    = "0x313ce567"
SEL_TOTALSUPPLY = "0x18160ddd"
# Common access-control
SEL_OWNER       = "0x8da5cb5b"
# Pausable
SEL_PAUSED      = "0x5c975abb"

def gx_read_erc20_summary(address: str) -> dict:
    """Read common ERC20 fields via eth_call. Returns dict with optional keys."""
    out = {}
    try:
        r = gx_eth_call(address, SEL_SYMBOL)
        sym = _try_decode_string(r) or ""
        if sym: out["symbol"] = sym
    except Exception:
        pass
    try:
        r = gx_eth_call(address, SEL_DECIMALS)
        dec = _decode_uint(r)
        out["decimals"] = dec
    except Exception:
        pass
    try:
        r = gx_eth_call(address, SEL_TOTALSUPPLY)
        ts = _decode_uint(r)
        out["totalSupply"] = ts
    except Exception:
        pass
    try:
        r = gx_eth_call(address, SEL_PAUSED)
        if isinstance(r, str) and len(r) >= 66:
            out["paused"] = _decode_bool(r)
    except Exception:
        pass
    try:
        r = gx_eth_call(address, SEL_OWNER)
        if isinstance(r, str) and len(r) >= 66:
            out["owner"] = _decode_address(r)
    except Exception:
        pass
    return out

def gx_get_abi_text(address: str) -> str:
    """Fetch ABI (with TTL cache 15m)."""
    key = ("abi", address.lower())
    c = _GX_CACHE.get(key)
    if c is not None:
        return c
    try:
        res = explorer_getsourcecode(address)
        meta = res.get("data") or {}
        abi_text = meta.get("ABI") or ""
        if abi_text and abi_text != "Contract source code not verified":
            _GX_CACHE.set(key, abi_text, 900)
            return abi_text
    except Exception:
        pass
    try:
        abi_text = etherscan_getabi_direct(address)
        if abi_text and abi_text not in ("[]", "Contract source code not verified"):
            _GX_CACHE.set(key, abi_text, 900)
            return abi_text
    except Exception:
        pass
    try:
        for ex in EXPLORERS:
            if not ex.get("key"): continue
            params = {"module": ex["module"], "action": "getabi", "address": address, "apikey": ex["key"]}
            rr = _http_get(ex["base"], params=params, timeout=12)
            jj = rr.json()
            if str(jj.get("status")) == "1" and jj.get("result"):
                abi_text = jj.get("result")
                _GX_CACHE.set(key, abi_text, 900)
                return abi_text
    except Exception:
        pass
    _GX_CACHE.set(key, "[]", 300)
    return "[]"

def gx_has_role_fn(abi_text: str, fn_name: str) -> bool:
    try:
        return ('"name":"' + fn_name + '"') in abi_text or ('"name": "' + fn_name + '"') in abi_text
    except Exception:
        return False

def etherscan_getsourcecode_flat(address: str) -> dict:
    """
    Direct Etherscan getsourcecode using ETHERSCAN_API_KEY; fallback to explorer_getsourcecode.
    """
    key = os.getenv("ETHERSCAN_API_KEY", "")
    if key:
        try:
            url = "https://api.etherscan.io/api"
            params = {"module":"contract","action":"getsourcecode","address":address,"apikey":key}
            r = requests.get(url, params=params, timeout=12)
            j = r.json()
            if str(j.get("status")) == "1" and j.get("result"):
                first = j["result"][0]
                if isinstance(first, dict):
                    return first
        except Exception:
            pass
    try:
        res = explorer_getsourcecode(address)
        data = res.get("data") or {}
        if isinstance(data, list) and data:
            data = data[0]
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def guardex_parse_name_compiler(meta: dict) -> tuple[str,str]:
    """
    Try multiple ways to extract ContractName and CompilerVersion.
    """
    name = meta.get("ContractName") or meta.get("ContractName ") or meta.get("contractName") or "Unknown"
    ver  = meta.get("CompilerVersion") or meta.get("Compiler Version") or meta.get("compilerVersion") or "-"
    try:
        sc = meta.get("SourceCode") or ""
        if isinstance(sc, str) and sc.startswith("{{") and sc.endswith("}}"):
            sc = sc[1:-1]
        if isinstance(sc, str) and sc.strip().startswith("{"):
            import json
            j = json.loads(sc)
            if isinstance(j, dict):
                settings = j.get("settings") or {}
                ct = settings.get("compilationTarget") or {}
                if isinstance(ct, dict) and ct and name == "Unknown":
                    try:
                        name = list(ct.values())[0] or name
                    except Exception:
                        pass
                compiler = j.get("compiler") or {}
                if isinstance(compiler, dict) and (ver in ("-", "", None)):
                    ver = compiler.get("version") or ver
        if name == "Unknown":
            import re as _re
            m = _re.search(r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b", sc or "")
            if m:
                name = m.group(2)
    except Exception:
        pass
    return name, ver

def get_alchemy_rpc_url() -> str | None:
    if not ALCHEMY_API_KEY:
        return None
    return f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

def _rpc(payload: dict) -> dict:
    url = get_alchemy_rpc_url()
    if not url:
        return {"error": "ALCHEMY_API_KEY missing"}
    try:
        resp = requests.post(url, json=payload, timeout=20, headers={"Content-Type":"application/json"})
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def _to_eth(wei_hex_or_int) -> Decimal:
    try:
        if isinstance(wei_hex_or_int, str):
            wei = int(wei_hex_or_int, 16) if wei_hex_or_int.startswith("0x") else int(wei_hex_or_int)
        else:
            wei = int(wei_hex_or_int or 0)
        return Decimal(wei) / Decimal(10**18)
    except Exception:
        return Decimal(0)

def _short(addr: str) -> str:
    if not addr or len(addr) < 10: return addr
    return f"{addr[:6]}…{addr[-4:]}"

def alchemy_get_eth_balance(address: str) -> dict:
    j = _rpc({"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[address,"latest"]})
    if "error" in j:
        return {"ok": False, "error": j.get("error")}
    val = j.get("result")
    return {"ok": True, "eth": _to_eth(val)}

def alchemy_get_erc20_balances(address: str) -> dict:
    # Docs: alchemy_getTokenBalances (returns list of contract addresses + token balances (in hex))
    j = _rpc({"jsonrpc":"2.0","id":1,"method":"alchemy_getTokenBalances","params":[address]})
    if "error" in j:
        return {"ok": False, "error": j.get("error")}
    res = j.get("result") or {}
    out = []
    for t in (res.get("tokenBalances") or [])[:15]:
        contract = t.get("contractAddress")
        tokenBalHex = t.get("tokenBalance")
        out.append({"contract": contract, "balance_hex": tokenBalHex})
    return {"ok": True, "tokens": out}

def alchemy_get_asset_transfers(address: str, max_count: int = 10) -> dict:
    # Docs: alchemy_getAssetTransfers with category ["external","internal","erc20","erc721","erc1155"]
    params = [{
        "fromBlock": "0x0",
        "toBlock": "latest",
        "toAddress": address,
        "category": ["external","internal","erc20","erc721","erc1155"],
        "withMetadata": True,
        "excludeZeroValue": True,
        "maxCount": hex(max_count)
    }]
    j_in = _rpc({"jsonrpc":"2.0","id":1,"method":"alchemy_getAssetTransfers","params": params})
    if "error" in j_in:
        return {"ok": False, "error": j_in.get("error")}
    in_tx = (j_in.get("result") or {}).get("transfers", [])

    params_out = [{
        "fromBlock": "0x0",
        "toBlock": "latest",
        "fromAddress": address,
        "category": ["external","internal","erc20","erc721","erc1155"],
        "withMetadata": True,
        "excludeZeroValue": True,
        "maxCount": hex(max_count)
    }]
    j_out = _rpc({"jsonrpc":"2.0","id":1,"method":"alchemy_getAssetTransfers","params": params_out})
    if "error" in j_out:
        return {"ok": False, "error": j_out.get("error")}
    out_tx = (j_out.get("result") or {}).get("transfers", [])

    txs = (in_tx + out_tx)[:max_count]
    # Normalize
    norm = []
    for t in txs:
        try:
            ts = t.get("metadata", {}).get("blockTimestamp")
            # ts is ISO string like "2025-08-14T12:34:56Z"
            date_s = ts.replace("T", " ").replace("Z","") if ts else ""
            frm = t.get("from")
            to  = t.get("to")
            val = t.get("value")
            asset = t.get("asset")
            cat = t.get("category")
            # status not directly available; mark external as success by default
            success = True
            # value might be None for NFTs; if numeric, show
            val_str = ""
            if isinstance(val, (int, float, str)):
                val_str = str(val)
            elif val is None and asset:
                val_str = asset
            norm.append({
                "date": date_s,
                "from": frm,
                "to": to,
                "value": val_str,
                "asset": asset or "",
                "category": cat or "",
                "status": "✅" if success else "❌"
            })
        except Exception:
            continue
    return {"ok": True, "txs": norm}

# -------------------- Etherscan/Explorers: contract analysis --------------------
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
    res = explorer_getsourcecode(address)
    if not res.get("ok"):
        facts["error"] = res.get("error") or "explorer_error"
        return facts
    info = (res.get("data") or {})

    facts["name"]            = info.get("ContractName") or info.get("Proxy") or "unknown"
    facts["sourceverified"]  = bool(info.get("SourceCode"))
    facts["impl"]            = info.get("Implementation") or ""
    facts["proxy"]           = (info.get("Proxy") == "1")
    facts["compilerVersion"] = info.get("CompilerVersion") or ""
    abi_json                 = info.get("ABI") or "[]"
    facts["via"]             = res.get("source") or ""

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
    if facts.get("via"):
        lines.append(f"🔎 {L['via']}: {facts.get('via')}")
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
        params = {
            "engine": "google",
            "q": query,
            "api_key": SERPAPI_KEY,
            "hl": "en" if lang == "en" else "ru",
            "num": "5"
        }
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
              "ru": f"Свежие сниппеты из веба (UTC {date_str}):"}.get(lang, f"Fresh web snippets (UTC {date_str}):")
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
        return {"en":"Price fetch error.","ru":"Ошибка получения цены."}.get(lang, "Price fetch error.")
    name_map = {
        "bitcoin":"BTC","ethereum":"ETH","solana":"SOL","the-open-network":"TON",
        "tether":"USDT","usd-coin":"USDC","binancecoin":"BNB","arbitrum":"ARB","optimism":"OP",
        "cardano":"ADA","ripple":"XRP","avalanche-2":"AVAX","tron":"TRX","dogecoin":"DOGE","matic-network":"MATIC",
        "sui":"SUI","apt":"APT"
    }
    lines = {"en":["🔔 Spot prices (USD):"],"ru":["🔔 Спот-цены (USD):"]}.get(lang, ["🔔 Spot prices (USD):"])
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
        return {"en":"No price data.","ru":"Нет данных по ценам."}.get(lang, "No price data.")
    try:
        all_ts = [v.get("last_updated_at") for v in data.values() if isinstance(v, dict) and v.get("last_updated_at")]
        if all_ts:
            dt = datetime.utcfromtimestamp(max(all_ts)).strftime("%Y-%m-%d %H:%M UTC")
            lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}."}.get(lang, f"\nAs of {dt}."))
    except Exception:
        pass
    return "\n".join(lines)

# UI для цен
def _t_refresh(lang: str) -> str:
    return {"en":"🔄 Refresh","ru":"🔄 Обновить"}.get(lang, "🔄 Refresh")

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
            {"en":"No market data.","ru":"Нет рыночных данных."}.get(lang, "No market data."),
            []
        )
    lines = {
        "en": ["🏆 Top-10 by market cap (USD):"],
        "ru": ["🏆 Топ-10 по капитализации (USD):"],
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
    lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}."}.get(lang, f"\nAs of {dt}."))
    return ("\n".join(lines), ids)

def build_top10_keyboard(chat_id: int, ids: list[str], lang: str) -> InlineKeyboardMarkup:
    token = store_price_ids(chat_id, ids)
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t_refresh(lang), callback_data=f"prf:{token}")]])

# -------------------- GAS / F&G / BTC DOM --------------------

def fetch_gas_alchemy() -> dict | None:
    """
    Robust gas via Alchemy eth_feeHistory / eth_gasPrice.
    Returns gwei floats: safe, propose, fast, base.
    """
    if not ALCHEMY_API_KEY:
        return None
    try:
        url = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
        # Try fee history with percentiles
        r = requests.post(url, json={
            "jsonrpc":"2.0","id":1,
            "method":"eth_feeHistory",
            "params":[5, "latest", [10, 50, 90]]
        }, timeout=10)
        res = (r.json() or {}).get("result", {})

        base_hex = res.get("baseFeePerGas") or []
        base_next = int(base_hex[-1], 16) if base_hex else None
        rewards = res.get("reward") or []
        last_reward = rewards[-1] if rewards else []

        h2g = lambda h: (int(h, 16) / 1e9) if h else 0.0
        base_g = (int(base_next) / 1e9) if base_next is not None else None
        p10 = h2g(last_reward[0]) if len(last_reward) > 0 else 0.0
        p50 = h2g(last_reward[1]) if len(last_reward) > 1 else 0.0
        p90 = h2g(last_reward[2]) if len(last_reward) > 2 else 0.0

        if base_g is None or p50 == 0.0:
            # Fallback to gasPrice
            r2 = requests.post(url, json={
                "jsonrpc":"2.0","id":2,"method":"eth_gasPrice","params":[]
            }, timeout=10)
            gp = int((r2.json() or {}).get("result","0x0"), 16) / 1e9
            if gp == 0:
                return None
            return {"source":"alchemy","safe":gp*0.9,"propose":gp,"fast":gp*1.1,"base":gp}
        return {"source":"alchemy","safe":base_g + p10,"propose":base_g + p50,"fast":base_g + p90,"base":base_g}
    except Exception:
        return None


def fetch_gas_cloudflare() -> dict | None:
    """
    Public fallback via Cloudflare Ethereum gateway (no API key).
    """
    try:
        url = "https://cloudflare-eth.com"
        r = requests.post(url, json={
            "jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":[5,"latest",[10,50,90]]
        }, timeout=10)
        res = (r.json() or {}).get("result", {})
        base_hex = res.get("baseFeePerGas") or []
        base_next = int(base_hex[-1], 16) if base_hex else None
        rewards = res.get("reward") or []
        last_reward = rewards[-1] if rewards else []

        h2g = lambda h: (int(h, 16) / 1e9) if h else 0.0
        base_g = (int(base_next) / 1e9) if base_next is not None else None
        p10 = h2g(last_reward[0]) if len(last_reward) > 0 else 0.0
        p50 = h2g(last_reward[1]) if len(last_reward) > 1 else 0.0
        p90 = h2g(last_reward[2]) if len(last_reward) > 2 else 0.0

        if base_g is None:
            r2 = requests.post(url, json={
                "jsonrpc":"2.0","id":2,"method":"eth_gasPrice","params":[]
            }, timeout=10)
            gp = int((r2.json() or {}).get("result","0x0"), 16) / 1e9
            if gp == 0:
                return None
            return {"source":"cloudflare","safe":gp*0.9,"propose":gp,"fast":gp*1.1,"base":gp}
        return {"source":"cloudflare","safe":base_g + p10,"propose":base_g + p50,"fast":base_g + p90,"base":base_g}
    except Exception:
        return None

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
    for fn in (fetch_gas_alchemy, fetch_gas_cloudflare, fetch_gas_etherscan, fetch_gas_ethgasstation, fetch_gas_etherchain):
        data = fn()
        if data and data.get("propose"):
            return data
    return {"error": "gas_unavailable"}

def format_gas_message(data: dict, lang: str) -> str:
    if "error" in data:
        return {"en":"Gas data unavailable.","ru":"Данные по газу недоступны."}.get(lang, "Gas data unavailable.")
    src = data.get("source", "n/a")
    lines = {
        "en": ["⛽ Ethereum gas (gwei):"],
        "ru": ["⛽ Газ Ethereum (gwei):"],
    }.get(lang, ["⛽ Ethereum gas (gwei):"])
    lines.append(f"Safe: {data.get('safe'):.1f}")
    lines.append(f"Propose: {data.get('propose'):.1f}")
    lines.append(f"Fast: {data.get('fast'):.1f}")
    if data.get("base") is not None:
        lines.append(f"Base fee: {data.get('base'):.1f}")
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines.append({"en":f"\nSource: {src}. As of {dt}.",
                  "ru":f"\nИсточник: {src}. По состоянию на {dt}."}.get(lang, f"\nSource: {src}. As of {dt}."))
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
                "ru":"Индекс страха и жадности недоступен."}.get(lang, "Fear & Greed data unavailable.")
    val = d["value"]
    cls = d.get("classification","")
    try:
        ts = int(d.get("timestamp") or 0)
        dt = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    hdr = {"en":"😨/😎 Crypto Fear & Greed Index:",
           "ru":"😨/😎 Индекс страха и жадности:"}.get(lang, "😨/😎 Crypto Fear & Greed Index:")
    return f"{hdr}\n{val} ({cls})\n\n" + {"en":f"As of {dt}.","ru":f"По состоянию на {dt}."}.get(lang, f"As of {dt}.")

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
                "ru":"Доминация BTC недоступна."}.get(lang, "BTC dominance unavailable.")
    dom = float(d["dominance"])
    mcap = d.get("mcap_usd")
    lines = {
        "en": [f"🟧 BTC dominance: {dom:.2f}%"],
        "ru": [f"🟧 Доминация BTC: {dom:.2f}%"],
    }.get(lang, [f"🟧 BTC dominance: {dom:.2f}%"])
    if isinstance(mcap, (int, float)):
        lines.append({"en":f"Total crypto mcap: ${mcap:,.0f}",
                      "ru":f"Общая капитализация рынка: ${mcap:,.0f}"}[lang])
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines.append({"en":f"\nAs of {dt}.","ru":f"\nПо состоянию на {dt}."}.get(lang, f"\nAs of {dt}."))
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


@app.route("/webhook/<secret>", methods=["POST","GET"])
def webhook_with_secret(secret):
    # Allow GET for quick checks
    if request.method == "GET":
        return "ok"

    # Path-secret check
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "bad secret"}), 403

    update = request.get_json(force=True, silent=True) or {}

    # Callback buttons
    if "callback_query" in update:
        cq = update["callback_query"]
        data = cq.get("data") or ""
        chat_id = cq.get("message", {}).get("chat", {}).get("id")
        try:
            if data == "qr_eth":
                send_qr(chat_id, "ETH", ETH_DONATE_ADDRESS)
                bot.answer_callback_query(cq.get("id"), text="QR ETH sent")
            elif data == "qr_ton":
                send_qr(chat_id, "TON", TON_DONATE_ADDRESS)
                bot.answer_callback_query(cq.get("id"), text="QR TON sent")
            elif data == "qr_sol":
                send_qr(chat_id, "SOL", SOL_DONATE_ADDRESS)
                bot.answer_callback_query(cq.get("id"), text="QR SOL sent")
            elif data == "addr_eth":
                bot.send_message(chat_id=chat_id, text=f"ETH: `{ETH_DONATE_ADDRESS}`", parse_mode="Markdown")
                bot.answer_callback_query(cq.get("id"), text="ETH address sent")
            elif data == "addr_ton":
                bot.send_message(chat_id=chat_id, text=f"TON: `{TON_DONATE_ADDRESS}`", parse_mode="Markdown")
                bot.answer_callback_query(cq.get("id"), text="TON address sent")
            elif data == "addr_sol":
                bot.send_message(chat_id=chat_id, text=f"SOL: `{SOL_DONATE_ADDRESS}`", parse_mode="Markdown")
                bot.answer_callback_query(cq.get("id"), text="SOL address sent")
            elif data.startswith("prf:"):
                token = data.split(":", 1)[1].strip()
                ids = resolve_price_ids(chat_id, token) or ["bitcoin","ethereum","solana","the-open-network"]
                lang_cq = get_lang_override(chat_id) or DEFAULT_LANG
                data_now = coingecko_prices(ids, vs="usd")
                msg_now = format_prices_message(data_now, lang_cq, vs="usd")
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

    # Regular messages
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return "ok"

    text = (msg.get("text") or msg.get("caption") or "").strip()
    t_low = (text or "").lower()


    # ===== Guardex: /impl /abi /status =====
    if t_low.startswith("/impl"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /impl <ETH address>")
            return "ok"
        addr = parts[1]
        meta = etherscan_getsourcecode_flat(addr) or {}
        is_proxy = (meta.get("Proxy") == "1") or bool(meta.get("Implementation"))
        if not is_proxy:
            bot.send_message(chat_id=chat_id, text="Not a proxy (no implementation).")
            return "ok"
        impl = resolve_proxy_impl(addr)
        if not impl:
            bot.send_message(chat_id=chat_id, text="Proxy detected, but implementation not found (EIP-1967 slot empty).")
            return "ok"
        im_meta = etherscan_getsourcecode_flat(impl) or {}
        try:
            name, ver = guardex_parse_name_compiler(im_meta)
        except Exception:
            name = im_meta.get("ContractName") or "Unknown"
            ver  = im_meta.get("CompilerVersion") or "-"
        abi_text = gx_get_abi_text(impl)
        verified_bool = bool(abi_text and abi_text != "Contract source code not verified")
        v_mark = "✅" if verified_bool else "❌"
        lines = [
            "🧭 Network: ethereum",
            f"🔗 Proxy: {addr}",
            f"🧷 Implementation: {impl}",
            f"🏷️ Contract name: {name}",
            f"✅ Source verified: {v_mark}",
            f"🧪 Compiler: {ver}",
            "🔎 Data source: Etherscan"
        ]
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("Etherscan (Proxy)", url=f"https://etherscan.io/address/{addr}"),
            InlineKeyboardButton("Etherscan (Impl)",  url=f"https://etherscan.io/address/{impl}")
        ]])
        bot.send_message(chat_id=chat_id, text="\n".join(lines), reply_markup=kb, disable_web_page_preview=True)
        return "ok"

    if t_low.startswith("/abi"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /abi <ETH address>")
            return "ok"
        addr = parts[1]
        meta = etherscan_getsourcecode_flat(addr) or {}
        target = addr
        if (meta.get("Proxy") == "1") or bool(meta.get("Implementation")):
            impl = resolve_proxy_impl(addr)
            if impl: target = impl
        abi_text = gx_get_abi_text(target) or "[]"
        if len(abi_text) > 3500:
            preview = abi_text[:3400] + "..."
            link = f"https://etherscan.io/address/{target}#code"
            bot.send_message(chat_id=chat_id, text=f"ABI for {target} (truncated):\n\n<pre>{html.escape(preview)}</pre>\n\nFull: {link}", parse_mode="HTML", disable_web_page_preview=True)
        else:
            bot.send_message(chat_id=chat_id, text=f"<pre>{html.escape(abi_text)}</pre>", parse_mode="HTML")
        return "ok"

    if t_low.startswith("/status"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /status <ETH address>")
            return "ok"
        addr = parts[1]
        meta = etherscan_getsourcecode_flat(addr) or {}
        is_proxy = (meta.get("Proxy") == "1") or bool(meta.get("Implementation"))
        impl = resolve_proxy_impl(addr) if is_proxy else ""
        state_target = addr  # storage lives on proxy
        abi_target = (impl if impl else addr)

        summary = gx_read_erc20_summary(state_target)
        sym = summary.get("symbol") or "-"
        dec = summary.get("decimals")
        dec_s = str(dec) if isinstance(dec, int) else "-"
        ts = summary.get("totalSupply")
        ts_s = str(ts) if isinstance(ts, int) else "-"
        paused = summary.get("paused")
        paused_s = "—" if (paused is None) else ("Yes" if paused else "No")
        owner = summary.get("owner") or "—"
        if owner in ("0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000001", "—"):
            r2 = gx_eth_call(state_target, "0x893d20e8")  # getOwner()
            if isinstance(r2, str) and len(r2) >= 66:
                owner = _decode_address(r2)

        # Humanize TotalSupply
        ts_h = ts_s
        try:
            if isinstance(ts, int) and isinstance(dec, int) and dec <= 36 and ts is not None:
                getcontext().prec = 50
                ts_h = f"{(Decimal(ts) / (Decimal(10) ** dec)):.{min(dec, 6)}f}"
        except Exception:
            pass

        abi_text = gx_get_abi_text(abi_target)
        roles_presence = []
        for fn in ["owner", "masterMinter", "pauser", "blacklister", "rescuer"]:
            roles_presence.append(f"{fn}: {'✅' if gx_has_role_fn(abi_text, fn) else '—'}")
        roles_line = " | ".join(roles_presence)

        lines = [
            "🧭 Network: ethereum",
            f"🔗 Address: {addr}",
            f"🧩 Proxy: {'✅' if is_proxy else '❌'}" + (f"  →  Implementation: {impl}" if is_proxy and impl else ""),
            f"🏷️ Symbol: {sym}",
            f"🔢 Decimals: {dec_s}",
            f"💰 TotalSupply (raw): {ts_s}",
            f"💰 TotalSupply (human): {ts_h}",
            f"⏸️ Paused: {paused_s}",
            f"👤 Owner: {owner}",
            f"🔐 Roles: {roles_line}",
            "🔎 Data source: Etherscan / Alchemy RPC"
        ]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open on Etherscan", url=f"https://etherscan.io/address/{abi_target}")]])
        bot.send_message(chat_id=chat_id, text="\n".join(lines), reply_markup=kb, disable_web_page_preview=True)
        return "ok"
    cur_lang = get_lang_override(chat_id) or DEFAULT_LANG

    # /start
    if t_low in ("/start", "start"):
        start_lang = get_lang_override(chat_id) or DEFAULT_LANG
        bot.send_message(chat_id=chat_id, text=WELCOME.get(start_lang, WELCOME["en"]), reply_markup=build_donate_keyboard())
        return "ok"

    # Donations
    if t_low in ("/donate", "donate", "tip", "/tip"):
        bot.send_message(chat_id=chat_id, text="Thanks for considering a donation! Use the Donate button below.")
        return "ok"

    # Top-10
    if (
        t_low.strip() in ("top10", "top ten", "top-ten", "top coins") or
        re.search(r"\btop\s*-?\s*10\b", t_low) or
        re.search(r"\bshow\s+top\s+coins\b", t_low)
    ):
        mkts = coingecko_top_market(10)
        msg_out, ids = format_top10(mkts, lang=cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_top10_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /price
    if t_low.startswith("/price"):
        tail = text.split(None, 1)[1] if len(text.split()) > 1 else ""
        query_text = tail or "BTC ETH SOL TON"
        ids = _cg_ids_from_text(query_text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=cur_lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /top10 (compat)
    if t_low.startswith("/top10"):
        mkts = coingecko_top_market(10)
        msg_out, ids = format_top10(mkts, lang=cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_top10_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /gas
    if t_low.startswith("/gas") or t_low == "gas":
        msg_out = format_gas_message(get_eth_gas(), cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_gas_keyboard(cur_lang))
        return "ok"

    # /feargreed | /fng
    if t_low.startswith("/feargreed") or t_low == "/fng" or t_low == "feargreed" or t_low == "fng":
        d = fetch_fear_greed()
        msg_out = format_fear_greed(d, cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_fng_keyboard(cur_lang))
        return "ok"

    # /btcdom
    if t_low.startswith("/btcdom") or t_low == "btcdom":
        d = fetch_btc_dominance()
        msg_out = format_btc_dominance(d, cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_btcdom_keyboard(cur_lang))
        return "ok"

    # /balance
    if t_low.startswith("/balance"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /balance <ETH address>")
            return "ok"
        addr = parts[1]
        if not ALCHEMY_API_KEY:
            bot.send_message(chat_id=chat_id, text="Balances are temporarily unavailable (set ALCHEMY_API_KEY).")
            return "ok"
        eth_bal = alchemy_get_eth_balance(addr)
        if not eth_bal.get("ok"):
            bot.send_message(chat_id=chat_id, text="Failed to fetch balance.")
            return "ok"
        tokens = alchemy_get_erc20_balances(addr)
        lines = [f"💰 Balance for {_short(addr)}:"]
        lines.append(f"ETH: {eth_bal.get('eth')}")
        if tokens.get("ok"):
            tlist = tokens.get("tokens") or []
            if tlist:
                lines.append("ERC-20 (raw, first 10):")
                for t in tlist[:10]:
                    lines.append(f"- {t.get('contract')} : {t.get('balance_hex')}")
        bot.send_message(chat_id=chat_id, text="\n".join(lines))
        return "ok"

    # /txs
    if t_low.startswith("/txs"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /txs <ETH address>")
            return "ok"
        addr = parts[1]
        if not ALCHEMY_API_KEY:
            bot.send_message(chat_id=chat_id, text="Transactions are temporarily unavailable (set ALCHEMY_API_KEY).")
            return "ok"
        hist = alchemy_get_asset_transfers(addr, max_count=10)
        if not hist.get("ok"):
            bot.send_message(chat_id=chat_id, text="Failed to fetch transactions.")
            return "ok"
        rows = hist.get("txs") or []
        if not rows:
            bot.send_message(chat_id=chat_id, text="No recent transfers found.")
            return "ok"
        header = "# | Date (UTC)        | From → To                | Value | Status"
        lines = [header]
        for i, r in enumerate(rows, start=1):
            ln = f"{i} | {str(r.get('date'))[:16]:16} | {_short(r.get('from') or '')} → {_short(r.get('to') or '')} | {r.get('value') or ''} | {r.get('status')}"
            lines.append(ln)
        bot.send_message(chat_id=chat_id, text="\n".join(lines))
        return "ok"

    # /scan
    if t_low.startswith("/scan"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /scan <ETH address>")
            return "ok"
        address = parts[1]
        facts = analyze_eth_contract(address)
        report = format_report(facts, "en")
        bot.send_message(chat_id=chat_id, text=report, reply_markup=build_donate_keyboard())
        return "ok"

    
    # /impl <address> — show implementation metadata via direct Etherscan + fallbacks
    if t_low.startswith("/impl"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /impl <ETH address>")
            return "ok"
        addr = parts[1]
        # detect proxy from aggregator meta (fast)
        meta_res = explorer_getsourcecode(addr)
        meta = meta_res.get("data") or {}
        is_proxy = (meta.get("Proxy") == "1") or bool(meta.get("Implementation"))
        if not is_proxy:
            bot.send_message(chat_id=chat_id, text="Not a proxy (no implementation).")
            return "ok"
        # resolve implementation: prefer explorer hint, else EIP-1967
        impl = (meta.get("Implementation") or "").strip()
        if not (impl.startswith("0x") and len(impl) == 42):
            # fallback to slot
            try:
                slot_hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbb"
                rpc = get_alchemy_rpc_url()
                word = "0x" + "00"*32
                if rpc:
                    payload = {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]}
                    resp = requests.post(rpc, json=payload, timeout=12)
                    word = (resp.json() or {}).get("result", word)
                h = (word[2:] if isinstance(word, str) and word.startswith("0x") else "").rjust(64, "0")
                impl = "0x" + h[-40:] if h else ""
            except Exception:
                impl = ""
        if not impl or impl.lower() == "0x" + "0"*40:
            bot.send_message(chat_id=chat_id, text="Proxy detected, but implementation not found (EIP-1967 slot empty).")
            return "ok"
        im_meta = etherscan_getsourcecode_flat(impl)
        name, ver = guardex_parse_name_compiler(im_meta)
        # ABI-based verification; if empty ABI, try explicit path in your codebase if exists
        abi_text = im_meta.get("ABI") or ""
        if not abi_text or abi_text == "Contract source code not verified":
            # fallback: ask explorer for ABI via existing code path if any
            try:
                q = {"module": meta.get("module") or "contract", "action": "getabi", "address": impl, "apikey": os.getenv("ETHERSCAN_API_KEY","")}
                r = requests.get("https://api.etherscan.io/api", params=q, timeout=12)
                j = r.json()
                if str(j.get("status")) == "1" and j.get("result"):
                    abi_text = j.get("result")
            except Exception:
                pass
        verified = bool(abi_text and abi_text != "Contract source code not verified")
        v_mark = "✅" if verified else "❌"
        lines = [
            "🧭 Network: ethereum",
            f"🔗 Proxy: {addr}",
            f"🧷 Implementation: {impl}",
            f"🏷️ Contract name: {name}",
            f"✅ Source verified: {v_mark}",
            f"🧪 Compiler: {ver}",
            f"🔎 Data source: Etherscan"
        ]
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("Etherscan (Proxy)", url=f"https://etherscan.io/address/{addr}"),
            InlineKeyboardButton("Etherscan (Impl)",  url=f"https://etherscan.io/address/{impl}")
        ]])
        bot.send_message(chat_id=chat_id, text="\n".join(lines), reply_markup=kb, disable_web_page_preview=True)
        return "ok"

    # /abi <address> — implementation ABI if proxy
    if t_low.startswith("/abi"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /abi <ETH address>")
            return "ok"
        addr = parts[1]
        meta_res = explorer_getsourcecode(addr)
        meta = meta_res.get("data") or {}
        target = addr
        if (meta.get("Proxy") == "1") or bool(meta.get("Implementation")):
            # resolve as above
            impl = (meta.get("Implementation") or "").strip()
            if not (impl.startswith("0x") and len(impl) == 42):
                try:
                    slot_hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbb"
                    rpc = get_alchemy_rpc_url()
                    word = "0x" + "00"*32
                    if rpc:
                        payload = {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]}
                        resp = requests.post(rpc, json=payload, timeout=12)
                        word = (resp.json() or {}).get("result", word)
                    h = (word[2:] if isinstance(word, str) and word.startswith("0x") else "").rjust(64, "0")
                    impl = "0x" + h[-40:] if h else ""
                except Exception:
                    impl = ""
            if impl and impl.lower() != "0x" + "0"*40:
                target = impl
        # ABI via Etherscan direct
        try:
            key = os.getenv("ETHERSCAN_API_KEY","")
            abi_text = "[]"
            if key:
                url = "https://api.etherscan.io/api"
                params = {"module":"contract","action":"getabi","address":target,"apikey":key}
                rr = requests.get(url, params=params, timeout=12)
                jj = rr.json()
                if str(jj.get("status")) == "1" and jj.get("result"):
                    abi_text = jj.get("result")
            if len(abi_text) > 3500:
                preview = abi_text[:3400] + "..."
                link = f"https://etherscan.io/address/{target}#code"
                bot.send_message(chat_id=chat_id, text=f"ABI for {target} (truncated):\n\n<pre>{html.escape(preview)}</pre>\n\nFull: {link}", parse_mode="HTML", disable_web_page_preview=True)
            else:
                bot.send_message(chat_id=chat_id, text=f"<pre>{html.escape(abi_text)}</pre>", parse_mode="HTML")
        except Exception:
            bot.send_message(chat_id=chat_id, text="Failed to fetch ABI from Etherscan.")
        return "ok"

    # /status <address> — summarize token & roles (auto-resolve proxy -> implementation)
    if t_low.startswith("/status"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text="Usage: /status <ETH address>")
            return "ok"
        addr = parts[1]
        meta_res = explorer_getsourcecode(addr)
        meta = meta_res.get("data") or {}
        is_proxy = (meta.get("Proxy") == "1") or bool(meta.get("Implementation"))
        target = addr
        impl = ""
        if is_proxy:
            impl = (meta.get("Implementation") or "").strip()
            if not (impl.startswith("0x") and len(impl) == 42):
                try:
                    slot_hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbb"
                    rpc = get_alchemy_rpc_url()
                    word = "0x" + "00"*32
                    if rpc:
                        payload = {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]}
                        resp = _http_post(rpc, json_payload=payload, timeout=12)
                        word = (resp.json() or {}).get("result", word)
                    h = (word[2:] if isinstance(word, str) and word.startswith("0x") else "").rjust(64, "0")
                    impl = "0x" + h[-40:] if h else ""
                except Exception:
                    impl = ""
            if impl and impl.lower() != "0x" + "0"*40:
                target = impl

        summary = gx_read_erc20_summary(target)
        sym = summary.get("symbol") or "-"
        dec = summary.get("decimals"); dec_s = str(dec) if isinstance(dec, int) else "-"
        ts = summary.get("totalSupply"); ts_s = str(ts) if isinstance(ts, int) else "-"
        paused = summary.get("paused"); paused_s = "—" if (paused is None) else ("Yes" if paused else "No")
        owner = summary.get("owner") or "—"

        abi_text = gx_get_abi_text(target)
        roles_presence = []
        for fn in ["owner", "masterMinter", "pauser", "blacklister", "rescuer"]:
            roles_presence.append(f"{fn}: {'✅' if gx_has_role_fn(abi_text, fn) else '—'}")
        roles_line = " | ".join(roles_presence)

        lines = [
            "🧭 Network: ethereum",
            f"🔗 Address: {addr}",
            f"🧩 Proxy: {'✅' if is_proxy else '❌'}" + (f"  →  Implementation: {target}" if is_proxy else ""),
            f"🏷️ Symbol: {sym}",
            f"🔢 Decimals: {dec_s}",
            f"💰 TotalSupply: {ts_s}",
            f"⏸️ Paused: {paused_s}",
            f"👤 Owner: {owner}",
            f"🔐 Roles: {roles_line}",
            "🔎 Data source: Etherscan / Alchemy RPC"
        ]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open on Etherscan", url=f"https://etherscan.io/address/{target}")]])
        bot.send_message(chat_id=chat_id, text="\n".join(lines), reply_markup=kb, disable_web_page_preview=True)
        return "ok"
# Address mention => explorer report
    m = ADDR_RE.search(text)
    if m:
        address = m.group(0)
        facts = analyze_eth_contract(address)
        report = format_report(facts, cur_lang)
        bot.send_message(chat_id=chat_id, text=report, reply_markup=build_donate_keyboard())
        return "ok"

    # Natural language price question
    if is_price_query(text):
        ids = _cg_ids_from_text(text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=cur_lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # Empty text => show welcome
    if not text:
        start_lang = get_lang_override(chat_id) or DEFAULT_LANG
        bot.send_message(chat_id=chat_id, text=WELCOME.get(start_lang, WELCOME["en"]), reply_markup=build_donate_keyboard())
        return "ok"

    # Fallback AI reply
    answer = ai_reply(text, cur_lang, chat_id)
    bot.send_message(chat_id=chat_id, text=answer, reply_markup=build_donate_keyboard())
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
    cur_lang = get_lang_override(chat_id) or detect_lang(text, None, chat_id)

    # Команды /start и без слэша
    if t_low in ("/start", "start"):
        start_lang = get_lang_override(chat_id) or DEFAULT_LANG
        bot.send_message(chat_id=chat_id, text=WELCOME.get(start_lang, WELCOME["en"]),
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        send_donate_message(chat_id, start_lang)
        return "ok"

    # Натуральное переключение языка без слэша
    lang_nl = maybe_set_language_from_text(t_low)
    if lang_nl in ("en", "ru"):
        set_lang_override(chat_id, lang_nl)
        bot.send_message(chat_id=chat_id, text={"en":"Language set.","ru":"Язык установлен."}[lang_nl])
        return "ok"

    # Принудительная установка языка: /lang en|ru
    if t_low.startswith("/lang"):
        parts = t_low.split()
        if len(parts) >= 2 and parts[1] in ("en","ru"):
            set_lang_override(chat_id, parts[1])
            bot.send_message(chat_id=chat_id, text={"en":"Language set.","ru":"Язык установлен."}.get(parts[1], "Language set."))
        else:
            bot.send_message(chat_id=chat_id, text="Usage: /lang en | ru")
        return "ok"

    # Донаты (и без слэша тоже)
    if t_low in ("/donate", "donate", "донат", "/tip", "tip"):
        send_donate_message(chat_id, cur_lang)
        return "ok"

    # TOP-10 — натуральные фразы без слэша
    if (
        t_low.strip() in ("top10", "top ten", "top-ten", "top coins") or
        re.search(r"\btop\s*-?\s*10\b", t_low) or
        re.search(r"\bshow\s+top\s+coins\b", t_low)
    ):
        mkts = coingecko_top_market(10)
        msg_out, ids = format_top10(mkts, lang=cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_top10_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /price BTC ETH SOL ...
    if t_low.startswith("/price"):
        tail = text.split(None, 1)[1] if len(text.split()) > 1 else ""
        query_text = tail or "BTC ETH SOL TON"
        ids = _cg_ids_from_text(query_text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=cur_lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /top10 (оставляем совместимость)
    if t_low.startswith("/top10"):
        mkts = coingecko_top_market(10)
        msg_out, ids = format_top10(mkts, lang=cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_top10_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # /gas и без слэша
    if t_low.startswith("/gas") or t_low == "gas":
        msg_out = format_gas_message(get_eth_gas(), cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_gas_keyboard(cur_lang))
        return "ok"

    # /feargreed | /fng и без слэша
    if t_low.startswith("/feargreed") or t_low == "/fng" or t_low == "feargreed" or t_low == "fng":
        d = fetch_fear_greed()
        msg_out = format_fear_greed(d, cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_fng_keyboard(cur_lang))
        return "ok"

    # /btcdom и без слэша
    if t_low.startswith("/btcdom") or t_low == "btcdom":
        d = fetch_btc_dominance()
        msg_out = format_btc_dominance(d, cur_lang)
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_btcdom_keyboard(cur_lang))
        return "ok"

    # /balance <address>
    if t_low.startswith("/balance"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text={"en":"Usage: /balance <ETH address>","ru":"Использование: /balance <ETH адрес>"}.get(cur_lang, "Usage: /balance <ETH address>"))
            return "ok"
        addr = parts[1]
        if not ALCHEMY_API_KEY:
            bot.send_message(chat_id=chat_id, text={"en":"Balances are temporarily unavailable (set ALCHEMY_API_KEY).","ru":"Баланс временно недоступен (установите ALCHEMY_API_KEY)."}.get(cur_lang, ""))
            return "ok"
        eth_bal = alchemy_get_eth_balance(addr)
        if not eth_bal.get("ok"):
            bot.send_message(chat_id=chat_id, text={"en":"Failed to fetch balance.","ru":"Не удалось получить баланс."}.get(cur_lang, ""))
            return "ok"
        tokens = alchemy_get_erc20_balances(addr)
        lines = {"en":[f"💰 Balance for {_short(addr)}:"],
                 "ru":[f"💰 Баланс {_short(addr)}:"]}.get(cur_lang, [f"💰 Balance for {_short(addr)}:"])
        lines.append(f"ETH: {eth_bal.get('eth')}")
        if tokens.get("ok"):
            # show first up to 10 tokens (contract only; no decimals without metadata)
            tlist = tokens.get("tokens") or []
            if tlist:
                lines.append({"en":"ERC-20 (raw, first 10):","ru":"ERC-20 (сырые, первые 10):"}.get(cur_lang,"ERC-20:"))
                for t in tlist[:10]:
                    lines.append(f"- {t.get('contract')} : {t.get('balance_hex')}")
        bot.send_message(chat_id=chat_id, text="\n".join(lines))
        return "ok"

    # /txs <address>
    if t_low.startswith("/txs"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text={"en":"Usage: /txs <ETH address>","ru":"Использование: /txs <ETH адрес>"}.get(cur_lang, "Usage: /txs <ETH address>"))
            return "ok"
        addr = parts[1]
        if not ALCHEMY_API_KEY:
            bot.send_message(chat_id=chat_id, text={"en":"Transactions are temporarily unavailable (set ALCHEMY_API_KEY).","ru":"Транзакции временно недоступны (установите ALCHEMY_API_KEY)."}.get(cur_lang, ""))
            return "ok"
        hist = alchemy_get_asset_transfers(addr, max_count=10)
        if not hist.get("ok"):
            bot.send_message(chat_id=chat_id, text={"en":"Failed to fetch transactions.","ru":"Не удалось получить транзакции."}.get(cur_lang, ""))
            return "ok"
        rows = hist.get("txs") or []
        if not rows:
            bot.send_message(chat_id=chat_id, text={"en":"No recent transfers found.","ru":"Недавние переводы не найдены."}.get(cur_lang, ""))
            return "ok"
        # Build compact table
        if cur_lang == "ru":
            header = "# | Дата (UTC)        | От → Кому                | Значение | Статус"
        else:
            header = "# | Date (UTC)        | From → To                | Value | Status"
        lines = [header]
        for i, r in enumerate(rows, start=1):
            ln = f"{i} | {str(r.get('date'))[:16]:16} | {_short(r.get('from') or '')} → {_short(r.get('to') or '')} | {r.get('value') or ''} | {r.get('status')}"
            lines.append(ln)
        bot.send_message(chat_id=chat_id, text="\n".join(lines))
        return "ok"

    
    # /check <address>
    if t_low.startswith("/check"):
        parts = text.split()
        if len(parts) < 2 or not ADDR_RE.match(parts[1]):
            bot.send_message(chat_id=chat_id, text={"en":"Usage: /check <ETH address>","ru":"Использование: /check <ETH адрес>"}.get(cur_lang, "Usage: /check <ETH address>"))
            return "ok"
        addr = parts[1]
        try:
            from server_contract_check import check_contract, format_check_report
            facts = check_contract(addr, alchemy_key=ALCHEMY_API_KEY,
                                   etherscan_key=ETHERSCAN_API_KEY,
                                   polygonscan_key=POLYGONSCAN_API_KEY,
                                   bscscan_key=BSCSCAN_API_KEY)
            report = format_check_report(facts, cur_lang)
        except Exception as e:
            report = {"en":"Internal error during /check.","ru":"Внутренняя ошибка при /check."}.get(cur_lang, "Internal error during /check.")
        bot.send_message(chat_id=chat_id, text=report,
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Адрес контракта → отчёт из блок-эксплорера
    m = ADDR_RE.search(text)
    if m:
        address = m.group(0)
        facts = analyze_eth_contract(address)
        report = format_report(facts, cur_lang)
        bot.send_message(chat_id=chat_id, text=report,
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Быстрый ответ цен через CoinGecko (натуральные фразы)
    if is_price_query(text):
        ids = _cg_ids_from_text(text)
        data = coingecko_prices(ids, vs="usd")
        msg_out = format_prices_message(data, lang=cur_lang, vs="usd")
        bot.send_message(chat_id=chat_id, text=msg_out, reply_markup=build_price_keyboard(chat_id, ids, cur_lang))
        return "ok"

    # Пусто
    if not text:
        # На случай пустого текста просто покажем приветствие по текущему языку
        start_lang = get_lang_override(chat_id) or DEFAULT_LANG
        bot.send_message(chat_id=chat_id, text=WELCOME.get(start_lang, WELCOME["en"]),
                         reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
        return "ok"

    # Обычный AI-ответ
    answer = ai_reply(text, cur_lang, chat_id)
    bot.send_message(chat_id=chat_id, text=answer,
                     reply_markup=build_donate_keyboard() if DONATE_STICKY else None)
    return "ok"

# -------------------- Local run --------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)


# ===== server_contract_check integrated below =====


import os, re, json, time, hashlib
from decimal import Decimal
from datetime import datetime
import requests

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

# EIP-1967 implementation slot = keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)

def _alchemy_url(api_key: str | None) -> str | None:
    if not api_key:
        return None
    return f"https://eth-mainnet.g.alchemy.com/v2/{api_key}"

def _rpc(url: str, method: str, params: list) -> dict:
    try:
        r = requests.post(url, json={"jsonrpc":"2.0","id":1,"method":method,"params":params}, timeout=20, headers={"Content-Type":"application/json"})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _hex_to_bytes(x: str) -> bytes:
    x = x or ""
    if x.startswith("0x"):
        x = x[2:]
    if len(x) % 2 == 1:
        x = "0"+x
    try:
        return bytes.fromhex(x)
    except Exception:
        return b""

def _parse_abi_string(output_hex: str) -> str | None:
    b = _hex_to_bytes(output_hex)
    if len(b) < 64:
        return None
    # first 32 bytes = offset (skip), next 32 = length, then data
    try:
        length = int.from_bytes(b[32:64], "big")
        data = b[64:64+length]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None

def _parse_abi_uint(output_hex: str) -> int | None:
    b = _hex_to_bytes(output_hex)
    if len(b) < 32:
        return None
    return int.from_bytes(b[-32:], "big")

def _parse_abi_bool(output_hex: str) -> bool | None:
    n = _parse_abi_uint(output_hex)
    if n is None: return None
    return bool(n)

def _eth_call(url: str, to_addr: str, data_hex: str) -> str | None:
    j = _rpc(url, "eth_call", [{"to": to_addr, "data": data_hex}, "latest"])
    if "error" in j:
        return None
    return j.get("result")

def _name(url: str, addr: str) -> str | None:
    # function selector for name(): 0x06fdde03
    out = _eth_call(url, addr, "0x06fdde03")
    return _parse_abi_string(out) if out else None

def _symbol(url: str, addr: str) -> str | None:
    # 0x95d89b41
    out = _eth_call(url, addr, "0x95d89b41")
    return _parse_abi_string(out) if out else None

def _decimals(url: str, addr: str) -> int | None:
    # 0x313ce567
    out = _eth_call(url, addr, "0x313ce567")
    return _parse_abi_uint(out) if out else None

def _supports_interface(url: str, addr: str, iid_hex: str) -> bool | None:
    # supportsInterface(bytes4) => 0x01ffc9a7 + 28 zero bytes + 4 byte interface id
    data = "0x01ffc9a7" + "0"*56 + iid_hex.replace("0x","").lower()
    out = _eth_call(url, addr, data)
    return _parse_abi_bool(out) if out else None

def _eip1967_impl(url: str, addr: str) -> str | None:
    slot_hex = hex(EIP1967_IMPL_SLOT)
    j = _rpc(url, "eth_getStorageAt", [addr, slot_hex, "latest"])
    if "error" in j:
        return None
    res = j.get("result") or ""
    b = _hex_to_bytes(res)
    if len(b) < 32:
        return None
    impl_bytes = b[-20:]
    impl = "0x" + impl_bytes.hex()
    if impl.lower() == "0x0000000000000000000000000000000000000000":
        return None
    return impl

def _getsourcecode_any(address: str, etherscan_key: str|None, polygonscan_key: str|None, bscscan_key: str|None) -> dict:
    # Try explorers in order; return first success
    sources = []
    if etherscan_key:
        sources.append(("Etherscan","https://api.etherscan.io/api", etherscan_key))
    if polygonscan_key:
        sources.append(("PolygonScan","https://api.polygonscan.com/api", polygonscan_key))
    if bscscan_key:
        sources.append(("BscScan","https://api.bscscan.com/api", bscscan_key))
    for name, base, key in sources:
        try:
            q = {"module":"contract","action":"getsourcecode","address":address,"apikey":key}
            r = requests.get(base, params=q, timeout=15)
            j = r.json()
            if str(j.get("status")) == "1":
                data = (j.get("result") or [{}])[0]
                return {"ok": True, "source": name, "data": data}
        except Exception:
            continue
    return {"ok": False}

def check_contract(address: str, alchemy_key: str|None, etherscan_key: str|None=None, polygonscan_key: str|None=None, bscscan_key: str|None=None) -> dict:
    addr = address.strip()
    if not ADDR_RE.fullmatch(addr):
        return {"ok": False, "error":"bad_address"}
    url = _alchemy_url(alchemy_key)
    facts = {"ok": True, "network":"ethereum", "address": addr, "via": ["on-chain"]}

    if url:
        try:
            nm = _name(url, addr)
            if nm: facts["name"] = nm
        except Exception: pass
        try:
            sb = _symbol(url, addr)
            if sb: facts["symbol"] = sb
        except Exception: pass
        try:
            dc = _decimals(url, addr)
            if dc is not None: facts["decimals"] = dc
        except Exception: pass
        # ERC-165
        try:
            erc721 = _supports_interface(url, addr, "0x80ac58cd")
            if erc721 is not None:
                facts.setdefault("erc165", {})["erc721"] = bool(erc721)
        except Exception: pass
        try:
            erc1155 = _supports_interface(url, addr, "0xd9b67a26")
            if erc1155 is not None:
                facts.setdefault("erc165", {})["erc1155"] = bool(erc1155)
        except Exception: pass
        # EIP-1967 proxy
        try:
            impl = _eip1967_impl(url, addr)
            if impl:
                facts["proxy"] = True
                facts["implementation"] = impl
            else:
                facts["proxy"] = False
        except Exception: pass

    # Optional enrichment from explorers
    exp = _getsourcecode_any(addr, etherscan_key, polygonscan_key, bscscan_key)
    if exp.get("ok"):
        data = exp.get("data") or {}
        facts["via"].append(exp.get("source"))
        if not facts.get("name"):
            facts["name"] = data.get("ContractName") or data.get("Proxy") or ""
        if data.get("CompilerVersion"):
            facts["compilerVersion"] = data.get("CompilerVersion")
        if data.get("SourceCode"):
            facts["sourceverified"] = True
        if data.get("Implementation") and not facts.get("implementation"):
            facts["implementation"] = data.get("Implementation")
        if data.get("Proxy") in ("1", 1, True):
            facts["proxy"] = True

    return facts

def format_check_report(facts: dict, lang: str) -> str:
    L = {
        "en": {
            "hdr":"🔎 Contract quick check:",
            "network":"Network","address":"Address",
            "name":"Name","symbol":"Symbol","decimals":"Decimals",
            "erc165":"ERC-165","erc721":"ERC-721","erc1155":"ERC-1155",
            "proxy":"Proxy","impl":"Implementation","via":"Via",
            "error":"Internal error or bad address."
        },
        "ru": {
            "hdr":"🔎 Быстрая проверка контракта:",
            "network":"Сеть","address":"Адрес",
            "name":"Имя","symbol":"Символ","decimals":"Десятичные",
            "erc165":"ERC-165","erc721":"ERC-721","erc1155":"ERC-1155",
            "proxy":"Прокси","impl":"Реализация","via":"Источник",
            "error":"Внутренняя ошибка или неверный адрес."
        }
    }.get(lang, {
        "hdr":"🔎 Contract quick check:",
        "network":"Network","address":"Address",
        "name":"Name","symbol":"Symbol","decimals":"Decimals",
        "erc165":"ERC-165","erc721":"ERC-721","erc1155":"ERC-1155",
        "proxy":"Proxy","impl":"Implementation","via":"Via",
        "error":"Internal error or bad address."
    })
    if not facts or not facts.get("ok"):
        return L["error"]
    lines = [L["hdr"]]
    lines.append(f"🧭 {L['network']}: {facts.get('network','ethereum')}")
    lines.append(f"🔗 {L['address']}: {facts.get('address','')}")
    if facts.get("name"):     lines.append(f"🏷️ {L['name']}: {facts.get('name')}")
    if facts.get("symbol"):   lines.append(f"💠 {L['symbol']}: {facts.get('symbol')}")
    if facts.get("decimals") is not None: lines.append(f"🔢 {L['decimals']}: {facts.get('decimals')}")
    if "erc165" in facts:
        e = facts.get("erc165", {})
        lines.append(f"🧪 {L['erc165']}: {L['erc721']}={'✅' if e.get('erc721') else '❌'}, {L['erc1155']}={'✅' if e.get('erc1155') else '❌'}")
    if "proxy" in facts:
        lines.append(f"🧩 {L['proxy']}: {'✅' if facts.get('proxy') else '❌'}")
    if facts.get("implementation"):
        lines.append(f"🧷 {L['impl']}: {facts.get('implementation')}")
    if facts.get("compilerVersion"):
        lines.append(f"🧪 Compiler: {facts.get('compilerVersion')}")
    if facts.get("sourceverified"):
        lines.append("✅ Source verified")
    if facts.get("via"):
        lines.append(f"🔎 {L['via']}: " + ", ".join(facts.get("via")))
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    if lang == "en":
        lines.append(f"\nAs of {dt}.")
    else:
        lines.append(f"\nПо состоянию на {dt}.")
    return "\n".join(lines)
