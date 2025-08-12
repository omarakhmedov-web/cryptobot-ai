import os
import re
import json
import requests
from flask import Flask, request
from telegram import Bot, ParseMode
from groq import Groq

app = Flask(__name__)

# --- ENV ---
TELEGRAM_TOKEN   = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY     = os.environ["GROQ_API_KEY"]
PORT             = int(os.environ.get("PORT", 10000))

# НЕобязательные ключи (если нет — просто пропустим соответствующие проверки)
ETHERSCAN_API_KEY   = os.environ.get("ETHERSCAN_API_KEY")
BSCSCAN_API_KEY     = os.environ.get("BSCSCAN_API_KEY")
POLYGONSCAN_API_KEY = os.environ.get("POLYGONSCAN_API_KEY")

bot    = Bot(token=TELEGRAM_TOKEN)
client = Groq(api_key=GROQ_API_KEY)  # без proxies и прочего — как и должно быть

# --- Язык: простой, быстрый детектор по диапазонам Unicode ---
def detect_lang(txt: str) -> str:
    if not txt:
        return "en"
    # cyrillic
    if re.search(r"[\u0400-\u04FF]", txt):
        return "ru"
    # arabic
    if re.search(r"[\u0600-\u06FF]", txt):
        return "ar"
    # chinese/japanese/korean (очень грубо)
    if re.search(r"[\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]", txt):
        return "zh"
    # spanish/portuguese accents (латиница + диакритика) – оставить en, LLM переформулирует
    return "en"

WELCOME = {
    "en": (
        "Hello! I'm CryptoGuard, your Web3 security assistant. "
        "Send me a token/contract address (like `0x...`) and I'll run checks:\n"
        "• Ownership/Mint/Fees/Blacklist/Pausable\n"
        "• Proxy/Upgradeable, Deployer history & socials\n"
        "• Liquidity locks, Top holders, Transfer anomalies\n"
        "• Pools/Liquidity/Price/Volume from DexScreener\n\n"
        "You can ask in any language — I’ll reply in that language."
    ),
    "ru": (
        "Привет! Я CryptoGuard — помощник по безопасности Web3. "
        "Отправь адрес контракта (например, `0x...`) и я выполню проверки:\n"
        "• Владение/Минт/Комиссии/Чёрный список/Пауза\n"
        "• Прокси/Апгрейд, история деплоя и соцсети\n"
        "• Блокировки ликвидности, топ-холдеры, аномалии переводов\n"
        "• Пулы/Ликвидность/Цена/Объём с DexScreener\n\n"
        "Пиши на любом языке — отвечу на нём же."
    ),
    "ar": "أرسل عنوان العقد (مثل 0x...) وسأقوم بفحوصات الأمان والشفافية والحوكمة والسيولة. يمكنني الرد بلغتك.",
    "zh": "发送合约地址（如 0x...），我会进行所有权、代理、黑名单、流动性、池子、价格/成交量等检查。我会用你的语言回复。"
}

# -------- Утилиты блокчейн-сканеров --------
SCAN = {
    "eth": {
        "name": "Ethereum",
        "base": "https://api.etherscan.io/api",
        "key": ETHERSCAN_API_KEY
    },
    "bsc": {
        "name": "BSC",
        "base": "https://api.bscscan.com/api",
        "key": BSCSCAN_API_KEY
    },
    "polygon": {
        "name": "Polygon",
        "base": "https://api.polygonscan.com/api",
        "key": POLYGONSCAN_API_KEY
    }
}

def is_address(s: str) -> bool:
    return bool(re.search(r"\b0x[a-fA-F0-9]{40}\b", s or ""))

def _scan_get(chain: str, module: str, action: str, params: dict) -> dict | None:
    cfg = SCAN[chain]
    if not cfg["key"]:
        return None
    payload = {"module": module, "action": action, "apikey": cfg["key"], **params}
    try:
        r = requests.get(cfg["base"], params=payload, timeout=12)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def get_token_standard_and_owner(chain: str, address: str) -> dict:
    """Пробуем понять стандарт токена и владельца из ABI и некоторых эвристик."""
    out = {
        "chain": SCAN[chain]["name"],
        "standard": None,
        "owner": None,
        "mint": None,
        "fees_tax": None,
        "blacklist_pause": None,
        "proxy": None,
        "deployer": None,
        "socials": None
    }
    j = _scan_get(chain, "contract", "getabi", {"address": address})
    if not j or j.get("status") != "1":
        return out
    try:
        abi = json.loads(j["result"])
    except Exception:
        return out

    # простая эвристика по функциям
    fnames = {item.get("name") for item in abi if item.get("type") == "function"}
    if {"totalSupply", "balanceOf", "transfer"} & fnames:
        out["standard"] = "ERC-20"
    if {"ownerOf", "tokenURI"} & fnames:
        out["standard"] = out["standard"] or "ERC-721/1155"

    out["mint"] = "mint" in (fnames or set())
    out["fees_tax"] = any(x in fnames for x in ["setTax", "taxFee", "setFees"])
    out["blacklist_pause"] = any(x in fnames for x in ["blacklist", "addToBlacklist", "pause", "paused"])

    # Владелец/деployer (часто owner() или owner) может быть
    if "owner" in fnames:
        out["owner"] = "function owner() present"
    # Прокси
    out["proxy"] = any(x in fnames for x in ["implementation", "upgradeTo", "proxyType"])

    # Заглушки: deployer/socials — нужны отдельные эндпоинты/скан логов конкретной сети
    return out

def get_holders_and_liquidity(chain: str, address: str) -> dict:
    """Пытаемся вытянуть топ-холдеров и lock-инфу, если скан поддерживает (часто платно)."""
    # Большинство таких эндпоинтов — платные/про-аккаунт. Оставим «не публично».
    return {
        "top_holders": "Not publicly available",
        "liquidity_locks": "Not publicly available",
        "transfer_anomalies": "Not publicly available"
    }

def get_dexscreener(address: str) -> dict | None:
    try:
        r = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{address}", timeout=12)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("pairs"):
            return None
        best = max(data["pairs"], key=lambda p: float(p.get("liquidity", {}).get("usd", 0) or 0))
        return {
            "dex_chain": best.get("chainId"),
            "pair": best.get("pairAddress"),
            "dex": best.get("dexId"),
            "liquidity_usd": best.get("liquidity", {}).get("usd"),
            "fdv_usd": best.get("fdv"),
            "price_usd": best.get("priceUsd"),
            "volume24h": best.get("volume", {}).get("h24"),
            "base_token": best.get("baseToken", {}).get("symbol"),
            "quote_token": best.get("quoteToken", {}).get("symbol"),
            "url": best.get("url"),
        }
    except Exception:
        return None

def summarize_with_llm(lang: str, sections: dict) -> str:
    """Попросим LLM оформить отчет на языке пользователя."""
    system = (
        "You are CryptoGuard, a Web3 security assistant. Summarize token/contract checks "
        "clearly and concisely for retail users. Use bullet points where useful. "
        "Respond ONLY in the user's language."
    )
    content = {
        "language": lang,
        "sections": sections
    }
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(content, ensure_ascii=False)}
            ],
            temperature=0.3,
        )
        text = resp.choices[0].message.content.strip()
        return text
    except Exception:
        # Фолбэк — простой форматированный текст на английском
        parts = [f"*{k}*\n{json.dumps(v, ensure_ascii=False, indent=2)}" for k, v in sections.items()]
        return "Token Report:\n" + "\n\n".join(parts)

def analyze_token(address: str, lang: str) -> str:
    sections = {}
    # 1) Попытка по сетям
    chain_hits = []
    for chain in ("eth", "bsc", "polygon"):
        info = get_token_standard_and_owner(chain, address)
        # если вообще ничего не пришло, пропускаем
        if any(v is not None for v in info.values()):
            chain_hits.append(info)

    if chain_hits:
        # Берем первый «наиболее заполненный» (просто по числу truthy полей)
        best = max(chain_hits, key=lambda d: sum(1 for v in d.values() if v))
        sections["On-chain checks"] = best
        sections.update(get_holders_and_liquidity(
            "eth" if best["chain"] == "Ethereum" else "bsc" if best["chain"] == "BSC" else "polygon",
            address
        ))
    else:
        sections["On-chain checks"] = {"note": "Explorers returned limited or no public data."}

    # 2) DexScreener
    ds = get_dexscreener(address)
    sections["DEX/Liquidity"] = ds or {"note": "No active DEX pairs found or API returned none."}

    # Итог — красиво упакуем LLM-ом на нужном языке
    return summarize_with_llm(lang, sections)

# --------- Маршруты ----------
@app.route("/", methods=["GET"])
def root():
    return "ok"

@app.route("/health", methods=["GET"])
def health():
    return "ok"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg  = data.get("message") or data.get("edited_message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    text    = msg.get("text", "")

    if not chat_id:
        return "ok"

    lang = detect_lang(text or "")

    # /start
    if text and text.strip().lower().startswith(("/start", "start")):
        bot.send_message(chat_id, WELCOME.get(lang, WELCOME["en"]), parse_mode=ParseMode.MARKDOWN)
        return "ok"

    # адрес токена?
    m = re.search(r"\b0x[a-fA-F0-9]{40}\b", text or "")
    if m:
        addr = m.group(0)
        try:
            report = analyze_token(addr, lang)
        except Exception as e:
            report = ( "⚠️ Error while analyzing the token. "
                       "Please try another address or later.\n\n"
                       f"Details: {type(e).__name__}" )
        bot.send_message(chat_id, report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
        return "ok"

    # иначе — обычный вопрос → к LLM
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": (
                    "You are CryptoGuard, a concise Web3 assistant. "
                    "Answer ONLY in the user's language. If user asks to check a token, "
                    "ask them to provide a contract address (0x...)."
                )},
                {"role": "user", "content": text}
            ],
            temperature=0.5
        )
        reply = resp.choices[0].message.content.strip()
    except Exception as e:
        reply = f"Error: {type(e).__name__}. Please try again later."

    bot.send_message(chat_id, reply, parse_mode=ParseMode.MARKDOWN)
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
