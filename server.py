import os, json, time, re, hmac, hashlib, logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import requests
from flask import Flask, request, jsonify, abort
from pydantic import BaseModel, HttpUrl, ValidationError

# ------------ Config ------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")  # any random string
SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # optional
ETH_DONATION = os.getenv("ETH_DONATION", "")
TON_DONATION = os.getenv("TON_DONATION", "")
SOL_DONATION = os.getenv("SOL_DONATION", "")
STRICT_MODE = os.getenv("STRICT_MODE", "true").lower() == "true"
DEFAULT_LANG = "EN"
COINGECKO_API = "https://api.coingecko.com/api/v3"

assert TELEGRAM_BOT_TOKEN, "TELEGRAM_BOT_TOKEN is required"
assert APP_BASE_URL, "APP_BASE_URL is required"
assert WEBHOOK_SECRET, "WEBHOOK_SECRET is required"

# ------------ Logging ------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cryptobot-ai")

# ------------ Telegram helpers ------------
TG_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

def tg_send(chat_id: int, text: str, reply_to: int | None = None, disable_preview: bool = False):
    try:
        requests.post(f"{TG_API}/sendMessage", json={
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": disable_preview,
            **({"reply_to_message_id": reply_to} if reply_to else {})
        }, timeout=20)
    except Exception as e:
        log.exception("sendMessage failed: %s", e)

# ------------ Schema for safe answers ------------
class Source(BaseModel):
    title: str
    url: HttpUrl

class BotAnswer(BaseModel):
    answer: str
    details: List[str] = []
    sources: List[Source] = []
    confidence: float = 0.5
    checked_at: str | None = None  # ISO time

def format_answer(data: Dict[str, Any]) -> str:
    try:
        a = BotAnswer(**data)
    except ValidationError as e:
        return f"*Internal schema error*: `{e}`"

    lines = [a.answer]
    if a.details:
        lines += [""] + [f"• {x}" for x in a.details]
    if a.sources:
        lines += ["", "*Sources:*"] + [f"- [{s.title}]({s.url})" for s in a.sources]
    if a.checked_at:
        lines += [f"\n_Last updated_: {a.checked_at} (GMT+4)"]
    lines += [f"_Confidence_: {a.confidence:.2f}"]
    return "\n".join(lines)

def enforce_sources(candidate: Dict[str, Any]) -> Dict[str, Any]:
    if STRICT_MODE and not candidate.get("sources"):
        candidate["answer"] = "I cannot verify this with reliable sources."
        candidate.setdefault("details", []).append("Try refining the request or allow me to search the web.")
        candidate["confidence"] = 0.2
    return candidate

# ------------ Tools ------------
def now_baku_iso() -> str:
    # Render dynos use UTC; we display GMT+4 (Asia/Baku)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def web_search(query: str) -> List[Dict[str, str]]:
    if not SERPAPI_KEY:
        return []
    url = "https://serpapi.com/search.json"
    params = {"q": query, "engine": "google", "num": 5, "api_key": SERPAPI_KEY}
    r = requests.get(url, params=params, timeout=25)
    r.raise_for_status()
    items = r.json().get("organic_results", [])[:5]
    res = []
    for x in items:
        link = x.get("link")
        title = x.get("title")
        if link and title:
            res.append({"title": title, "url": link})
    return res

def price_feed_coingecko(coin_id: str) -> Dict[str, Any]:
    r = requests.get(f"{COINGECKO_API}/simple/price",
                     params={"ids": coin_id, "vs_currencies": "usd", "include_24hr_vol": "true"},
                     timeout=20)
    r.raise_for_status()
    jd = r.json().get(coin_id, {})
    return {"price_usd": jd.get("usd"), "vol_24h": jd.get("usd_24h_vol")}

def token_info_stub(contract: str, chain: str) -> Dict[str, Any]:
    # Placeholder: connect Etherscan/BscScan/Solscan later
    return {"contract": contract, "chain": chain, "decimals": None, "name": None, "symbol": None}

def route_tools(text: str) -> List[str]:
    q = text.lower()
    tools: List[str] = []
    if any(k in q for k in ["price", "quote", "liquidity", "volume"]):
        tools.append("price")
    if any(k in q for k in ["contract", "address", "token", "decimals", "supply"]):
        tools.append("token")
    if any(k in q for k in ["is this scam", "legit", "trust", "review", "site", "twitter", "discord"]):
        tools.append("search")
    if not tools:
        # default to web search for factual queries
        if any(k in q for k in ["who", "what", "when", "where", "news", "faq", "how"]):
            tools.append("search")
    return list(dict.fromkeys(tools))

# ------------ Optional OpenAI polish ------------
def llm_polish_english(data: Dict[str, Any]) -> Dict[str, Any]:
    if not OPENAI_API_KEY:
        return data
    try:
        # Lazy import to keep startup fast
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        system = (
            "You are a precise assistant. Output must be short, structured, in EN. "
            "Do not invent sources. Use bullet points. No philosophy."
        )
        content = json.dumps(data, ensure_ascii=False)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": f"Rewrite this JSON into clearer English but keep fields: {content}"}
            ]
        )
        txt = resp.choices[0].message.content.strip()
        # Best-effort: try to parse back, otherwise just keep original
        if txt.startswith("{") and txt.endswith("}"):
            data2 = json.loads(txt)
            # keep sources if dropped
            if not data2.get("sources"):
                data2["sources"] = data.get("sources", [])
            return data2
        return data
    except Exception as e:
        log.warning("OpenAI polish skipped: %s", e)
        return data

# ------------ Language policy ------------
CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")

def prefer_english(user_text: str) -> bool:
    # EN by default; only switch if clearly Russian and user demands it
    if "force_ru=true" in user_text.lower():
        return False
    if CYRILLIC_RE.search(user_text):
        # still keep EN as default unless explicitly asked
        return True
    return True

# ------------ Flask app ------------
app = Flask(__name__)

@app.get("/healthz")
def health():
    return {"ok": True, "time": now_baku_iso()}

@app.post(f"/webhook/{WEBHOOK_SECRET}")
def webhook():
    # Optional: verify Telegram signature (not provided by BOT API), so we just trust the path secret
    upd = request.get_json(force=True, silent=True) or {}
    log.info("update: %s", json.dumps(upd)[:1000])

    msg = upd.get("message") or upd.get("edited_message")
    if not msg:
        return jsonify({"ok": True})

    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if not text:
        tg_send(chat_id, "Send a text message.")
        return jsonify({"ok": True})

    # Commands
    if text.startswith("/start"):
        tg_send(chat_id,
                "Welcome to CryptoBot AI.\n"
                "- Default language: EN\n"
                "- Use /donate to get addresses (ETH/TON/SOL)\n"
                "- Ask me about prices, tokens, sites. I’ll fetch sources.")
        return jsonify({"ok": True})

    if text.startswith("/donate"):
        lines = ["*Support the project*"]
        if ETH_DONATION: lines.append(f"• ETH/ERC-20: `{ETH_DONATION}`")
        if TON_DONATION: lines.append(f"• TON: `{TON_DONATION}`")
        if SOL_DONATION: lines.append(f"• SOL: `{SOL_DONATION}`")
        tg_send(chat_id, "\n".join(lines), disable_preview=True)
        return jsonify({"ok": True})

    if text.startswith("/help"):
        tg_send(chat_id,
                "Examples:\n"
                "- price BTC\n- token 0x... on Ethereum\n- is this site legit: example.com\n- how to create a wallet")
        return jsonify({"ok": True})

    # --------- Router ---------
    tools = route_tools(text)

    answer: Dict[str, Any] = {
        "answer": "Here is what I found:",
        "details": [],
        "sources": [],
        "confidence": 0.6,
        "checked_at": now_baku_iso()
    }

    try:
        # Simple patterns
        if text.lower().startswith("price "):
            coin = text.split(maxsplit=1)[1].strip().lower()
            pf = price_feed_coingecko(coin)
            price = pf.get("price_usd")
            vol = pf.get("vol_24h")
            if price is not None:
                answer["answer"] = f"{coin.upper()} price: ${price:,.4f}"
                if vol is not None:
                    answer["details"].append(f"24h volume: ${vol:,.0f}")
                answer["sources"].append({"title":"CoinGecko Simple Price","url":"https://www.coingecko.com/"})
                answer["confidence"] = 0.8
            else:
                answer["answer"] = f"Price not found for '{coin}'."
                answer["confidence"] = 0.3

        elif text.lower().startswith("token "):
            # token <contract> [on <chain>]
            parts = text.split()
            contract = parts[1] if len(parts) > 1 else ""
            chain = "ethereum"
            if " on " in text.lower():
                chain = text.lower().split(" on ", 1)[1].strip()
            ti = token_info_stub(contract, chain)
            answer["answer"] = f"Token info (stub) for {contract} on {chain}:"
            for k, v in ti.items():
                answer["details"].append(f"{k}: {v}")
            answer["sources"].append({"title":"(Add Etherscan/Solscan later)","url":"https://etherscan.io/"})
            answer["confidence"] = 0.5

        elif "site" in text.lower() or "http" in text.lower() or "www." in text.lower():
            # basic web check
            q = text
            sources = web_search(q)
            if sources:
                answer["answer"] = "Top related sources:"
                answer["sources"] = sources
                answer["confidence"] = 0.7
            else:
                answer["answer"] = "No sources found."
                answer["confidence"] = 0.3

        elif "how to" in text.lower() or "guide" in text.lower():
            # fallback to search
            sources = web_search(text)
            answer["answer"] = "Here are relevant guides:"
            answer["sources"] = sources
            answer["confidence"] = 0.6

        else:
            # generic factual query → search
            if "search" in tools:
                sources = web_search(text)
                if sources:
                    answer["answer"] = "Sources that match your query:"
                    answer["sources"] = sources
                    answer["confidence"] = 0.6
                else:
                    answer["answer"] = "I couldn't find reliable sources."
                    answer["confidence"] = 0.3
            else:
                # If nothing matched, nudge user
                answer["answer"] = "Tell me the coin (e.g., `price btc`) or paste a contract (e.g., `token 0x... on Ethereum`)."
                answer["confidence"] = 0.4

    except Exception as e:
        log.exception("processing error: %s", e)
        answer = {
            "answer": "Internal error while fetching data.",
            "details": [str(e)],
            "sources": [],
            "confidence": 0.2,
            "checked_at": now_baku_iso()
        }

    # Strict mode: must have sources for factual claims
    answer = enforce_sources(answer)

    # Optional LLM polishing (keeps EN, short & structured)
    if prefer_english(text):
        answer = llm_polish_english(answer)

    tg_send(chat_id, format_answer(answer), reply_to=msg.get("message_id"))
    return jsonify({"ok": True})

# ------------ Webhook setup helper ------------
@app.post("/set_webhook")
def set_webhook():
    # Protect with simple header secret
    key = request.headers.get("X-Setup-Secret")
    if key != WEBHOOK_SECRET:
        abort(403)
    url = f"{APP_BASE_URL}/webhook/{WEBHOOK_SECRET}"
    r = requests.get(f"{TG_API}/setWebhook", params={"url": url}, timeout=20)
    return r.json(), r.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
