import os, json, re, logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import requests
from flask import Flask, request, jsonify, abort
from pydantic import BaseModel, HttpUrl, ValidationError

# ============== Config (lazy, без assert) ==============
def getenv_strip(key: str, default: str = "") -> str:
    v = os.getenv(key, default)
    return v.strip() if isinstance(v, str) else v

TELEGRAM_BOT_TOKEN = getenv_strip("TELEGRAM_BOT_TOKEN", "")
APP_BASE_URL       = getenv_strip("APP_BASE_URL", "")
WEBHOOK_SECRET     = getenv_strip("WEBHOOK_SECRET", "")
SERPAPI_KEY        = getenv_strip("SERPAPI_KEY", "")
OPENAI_API_KEY     = getenv_strip("OPENAI_API_KEY", "")
STRICT_MODE        = getenv_strip("STRICT_MODE", "true").lower() == "true"

# Donations
ETH_DONATION = getenv_strip("ETH_DONATION", "")
TON_DONATION = getenv_strip("TON_DONATION", "")
SOL_DONATION = getenv_strip("SOL_DONATION", "")

COINGECKO_API = "https://api.coingecko.com/api/v3"

# ============== Logging ==============
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cryptobot-ai")

# Поможем глазами увидеть, что env реально подхватились (без утечки секретов)
def mask(s: str, show: int = 5) -> str:
    if not s: return "(empty)"
    return s[:show] + "…" + f"({len(s)} chars)"

log.info("ENV check: TELEGRAM_BOT_TOKEN=%s | APP_BASE_URL=%s | WEBHOOK_SECRET=%s",
         mask(TELEGRAM_BOT_TOKEN), APP_BASE_URL or "(empty)", mask(WEBHOOK_SECRET))

# ============== Telegram helpers ==============
def tg_api_base() -> str | None:
    if not TELEGRAM_BOT_TOKEN:
        return None
    return f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

def tg_send(chat_id: int, text: str, reply_to: int | None = None, disable_preview: bool = False):
    api = tg_api_base()
    if not api:
        log.error("TELEGRAM_BOT_TOKEN missing at send time; message not sent.")
        return
    try:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": disable_preview,
        }
        if reply_to:
            payload["reply_to_message_id"] = reply_to
        requests.post(f"{api}/sendMessage", json=payload, timeout=20)
    except Exception as e:
        log.exception("sendMessage failed: %s", e)

# ============== Schema & formatting ==============
class Source(BaseModel):
    title: str
    url: HttpUrl

class BotAnswer(BaseModel):
    answer: str
    details: List[str] = []
    sources: List[Source] = []
    confidence: float = 0.5
    checked_at: str | None = None  # ISO (we label GMT+4 in output)

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

# ============== Utils ==============
CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")

def now_baku_iso() -> str:
    # Render dynos run UTC; display local label GMT+4 (Asia/Baku)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def prefer_english(user_text: str) -> bool:
    # EN по умолчанию; RU только при явном запросе (force_ru=true)
    if "force_ru=true" in user_text.lower():
        return False
    return True

# ============== Tools ==============
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
    # Заглушка: для реальных данных подключи Etherscan/BscScan/Solscan
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
    if not tools and any(k in q for k in ["who", "what", "when", "where", "news", "faq", "how"]):
        tools.append("search")
    return list(dict.fromkeys(tools))

# ============== Optional OpenAI polish (keeps EN, short) ==============
def llm_polish_english(data: Dict[str, Any]) -> Dict[str, Any]:
    if not OPENAI_API_KEY:
        return data
    try:
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
        if txt.startswith("{") and txt.endswith("}"):
            data2 = json.loads(txt)
            if not data2.get("sources"):
                data2["sources"] = data.get("sources", [])
            return data2
        return data
    except Exception as e:
        log.warning("OpenAI polish skipped: %s", e)
        return data

# ============== App ==============
app = Flask(__name__)

@app.get("/healthz")
def health():
    return {"ok": True, "time": now_baku_iso()}

@app.get("/diag/env")
def diag_env():
    # Безопасная диагностика наличия env (секреты не показываем)
    return {
        "TELEGRAM_BOT_TOKEN_set": bool(TELEGRAM_BOT_TOKEN),
        "APP_BASE_URL_set": bool(APP_BASE_URL),
        "WEBHOOK_SECRET_set": bool(WEBHOOK_SECRET),
        "SERPAPI_KEY_set": bool(SERPAPI_KEY),
        "ETH_DONATION_set": bool(ETH_DONATION),
        "TON_DONATION_set": bool(TON_DONATION),
        "SOL_DONATION_set": bool(SOL_DONATION),
        "STRICT_MODE": STRICT_MODE,
        "time": now_baku_iso(),
    }

# -------- Telegram webhook --------
@app.post(f"/webhook/{WEBHOOK_SECRET or 'missing-secret'}")
def webhook():
    # Блокируем, если критичных env нет (но без падения импорта)
    if not TELEGRAM_BOT_TOKEN:
        return jsonify({"ok": False, "error": "TELEGRAM_BOT_TOKEN missing"}), 503

    api = tg_api_base()
    if not api:
        return jsonify({"ok": False, "error": "Telegram API base missing"}), 503

    upd = request.get_json(force=True, silent=True) or {}
    log.info("update: %s", json.dumps(upd)[:1000])

    # 1) CallbackQuery: кнопки "Copy …"
    if "callback_query" in upd:
        cq = upd["callback_query"]
        data = cq.get("data", "")
        if data.startswith("copy:"):
            addr = data.split("copy:", 1)[1]
            try:
                requests.post(f"{api}/answerCallbackQuery", json={
                    "callback_query_id": cq["id"],
                    "text": f"Copied: {addr}",
                    "show_alert": False
                }, timeout=20)
            except Exception as e:
                log.exception("answerCallbackQuery failed: %s", e)
        return jsonify({"ok": True})

    # 2) Обычные сообщения
    msg = upd.get("message") or upd.get("edited_message")
    if not msg:
        return jsonify({"ok": True})

    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if not text:
        tg_send(chat_id, "Send a text message.")
        return jsonify({"ok": True})

    # Команды
    if text.startswith("/start"):
        tg_send(chat_id,
                "Welcome to CryptoBot AI.\n"
                "- Default language: EN\n"
                "- Use /donate to get addresses (ETH/TON/SOL)\n"
                "- Ask me about prices, tokens, sites. I’ll fetch sources.")
        return jsonify({"ok": True})

    if text.startswith("/donate"):
        from urllib.parse import quote

        lines = ["*Support the project*"]
        buttons: List[List[Dict[str, Any]]] = []

        if ETH_DONATION:
            lines.append(f"• ETH/ERC-20: `{ETH_DONATION}`")
            buttons.append([{"text": "Copy ETH", "callback_data": f"copy:{ETH_DONATION}"}])
            buttons.append([{"text": "QR ETH",
                             "url": f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={quote(ETH_DONATION)}"}])

        if TON_DONATION:
            lines.append(f"• TON: `{TON_DONATION}`")
            buttons.append([{"text": "Copy TON", "callback_data": f"copy:{TON_DONATION}"}])
            buttons.append([{"text": "QR TON",
                             "url": f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={quote(TON_DONATION)}"}])

        if SOL_DONATION:
            lines.append(f"• SOL: `{SOL_DONATION}`")
            buttons.append([{"text": "Copy SOL", "callback_data": f"copy:{SOL_DONATION}"}])
            buttons.append([{"text": "QR SOL",
                             "url": f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={quote(SOL_DONATION)}"}])

        try:
            requests.post(f"{api}/sendMessage", json={
                "chat_id": chat_id,
                "text": "\n".join(lines),
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
                "reply_markup": {"inline_keyboard": buttons}
            }, timeout=20)
        except Exception as e:
            log.exception("sendMessage failed: %s", e)

        return jsonify({"ok": True})

    if text.startswith("/help"):
        tg_send(chat_id,
                "Examples:\n"
                "- price btc\n- token 0x... on Ethereum\n- is this site legit: example.com\n- how to create a wallet")
        return jsonify({"ok": True})

    # -------- Router --------
    tools = route_tools(text)

    answer: Dict[str, Any] = {
        "answer": "Here is what I found:",
        "details": [],
        "sources": [],
        "confidence": 0.6,
        "checked_at": now_baku_iso()
    }

    try:
        # --- Simple patterns ---
        if text.lower().startswith("price "):
            coin = text.split(maxsplit=1)[1].strip().lower()
            pf = price_feed_coingecko(coin)
            price = pf.get("price_usd")
            vol = pf.get("vol_24h")
            if price is not None:
                answer["answer"] = f"{coin.upper()} price: ${price:,.4f}"
                if vol is not None:
                    answer["details"].append(f"24h volume: ${vol:,.0f}")
                answer["sources"].append({"title": "CoinGecko Simple Price", "url": "https://www.coingecko.com/"})
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
            answer["sources"].append({"title": "(Add Etherscan/Solscan later)", "url": "https://etherscan.io/"})
            answer["confidence"] = 0.5

        elif "site" in text.lower() or "http" in text.lower() or "www." in text.lower():
            sources = web_search(text)
            if sources:
                answer["answer"] = "Top related sources:"
                answer["sources"] = sources
                answer["confidence"] = 0.7
            else:
                answer["answer"] = "No sources found."
                answer["confidence"] = 0.3

        elif "how to" in text.lower() or "guide" in text.lower():
            sources = web_search(text)
            answer["answer"] = "Here are relevant guides:"
            answer["sources"] = sources
            answer["confidence"] = 0.6

        else:
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

    answer = enforce_sources(answer)
    if prefer_english(text):
        answer = llm_polish_english(answer)

    tg_send(chat_id, format_answer(answer), reply_to=msg.get("message_id"))
    return jsonify({"ok": True})

# -------- Webhook setup helper --------
@app.post("/set_webhook")
def set_webhook():
    # Защита простым заголовком
    key = request.headers.get("X-Setup-Secret")
    expected = WEBHOOK_SECRET
    if not expected:
        return jsonify({"ok": False, "error": "WEBHOOK_SECRET missing"}), 400
    if key != expected:
        abort(403)

    if not APP_BASE_URL:
        return jsonify({"ok": False, "error": "APP_BASE_URL missing"}), 400
    if not TELEGRAM_BOT_TOKEN:
        return jsonify({"ok": False, "error": "TELEGRAM_BOT_TOKEN missing"}), 400

    api = tg_api_base()
    if not api:
        return jsonify({"ok": False, "error": "Telegram API base missing"}), 400

    url = f"{APP_BASE_URL}/webhook/{WEBHOOK_SECRET}"
    r = requests.get(f"{api}/setWebhook", params={"url": url}, timeout=20)
    try:
        jr = r.json()
    except Exception:
        jr = {"status_code": r.status_code, "text": r.text}
    return jr, r.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
