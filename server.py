import os, re, json, time
from typing import Dict, Any, Optional
from flask import Flask, request
import requests
from groq import Groq

app = Flask(__name__)

# ---------- ENV ----------
TELEGRAM_TOKEN      = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY        = os.environ["GROQ_API_KEY"]
ETHERSCAN_API_KEY   = os.environ.get("ETHERSCAN_API_KEY", "")  # optional
BSCSCAN_API_KEY     = os.environ.get("BSCSCAN_API_KEY", "")    # optional
PORT                = int(os.environ.get("PORT", 10000))
GROQ_MODEL          = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

# ВАЖНО: НИКАКИХ proxies в конструктор не передаём!
client = Groq(api_key=GROQ_API_KEY)

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

def send_message(chat_id: int, text: str):
    try:
        requests.post(TELEGRAM_API,
                      json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
                      timeout=10)
    except Exception:
        pass

# ---------- Lang detect ----------
def detect_lang(text: str) -> str:
    if not text: return "en"
    t = text.strip().lower()
    if re.search(r"[а-яё]", t): return "ru"
    if re.search(r"[؀-ۿ]", t):   return "ar"
    if re.search(r"[\u4e00-\u9fff]", t): return "zh"
    if any(ch in t for ch in "ığüşöç"):  return "tr"
    return "en"

WELCOME = {
    "en": "Hi! I’m CryptoGuard. Paste a token/contract (0x...), tx hash or link — I’ll highlight common Web3 risks.",
    "ru": "Привет! Я CryptoGuard. Вставьте токен/контракт (0x...), хеш транзакции или ссылку — отмечу типичные риски.",
    "ar": "مرحبًا! أنا CryptoGuard. أرسل عقدًا (0x...) أو معاملة أو رابطًا — سأشير إلى المخاطر الشائعة.",
    "zh": "你好！我是 CryptoGuard。贴上代币/合约（0x…）、交易哈希或链接——我会标出常见风险。",
    "tr": "Selam! Ben CryptoGuard. Token/kontrat (0x…), tx hash veya bağlantı gönder—yaygın riskleri işaretlerim.",
}

SYSTEM_PROMPT = (
    "You are CryptoGuard, a Web3 security assistant. "
    "You receive a concise technical summary (JSON) of on-chain checks and must produce a clear, compact report. "
    "Explain each signal and give practical DYOR tips. "
    "Never request seed/private keys. Reply in the user's language (fallback {lang})."
)

# ---------- Helpers ----------
ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

def extract_address(text: str) -> Optional[str]:
    m = ADDR_RE.search(text or "")
    return m.group(0).lower() if m else None

def detect_chain(text: str) -> str:
    t = (text or "").lower()
    if "bscscan" in t or "bnb" in t or " chain:bsc" in t: return "bsc"
    if "etherscan" in t or " chain:eth" in t: return "eth"
    return "eth"

# ---------- Explorer APIs ----------
ETHERSCAN_ENDPOINT = {
    "eth": ("https://api.etherscan.io/api", ETHERSCAN_API_KEY),
    "bsc": ("https://api.bscscan.com/api", BSCSCAN_API_KEY),
}

def etherscan_get_source(address: str, chain: str) -> Dict[str, Any]:
    base, key = ETHERSCAN_ENDPOINT[chain]
    if not key:
        return {"ok": False, "error": "no_api_key"}
    try:
        r = requests.get(base, params={
            "module":"contract","action":"getsourcecode","address":address,"apikey":key
        }, timeout=15)
        js = r.json()
        result = (js.get("result") or [])
        return {"ok": True, "result": result[0] if result else {}}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def etherscan_creator(address: str, chain: str) -> Dict[str, Any]:
    base, key = ETHERSCAN_ENDPOINT[chain]
    if not key:
        return {"ok": False, "error": "no_api_key"}
    try:
        r = requests.get(base, params={
            "module":"contract","action":"getcontractcreation","contractaddresses":address,"apikey":key
        }, timeout=15)
        js = r.json()
        result = (js.get("result") or [])
        return {"ok": True, "result": result[0] if result else {}}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def etherscan_txs_by_creator(creator: str, chain: str, limit: int=20) -> Dict[str, Any]:
    base, key = ETHERSCAN_ENDPOINT[chain]
    if not key:
        return {"ok": False, "error": "no_api_key"}
    try:
        r = requests.get(base, params={
            "module":"account","action":"txlist","address":creator,
            "startblock":0,"endblock":99999999,"page":1,"offset":limit,"sort":"desc",
            "apikey":key
        }, timeout=15)
        return {"ok": True, "result": r.json().get("result", [])}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------- Dexscreener ----------
def dexscreener_token(address: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{address}", timeout=15)
        return {"ok": True, "result": r.json().get("pairs", [])}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------- Risk heuristics ----------
def analyze_contract(address: str, chain: str) -> Dict[str, Any]:
    src = etherscan_get_source(address, chain)
    creator = etherscan_creator(address, chain)

    res: Dict[str, Any] = {"address": address, "chain": chain, "checks": []}

    if not src.get("ok"):
        res["checks"].append({"id":"source","status":"unknown","note":"explorer source unavailable","detail":src.get("error")})
    else:
        s = src["result"] or {}
        verified = bool(s.get("SourceCode"))
        is_proxy = (s.get("Proxy") == "1")
        impl     = s.get("Implementation") or ""
        res["checks"].append({"id":"verified","status":"pass" if verified else "fail",
                              "note":"contract verified" if verified else "contract NOT verified",
                              "meta":{"name": s.get("ContractName") or ""}})
        res["checks"].append({"id":"proxy","status":"warn" if is_proxy else "pass",
                              "note":"proxy detected (upgradeable)" if is_proxy else "no proxy flag",
                              "meta":{"implementation":impl if is_proxy else ""}})

    if not creator.get("ok"):
        res["checks"].append({"id":"creator","status":"unknown","note":"creator info unavailable","detail":creator.get("error")})
    else:
        cr = creator.get("result") or {}
        deployer = cr.get("contractCreator") or cr.get("creatorAddress") or ""
        txhash   = cr.get("txHash") or ""
        res["checks"].append({"id":"creator","status":"info","note":"creator & deploy tx","meta":{"creator":deployer,"tx":txhash}})
        if deployer:
            txs = etherscan_txs_by_creator(deployer, chain, 30)
            many = len(txs.get("result", []))
            res["checks"].append({"id":"creator_activity","status":"warn" if many>20 else "pass",
                                  "note":f"creator recent txs (last page): {many}"})

    ds = dexscreener_token(address)
    if not ds.get("ok"):
        res["checks"].append({"id":"dexscreener","status":"unknown","note":"dexscreener unavailable","detail":ds.get("error")})
    else:
        pairs = ds["result"]
        best_liq = 0.0
        youngest_days = None
        for p in pairs:
            liq = float(p.get("liquidity", {}).get("usd") or 0)
            if liq > best_liq:
                best_liq = liq
            ts = p.get("pairCreatedAt")
            if ts:
                age_days = max(0, (time.time() - int(ts)/1000) / 86400)
                youngest_days = age_days if youngest_days is None else min(youngest_days, age_days)
        res["checks"].append({
            "id":"liquidity",
            "status":"fail" if best_liq<5000 else "warn" if best_liq<20000 else "pass",
            "note":f"best liquidity ≈ ${int(best_liq):,}"
        })
        if youngest_days is not None:
            res["checks"].append({
                "id":"pair_age",
                "status":"warn" if youngest_days<7 else "pass",
                "note":f"youngest pair age ≈ {youngest_days:.1f} days"
            })
    return res

# ---------- LLM render ----------
def llm_render(lang: str, summary: Dict[str, Any]) -> str:
    messages = [
        {"role":"system", "content": SYSTEM_PROMPT.format(lang=lang)},
        {"role":"user", "content": json.dumps(summary, ensure_ascii=False)}
    ]
    try:
        resp = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=0.2,
            max_tokens=900,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        return f"[LLM error: {e}]\n\nRaw checks:\n{json.dumps(summary, ensure_ascii=False, indent=2)}"

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def root():
    return "OK", 200

@app.route("/webhook", methods=["GET","POST"])
def webhook():
    if request.method == "GET":
        return "OK", 200

    data = request.get_json(silent=True) or {}
    msg  = (data.get("message") or data.get("edited_message")) or {}
    chat = (msg.get("chat") or {})
    chat_id = chat.get("id")
    text = msg.get("text", "") or ""
    if not chat_id:
        return "ok", 200

    if text.strip().lower().startswith("/start"):
        lang = detect_lang((msg.get("from") or {}).get("language_code", "") or text)
        send_message(chat_id, WELCOME.get(lang, WELCOME["en"]))
        return "ok", 200

    lang = detect_lang(text)
    address = extract_address(text)
    chain = detect_chain(text)

    if address:
        summary = analyze_contract(address, chain)
        if not ETHERSCAN_API_KEY and chain == "eth":
            summary.setdefault("notes", []).append("etherscan key missing -> limited checks")
        if not BSCSCAN_API_KEY and chain == "bsc":
            summary.setdefault("notes", []).append("bscscan key missing -> limited checks")
        report = llm_render(lang, summary)
        send_message(chat_id, report)
        return "ok", 200

    # Общий вопрос -> LLM
    messages = [
        {"role":"system","content": SYSTEM_PROMPT.format(lang=lang)},
        {"role":"user","content": text},
    ]
    try:
        resp = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=0.3,
            max_tokens=800,
        )
        reply = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        reply = {
            "en": f"Model error: {e}\nPaste a contract (0x...) and I’ll analyze on-chain signals.",
            "ru": f"Ошибка модели: {e}\nВставьте адрес контракта (0x...) — выполню on-chain проверку.",
            "ar": f"خطأ في النموذج: {e}\nأرسل عنوان عقد (0x...) وسأجري فحصًا on-chain.",
            "zh": f"模型错误：{e}\n贴上合约地址 (0x...)，我会做链上检查。",
            "tr": f"Model hatası: {e}\nKontrat adresi (0x...) gönder, zincir üstü kontroller yapayım.",
        }.get(lang, f"Model error: {e}")

    send_message(chat_id, reply)
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
