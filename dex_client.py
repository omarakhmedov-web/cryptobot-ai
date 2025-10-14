import os, re, time, json
import requests

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))

def _build_bases():
    bases = []
    proxy = os.getenv("DS_PROXY_URL") or os.getenv("DEXSCREENER_PROXY_BASE") or ""
    if proxy:
        proxy = proxy.strip().rstrip("/")
        if proxy and proxy not in bases:
            bases.append(proxy)
    env_list = os.getenv("DEXSCREENER_BASES", "")
    for tok in (t.strip().rstrip("/") for t in env_list.split(",") if t.strip()):
        if tok and tok not in bases:
            bases.append(tok)
    for canon in ("https://api.dexscreener.com", "https://io.dexscreener.com", "https://cdn.dexscreener.com"):
        if canon not in bases:
            bases.append(canon)
    return bases

DS_BASES = _build_bases()

_ADDR40 = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ADDR64 = re.compile(r"^0x[a-fA-F0-9]{64}$")

def _pick_best_pair(pairs):
    if not isinstance(pairs, list) or not pairs:
        return None
    def _liq_usd(p):
        try:
            return float(((p.get("liquidity") or {}).get("usd")) or 0.0)
        except Exception:
            return 0.0
    pairs_sorted = sorted(pairs, key=_liq_usd, reverse=True)
    return pairs_sorted[0]

def _normalize_chain(ch):
    ch = (ch or "").lower()
    mapping = {
        "ethereum": "ethereum",
        "bsc": "bsc",
        "binance": "bsc",
        "polygon": "polygon",
        "matic": "polygon",
        "arbitrum": "arbitrum",
        "arbitrum-one": "arbitrum",
        "base": "base",
        "optimism": "optimism",
        "avalanche": "avalanche",
        "avalanche-c": "avalanche",
        "fantom": "fantom",
        "ftm": "fantom",
    }
    return mapping.get(ch, ch or "ethereum")

def _ds_get_json(path):
    last_err = None
    for base in DS_BASES:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "MetridexBot/1.2"})
            if r.ok:
                return r.json()
            last_err = "HTTP %s from %s" % (r.status_code, url)
        except Exception as e:
            last_err = "%s: %s" % (type(e).__name__, e)
            continue
    raise RuntimeError("DexScreener fetch failed: %s" % last_err)

def _extract_market_from_pair(p):
    m = {"ok": True}
    m["pairAddress"] = p.get("pairAddress") or p.get("pairId") or "—"
    base_token = (p.get("baseToken") or {})
    quote_token = (p.get("quoteToken") or {})
    m["tokenAddress"] = (base_token.get("address") or "").lower() or "—"
    m["chain"] = _normalize_chain(p.get("chainId") or p.get("chain"))
    try:
        m["priceUsd"] = float(p.get("priceUsd") or 0.0)
    except Exception:
        m["priceUsd"] = 0.0
    try:
        m["fdv"] = float((p.get("fdv")) or 0.0)
    except Exception:
        m["fdv"] = 0.0
    try:
        m["marketCap"] = float((p.get("marketCap")) or 0.0)
    except Exception:
        m["marketCap"] = 0.0
    liq = (p.get("liquidity") or {})
    try:
        m["liquidityUsd"] = float(liq.get("usd") or 0.0)
    except Exception:
        m["liquidityUsd"] = 0.0
    vol = (p.get("volume") or {})
    try:
        m["volume24h"] = float(vol.get("h24") or (p.get("txns") or {}).get("h24") or 0.0)
    except Exception:
        m["volume24h"] = 0.0
    ch = (p.get("priceChange") or {})
    m["priceChanges"] = {
        "m5": ch.get("m5"),
        "h1": ch.get("h1"),
        "h6": ch.get("h6"),
        "h24": ch.get("h24"),
    }
    m["asOf"] = int(time.time())
    if "pairCreatedAt" in p and p.get("pairCreatedAt"):
        try:
            ts = int(p["pairCreatedAt"])
            if ts > 10000000000:
                ts = ts // 1000
            m["pairCreatedAt"] = ts
        except Exception:
            pass
    m["links"] = {
        "dexscreener": p.get("url") or "",
        "dexId": p.get("dexId") or "",
    }
    return m

def fetch_market(text):
    text = (text or "").strip()
    token = None
    if _ADDR40.match(text):
        token = text
    if not token:
        m = re.search(r"0x[a-fA-F0-9]{40}", text)
        if m:
            token = m.group(0)
    if not token:
        return {"ok": False, "reason": "no_token"}
    try:
        j = _ds_get_json("latest/dex/tokens/%s" % token)
    except Exception:
        try:
            j = _ds_get_json("latest/dex/search?q=%s" % token)
        except Exception:
            return {"ok": False, "reason": "ds_unavailable"}
    pairs = None
    if isinstance(j, dict):
        pairs = j.get("pairs") or j.get("results") or j.get("data")
    if not pairs:
        return {"ok": False, "reason": "no_pairs"}
    best = _pick_best_pair(pairs)
    if not best:
        return {"ok": False, "reason": "no_best_pair"}
    return _extract_market_from_pair(best)
