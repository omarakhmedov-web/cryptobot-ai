# dex_client.py — Metridex market resolver (v0.4.2-SAFE)
# Goal: resolve ANY valid ERC-20 token address to a "market" dict for QuickScan/Details.
# - Uses DS proxy if provided (DEXSCREENER_PROXY_BASE / DS_PROXY_URL / DEX_BASE), else direct.
# - Token-first lookup, fallback to search, optional enrich of pairCreatedAt.
# - Returns COMPAT keys expected by server/report builders.
import os, re, time
import requests

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "6"))

def _build_bases():
    bases = []
    proxy = os.getenv("DS_PROXY_URL") or os.getenv("DEXSCREENER_PROXY_BASE") or os.getenv("DEX_BASE") or ""
    if proxy:
        proxy = proxy.strip().rstrip("/")
        if proxy and proxy not in bases:
            bases.append(proxy)
    env_list = os.getenv("DEXSCREENER_BASES", "")
    for tok in (t.strip().rstrip("/") for t in env_list.split(",") if t.strip()):
        if tok and tok not in bases:
            bases.append(tok)
    # Canonical endpoints last
    for canon in ("https://api.dexscreener.com", "https://io.dexscreener.com", "https://cdn.dexscreener.com"):
        if canon not in bases:
            bases.append(canon)
    if str(os.getenv("DEXSCREENER_FORCE_PROXY", "0")).strip().lower() in ("1","true","yes"):
        bases = [b for b in bases if not b.startswith("https://api.dexscreener.com")
                               and not b.startswith("https://io.dexscreener.com")
                               and not b.startswith("https://cdn.dexscreener.com")]
    return bases

DS_BASES = _build_bases()
_ADDR40 = re.compile(r"0x[a-fA-F0-9]{40}")

def _ds_get_json(path: str):
    last_err = None
    retries = int(float(os.getenv("DEXSCREENER_RETRIES", "2")))
    delay_ms = int(float(os.getenv("DEXSCREENER_RETRY_DELAY_MS", "300")))
    ua = os.getenv("HTTP_UA","MetridexBot/1.3")
    headers = {"User-Agent": ua, "Accept":"application/json", "Origin":"https://metridex.com"}
    for base in DS_BASES:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        attempt = 0
        while attempt <= retries:
            try:
                r = requests.get(url, timeout=HTTP_TIMEOUT, headers=headers)
                if r.ok:
                    return r.json()
                last_err = f"HTTP {r.status_code} from {url}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {e} @ {url}"
            attempt += 1
            if attempt <= retries and delay_ms > 0:
                time.sleep(delay_ms/1000.0)
    raise RuntimeError(f"DexScreener fetch failed: {last_err}")

def _normalize_chain(ch: str) -> str:
    ch = (ch or "").lower()
    m = {
        "ethereum":"ethereum","eth":"ethereum","1":"ethereum",
        "bsc":"bsc","binance":"bsc","binance smart chain":"bsc","56":"bsc",
        "polygon":"polygon","matic":"polygon","137":"polygon",
        "arbitrum":"arbitrum","arbitrum-one":"arbitrum","42161":"arbitrum",
        "base":"base","8453":"base",
        "optimism":"optimism","op":"optimism","10":"optimism",
        "avalanche":"avalanche","avax":"avalanche","43114":"avalanche",
        "fantom":"fantom","ftm":"fantom","250":"fantom",
    }
    return m.get(ch, ch or "ethereum")

def _pick_best_pair(pairs):
    if not isinstance(pairs, list) or not pairs:
        return None
    def liq_usd(p):
        try:
            return float(((p.get("liquidity") or {}).get("usd")) or 0.0)
        except Exception:
            return 0.0
    return sorted(pairs, key=liq_usd, reverse=True)[0]

def _enrich_pair(chain: str, pair_addr: str):
    chain = _normalize_chain(chain)
    pair_addr = (pair_addr or "").lower().strip()
    if not (chain and pair_addr):
        return {}
    try:
        j = _ds_get_json(f"latest/dex/pairs/{chain}/{pair_addr}")
        if isinstance(j, dict):
            dd = j.get("pair") or j.get("pairs") or j.get("data")
            if isinstance(dd, list) and dd:
                dd = dd[0]
            return dd if isinstance(dd, dict) else {}
    except Exception:
        return {}
    return {}

def fetch_market(text: str) -> dict:
    """
    Resolve user input to a market dict. Supports raw token 0x..., URLs with token,
    and (fallback) pair address via /search.
    Returns COMPAT keys expected by server:
      price, fdv, mc, liq, vol24h, priceChanges{m5,h1,h6,h24}, chain, pairAddress,
      tokenAddress, pairCreatedAt, links, pairSymbol, asOf, source.
    """
    raw = (text or "").strip()
    m = _ADDR40.search(raw)
    token = m.group(0).lower() if m else None
    if not token:
        return {"ok": False, "reason": "no_token"}

    # 1) Token endpoint
    j = None
    try:
        j = _ds_get_json(f"latest/dex/tokens/{token}")
    except Exception:
        pass

    # 2) Fallback: search endpoint (covers pair inputs, alt-chains, DS quirks)
    if not isinstance(j, dict) or not (j.get("pairs") or j.get("results") or j.get("data")):
        try:
            j = _ds_get_json(f"latest/dex/search?q={token}")
        except Exception:
            return {"ok": False, "reason": "ds_unavailable"}

    pairs = None
    if isinstance(j, dict):
        pairs = j.get("pairs") or j.get("results") or j.get("data")
    if not pairs:
        return {"ok": False, "reason": "no_pairs"}

    p = _pick_best_pair(pairs)
    if not p:
        return {"ok": False, "reason": "no_best_pair"}

    base = (p.get("baseToken") or {})
    quote = (p.get("quoteToken") or {})
    chain = _normalize_chain(p.get("chainId") or p.get("chain"))

    def _num(x, default=0.0):
        try:
            return float(x)
        except Exception:
            return default

    price_usd = _num(p.get("priceUsd"))
    fdv = _num(p.get("fdv"))
    mc = _num(p.get("marketCap"))
    liq_usd = _num((p.get("liquidity") or {}).get("usd"))
    vol24h = _num((p.get("volume") or {}).get("h24"))
    changes = (p.get("priceChange") or {})

    out = {
        "ok": True,
        "source": "DexScreener",
        "pairAddress": p.get("pairAddress") or p.get("pairId") or "",
        "tokenAddress": (base.get("address") or "").lower(),
        "chain": chain,
        "price": price_usd,
        "fdv": fdv,
        "mc": mc,
        "liq": liq_usd,
        "vol24h": vol24h,
        "priceChanges": {
            "m5": changes.get("m5"),
            "h1": changes.get("h1"),
            "h6": changes.get("h6"),
            "h24": changes.get("h24"),
        },
        "pairCreatedAt": p.get("pairCreatedAt"),
        "links": {
            "dexscreener": p.get("url") or "",
            "dexId": p.get("dexId") or "",
        },
        "pairSymbol": f"{(base.get('symbol') or '').strip()}/{(quote.get('symbol') or '').strip()}".strip("/"),
        "asOf": int(time.time()),
    }

    # Enrich missing pairCreatedAt (seconds)
    try:
        if not out.get("pairCreatedAt"):
            dd = _enrich_pair(chain, out["pairAddress"])
            ts = dd.get("pairCreatedAt") or dd.get("createdAt") or dd.get("launchedAt")
            if ts:
                if isinstance(ts, (int, float)) and ts > 10_000_000_000:
                    ts = int(ts // 1000)
                out["pairCreatedAt"] = ts
    except Exception:
        pass

    
    # --- Enrich missing priceChange from pair endpoint (reliable Δs) ---
    try:
        chg = out.get("priceChanges") or {}
        need = any(chg.get(k) in (None, "-", "—") for k in ("m5","h1","h6","h24"))
        if need and out.get("pairAddress") and out.get("chain"):
            dd = _enrich_pair(out["chain"], out["pairAddress"])
            if isinstance(dd, dict):
                pc = dd.get("priceChange") or {}
                for _k in ("m5","h1","h6","h24"):
                    if chg.get(_k) in (None, "-", "—") and (pc.get(_k) not in (None, "-", "—")):
                        chg[_k] = pc.get(_k)
                out["priceChanges"] = chg
    except Exception:
        pass

    # propagate website if available in token info
    try:
        if not out.get("website"):
            info = out.get("info") or {}
            if isinstance(info, dict):
                w = info.get("website") or info.get("url") or info.get("site")
                if w: out["website"] = w
    except Exception:
        pass
    return out
