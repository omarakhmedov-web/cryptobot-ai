# dex_client.py — Metridex market resolver (v0.4.3-DETERMINISTIC)
# Purpose: deterministic resolution for ANY valid ERC-20 address (ETH/BSC/Polygon),
# with stable fallbacks and strict timeouts, without changing server interface.
#
# Exported API (compat):
#   fetch_market(text: str) -> dict
#
# Environment (compat):
#   HTTP_TIMEOUT_SECONDS (default 6)
#   DEXSCREENER_RETRIES (default 2)
#   DEXSCREENER_RETRY_DELAY_MS (default 300)
#   DS_PROXY_URL | DEXSCREENER_PROXY_BASE | DEX_BASE (optional)
#
import os, re, time
import requests

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "6"))
_ADDR40 = re.compile(r"0x[a-fA-F0-9]{40}")

def _build_bases():
    bases = []
    proxy = os.getenv("DS_PROXY_URL") or os.getenv("DEXSCREENER_PROXY_BASE") or os.getenv("DEX_BASE") or ""
    if proxy:
        proxy = proxy.strip().rstrip("/")
        if proxy:
            bases.append(proxy)
    # add official (kept last)
    bases += [
        "https://api.dexscreener.com",
        "https://io.dexscreener.com",
    ]
    # dedup + filter cdn
    out = []
    for b in bases:
        if b and b not in out and not b.startswith("https://cdn.dexscreener.com"):
            out.append(b)
    return out

DS_BASES = _build_bases()

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
    ch = (ch or "").lower().strip()
    if ch in ("eth","ethereum"): return "ethereum"
    if ch in ("bsc","binance-smart-chain","binance"): return "bsc"
    if ch in ("polygon","matic"): return "polygon"
    return ch or "ethereum"

def _num(x):
    try:
        return float(x)
    except Exception:
        try:
            return int(x)
        except Exception:
            return None

def _first(lst):
    return lst[0] if isinstance(lst, list) and lst else None

def _ds_token(token: str):
    """Token-first lookup."""
    j = _ds_get_json(f"latest/dex/tokens/{token}")
    if isinstance(j, dict):
        data = j.get("pairs") or j.get("data") or j.get("pair") or []
        if isinstance(data, dict):
            data = [data]
        return [p for p in (data or []) if isinstance(p, dict)]
    return []

def _ds_search(token: str):
    """Fallback search when token lookup is empty or throttled."""
    j = _ds_get_json(f"latest/dex/search?q={token}")
    if isinstance(j, dict):
        data = j.get("pairs") or j.get("data") or []
        if isinstance(data, dict):
            data = [data]
        return [p for p in (data or []) if isinstance(p, dict)]
    return []

def _enrich_pair(chain: str, pair_addr: str) -> dict:
    """Fetch pair details to fill missing fields (pairCreatedAt, priceChange, url)."""
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

def _score_pair(p: dict) -> tuple:
    """Deterministic comparator key: prefer higher liquidity, fresher update, stable quote (WETH/WBNB/WMATIC/USDT/USDC)."""
    liq_usd = _num((p.get("liquidity") or {}).get("usd")) or -1
    ts = _num(p.get("updatedAt") or p.get("pairCreatedAt")) or -1
    sym = (p.get("baseToken") or {}).get("symbol") or ""
    quote = (p.get("quoteToken") or {}).get("symbol") or ""
    quote_rank = {"WETH":5,"WBNB":5,"WMATIC":5,"USDT":4,"USDC":4}.get(quote.upper(), 1)
    # higher is better for liq, ts, quote_rank
    return (-liq_usd * 1.0, -ts, -quote_rank, sym.upper())

def _choose_best(pairs: list) -> dict | None:
    if not pairs:
        return None
    try:
        pairs_sorted = sorted(pairs, key=_score_pair)
        return pairs_sorted[0]
    except Exception:
        return _first(pairs)

def _ensure_changes(p: dict, fallback: dict) -> dict:
    ch = p.get("priceChange") or {}
    if all(k in ch for k in ("m5","h1","h6","h24")) and all(ch.get(k) is not None for k in ("m5","h1","h6","h24")):
        return ch
    # Try to enrich from pair endpoint
    try:
        chain = p.get("chain") or p.get("chainId") or (fallback.get("chain") if isinstance(fallback, dict) else None)
        addr = p.get("pairAddress") or p.get("pairId")
        if chain and addr:
            detail = _enrich_pair(chain, addr)
            ch2 = (detail.get("priceChange") or {})
            out = {"m5": ch.get("m5"), "h1": ch.get("h1"), "h6": ch.get("h6"), "h24": ch.get("h24")}
            for k in ("m5","h1","h6","h24"):
                if out.get(k) is None and ch2.get(k) is not None:
                    out[k] = ch2.get(k)
            return out
    except Exception:
        pass
    # Fallback with safe None
    return {"m5": ch.get("m5"), "h1": ch.get("h1"), "h6": ch.get("h6"), "h24": ch.get("h24")}

def fetch_market(text: str) -> dict:
    """
    Resolve user input to a market dict. Supports raw token 0x..., URLs with token,
    and (fallback) search.
    Returns COMPAT keys expected by server:
      price, fdv, mc, liq, vol24h, priceChanges{m5,h1,h6,h24}, chain, pairAddress,
      tokenAddress, pairCreatedAt, links.dexscreener, pairSymbol, asOf, source, ok, reason(optional)
    """
    raw = (text or "").strip()
    m = _ADDR40.search(raw)
    token = m.group(0).lower() if m else None
    if not token:
        return {"ok": False, "reason": "no_token"}

    # 1) token-first
    pairs = []
    try:
        pairs = _ds_token(token)
    except Exception:
        pairs = []
    # 2) fallback search (covers alt chains or DS partials)
    if not pairs:
        try:
            pairs = _ds_search(token)
        except Exception:
            pairs = []

    # No pools → deterministic "no pools" output
    if not pairs:
        return {
            "ok": True,
            "source": "DexScreener",
            "pairAddress": "",
            "tokenAddress": token,
            "chain": "",
            "price": None, "fdv": None, "mc": None,
            "liq": None, "vol24h": None,
            "priceChanges": {"m5": None, "h1": None, "h6": None, "h24": None},
            "pairCreatedAt": None,
            "links": {"dexscreener": ""},
            "pairSymbol": "",
            "asOf": int(time.time()*1000),
            "notTradable": True,
            "reason": "no_pools"
        }

    # Choose best pair deterministically
    best = _choose_best(pairs) or pairs[0]
    chain = _normalize_chain(best.get("chainId") or best.get("chain"))
    # Enrich missing fields
    detail = {}
    try:
        detail = _enrich_pair(chain, best.get("pairAddress") or best.get("pairId") or "")
    except Exception:
        detail = {}

    def g(d, *keys, default=None):
        cur = d
        for k in keys:
            if not isinstance(cur, dict): return default
            cur = cur.get(k)
        return cur if cur is not None else default

    p = {**best, **({} if not isinstance(detail, dict) else detail)}
    price_usd = _num(p.get("priceUsd"))
    fdv = _num(p.get("fdv"))
    mc = _num(p.get("marketCap"))
    liq_usd = _num(g(p, "liquidity", "usd"))
    vol24h = _num(g(p, "volume", "h24"))
    # Price change normalization
    changes = _ensure_changes(p, {"chain": chain, "pairAddress": g(p,"pairAddress") or g(p,"pairId")})

    out = {
        "ok": True,
        "source": "DexScreener",
        "pairAddress": g(p,"pairAddress") or g(p,"pairId") or "",
        "tokenAddress": (g(p,"baseToken","address") or g(p,"info","address") or token or "").lower(),
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
        "links": {"dexscreener": p.get("url") or ""},
        "pairSymbol": p.get("pairSymbol") or (f"{g(p,'baseToken','symbol')}/{g(p,'quoteToken','symbol')}" if g(p,'baseToken','symbol') and g(p,'quoteToken','symbol') else ""),
        "asOf": int(time.time()*1000),
    }

    # propagate website to keep existing renderers happy
    try:
        if not out.get("website"):
            info = p.get("info") or {}
            if isinstance(info, dict):
                w = info.get("website") or info.get("url") or info.get("site")
                if w: out["website"] = w
    except Exception:
        pass

    return out
