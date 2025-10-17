# MDX_PATCH_2025_10_17 v4 — DS timeout=6s
import os, re, time
import requests

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "6"))

def _build_bases():
    bases = []
    # Prefer explicit proxy (Render env: DS_PROXY_URL or DEXSCREENER_PROXY_BASE)
    proxy = os.getenv("DS_PROXY_URL") or os.getenv("DEXSCREENER_PROXY_BASE") or ""
    if proxy:
        proxy = proxy.strip().rstrip("/")
        if proxy and proxy not in bases:
            bases.append(proxy)
    # Optional comma-separated list
    env_list = os.getenv("DEXSCREENER_BASES", "")
    for tok in (t.strip().rstrip("/") for t in env_list.split(",") if t.strip()):
        if tok and tok not in bases:
            bases.append(tok)
    # Canonical endpoints last
    for canon in ("https://api.dexscreener.com", "https://io.dexscreener.com", "https://cdn.dexscreener.com"):
        if canon not in bases:
            bases.append(canon)
    return bases

DS_BASES = _build_bases()

_ADDR40 = re.compile(r"^0x[a-fA-F0-9]{40}$")

def _ds_get_json(path: str):
    last_err = None
    for base in DS_BASES:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": os.getenv("HTTP_UA","MetridexBot/1.2")})
            if r.ok:
                try:
                    return r.json()
                except Exception as e:
                    last_err = f"Bad JSON from {url}: {e}"
                    continue
            last_err = f"HTTP {r.status_code} from {url}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e} @ {url}"
            continue
    raise RuntimeError(f"DexScreener fetch failed: {last_err}")


def _fetch_pair_details(chain: str, pair_addr: str) -> dict:
    """Fetch a single pair's details to enrich missing fields like pairCreatedAt."""
    chain = _normalize_chain(chain)
    pair_addr = (pair_addr or '').lower().strip()
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


def _pick_best_pair(pairs):
    if not isinstance(pairs, list) or not pairs:
        return None
    def _liq_usd(p):
        try:
            return float(((p.get('liquidity') or {}).get('usd')) or 0.0)
        except Exception:
            return 0.0
    return sorted(pairs, key=_liq_usd, reverse=True)[0]

def _normalize_chain(ch):
    ch = (ch or "").lower()
    mapping = {
        "ethereum": "ethereum", "eth": "ethereum",
        "bsc": "bsc", "binance": "bsc", "binance smart chain":"bsc",
        "polygon": "polygon", "matic": "polygon",
        "arbitrum": "arbitrum", "arbitrum-one":"arbitrum",
        "base": "base", "optimism":"optimism", "op":"optimism",
        "avalanche":"avalanche", "avalanche-c":"avalanche",
        "fantom":"fantom", "ftm":"fantom",
    }
    return mapping.get(ch, ch or "ethereum")

def _num(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def fetch_market(text: str) -> dict:
    '''
    Input: raw text. Extract first 0x-address (40 hex) and query DexScreener.
    Output: dict with COMPAT keys expected by server (_build_html_report expects these names):
      price, fdv, mc, liq, vol24h, priceChanges, chain, pairAddress, tokenAddress, pairCreatedAt, links, pairSymbol
    '''
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

    # Primary endpoint + fallback search
    try:
        j = _ds_get_json(f"latest/dex/tokens/{token}")
    except Exception:
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

    # Canonical metrics from DS
    price_usd = _num(p.get("priceUsd"), 0.0)
    fdv = _num(p.get("fdv"), 0.0)
    mc = _num(p.get("marketCap"), 0.0)
    # FDV/MC reconciliation: enforce FDV >= MC when both positive
    if fdv > 0 and mc > 0 and fdv < mc:
        fdv, mc = mc, fdv
    liq_usd = _num((p.get("liquidity") or {}).get("usd"), 0.0)
    vol24h = _num((p.get("volume") or {}).get("h24") or (p.get("txns") or {}).get("h24"), 0.0)
    changes = (p.get("priceChange") or {})

    # Build COMPAT structure expected by server.py report builders
    out = {
        "ok": True,
        "pairAddress": p.get("pairAddress") or p.get("pairId") or "",
        "tokenAddress": (base.get("address") or "").lower(),
        "chain": chain,
        # COMPAT keys (server expects these exact names):
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
        # Additional
        "pairCreatedAt": int(p.get("pairCreatedAt")/1000) if isinstance(p.get("pairCreatedAt"), (int, float)) and p.get("pairCreatedAt") > 10_000_000_000 else p.get("pairCreatedAt"),
        "links": {
            "dexscreener": p.get("url") or "",
            "dexId": p.get("dexId") or "",
        },
        "pairSymbol": f"{base.get('symbol') or ''}/{quote.get('symbol') or ''}".strip("/"),
        "asOf": int(time.time()),
    }
    
    # ENRICH_PAIR_CREATED_AT: ensure pairCreatedAt is populated
    try:
        if not out.get("pairCreatedAt"):
            _pc = _fetch_pair_details(chain, out.get("pairAddress"))
            _pcts = _pc.get("pairCreatedAt") or _pc.get("createdAt") or _pc.get("launchedAt")
            if _pcts:
                if isinstance(_pcts, (int, float)) and _pcts > 10_000_000_000:
                    _pcts = int(_pcts // 1000)
                out["pairCreatedAt"] = _pcts
    except Exception:
        pass
    # Derive ageDays from pairCreatedAt if present
    try:
        ts = out.get('pairCreatedAt')
        if ts and isinstance(ts, (int, float)) and ts > 0:
            import time
            out['ageDays'] = max(0.0, (time.time() - float(ts)) / 86400.0)
        else:
            out['ageDays'] = None
    except Exception:
        out['ageDays'] = None


    return out
