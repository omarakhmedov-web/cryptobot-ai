from __future__ import annotations
import os, re, time
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlparse
import requests
from age_fallback import resolve_pair_age_days

# ===== Config =====
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS","10"))
UA = os.getenv("HTTP_UA","MetridexBot/1.0 (+https://metridex.com)")
HEADERS = {"User-Agent": UA, "Accept": "application/json"}

# DexScreener bases (proxy first, then canonical + CDN)
DS_PROXY_BASE = (os.getenv("DEXSCREENER_PROXY_BASE") or os.getenv("DS_PROXY_BASE") or "").strip()
DS_BASES: List[str] = ([DS_PROXY_BASE] if DS_PROXY_BASE else []) + [
    b.strip() for b in ("https://api.dexscreener.com,https://io.dexscreener.com,https://www.dexscreener.com,https://cdn.dexscreener.com").split(",")
    if b.strip()
]

# Chain alias maps used by DS
DS_CHAIN_FROM_SHORT = {
    "eth":"ethereum", "ethereum":"ethereum",
    "bsc":"bsc", "binance smart chain":"bsc", "bnb":"bsc",
    "polygon":"polygon", "matic":"polygon",
    "arb":"arbitrum", "arbitrum":"arbitrum",
    "op":"optimism", "optimism":"optimism",
    "base":"base",
    "avax":"avalanche", "avalanche":"avalanche",
    "ftm":"fantom", "fantom":"fantom",
    "sol":"solana", "solana":"solana",
}

# Explorers (for "Open in Scan")
SCAN_HOST = {
    "ethereum": "etherscan.io",
    "bsc": "bscscan.com",
    "polygon": "polygonscan.com",
    "arbitrum": "arbiscan.io",
    "optimism": "optimistic.etherscan.io",
    "base": "basescan.org",
    "avalanche": "snowtrace.io",
    "fantom": "ftmscan.com",
    "solana": "solscan.io",
}

# ===== HTTP =====
def _http_get_json(url: str, params: Dict[str, Any] | None = None) -> Tuple[int, Any]:
    try:
        r = requests.get(url, params=params or {}, timeout=HTTP_TIMEOUT, headers=HEADERS)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 599, {"error": str(e)}

def _ds_get(path: str) -> Tuple[int, Any]:
    """Try multiple DexScreener hosts until one succeeds."""
    last_code, last_body = 599, {"error": "no hosts"}
    for base in DS_BASES:
        url = base.rstrip("/") + path
        code, body = _http_get_json(url)
        if code == 200 and isinstance(body, dict):
            return code, body
        last_code, last_body = code, body
    return last_code, last_body

# ===== Normalization =====
def _normalize_market(ds: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DexScreener 'pair' dict into a canonical market dict."""
    base_sym = ((ds.get('baseToken') or {}).get('symbol') or ds.get('symbol') or '?')
    quote_sym = ((ds.get('quoteToken') or {}).get('symbol') or ds.get('quoteSymbol') or '?')
    pair_symbol = ds.get('pairSymbol') or f"{base_sym}/{quote_sym}"
    price = ds.get('priceUsd')
    liq = ((ds.get('liquidity') or {}).get('usd')
           or ds.get('liquidityUsd') or ds.get('liquidityUSD'))
    pc = ds.get('priceChange') or {}
    # Map chain id/name to DS canonical
    chain_id = (ds.get('chainId') or ds.get('chain') or '—')
    chain_id = str(chain_id).strip().lower()
    for k,v in DS_CHAIN_FROM_SHORT.items():
        if chain_id == k:
            chain_id = v; break

    m: Dict[str, Any] = {
        'ok': True,
        'chain': chain_id or '—',
        'pairSymbol': pair_symbol,
        'price': _to_float(price),
        'fdv': _to_float(ds.get('fdv')),
        'mc': _to_float(ds.get('marketCap')),
        'liq': _to_float(liq),
        'vol24h': _to_float((ds.get('volume') or {}).get('h24')),
        'priceChanges': {
            'm5': _to_float((pc or {}).get('m5')),
            'h1': _to_float((pc or {}).get('h1')),
            'h24': _to_float((pc or {}).get('h24')),
        },
        'pairAddress': ds.get('pairAddress'),
        'baseAddress': (ds.get('baseToken') or {}).get('address'),
        'quoteAddress': (ds.get('quoteToken') or {}).get('address'),
        'tokenAddress': (ds.get('baseToken') or {}).get('address'),
        'source': 'DexScreener',
        'sources': ['DexScreener'],
        'links': {},
    }

    # Age fallback
    pcat = ds.get('pairCreatedAt') or ds.get('pairCreatedAtMs')
    if pcat:
        try:
            ts = int(pcat)
            if ts < 10**12:  # seconds -> ms
                ts *= 1000
            m['asof'] = int(time.time() * 1000)
            m['ageDays'] = max(0.0, (m['asof'] - ts) / 1000.0 / 86400.0)
        except Exception:
            pass

    # Links
    tkn = m.get('tokenAddress') or ''
    ch = m.get('chain') or '—'
    pair_addr = m.get('pairAddress') or ''
    site = (ds.get('info') or {}).get('website') or ((ds.get('info') or {}).get('websites') or [None])[0]
    l_dex = _swap_url(ch, tkn) or '—'
    l_scan = _scan_url(ch, tkn) or '—'
    l_ds   = _ds_pair_url(ch, pair_addr) if pair_addr else None
    m['links'] = {'dex': l_dex, 'scan': l_scan}
    if site: m['links']['site'] = site
    if l_ds: m['links']['dexscreener'] = l_ds

    # Supply-based fixes
    try:
        price_f = float(price) if price is not None else None
        total_supply = ((ds.get('fdvInfo') or {}).get('totalSupply')
                        or (ds.get('supply') or {}).get('total'))
        circ_supply  = ((ds.get('marketCapInfo') or {}).get('circulating')
                        or (ds.get('supply') or {}).get('circulating'))
        if (m.get('fdv') in (None, 0)) and total_supply and price_f:
            m['fdv'] = float(total_supply) * float(price_f)
        if (m.get('mc') in (None, 0)) and circ_supply and price_f:
            m['mc'] = float(circ_supply) * float(price_f)
        # Enforce FDV >= MC when both present
        fdv = float(m['fdv']) if m.get('fdv') is not None else None
        mc  = float(m['mc'])  if m.get('mc')  is not None else None
        if fdv is not None and mc is not None and fdv < mc:
            m['fdv'] = mc
    except Exception:
        pass

    return _apply_age_fallback(m)

def _to_float(x: Any) -> Optional[float]:
    try:
        return float(x) if x is not None else None
    except Exception:
        return None

def _short_chain(ch: str | None) -> str:
    s = (ch or '').strip().lower()
    for k,v in DS_CHAIN_FROM_SHORT.items():
        if s == k: return v
    return s or '—'

def _swap_url(chain: str, token: str) -> Optional[str]:
    c = _short_chain(chain)
    t = (token or '').strip()
    if not t: return None
    if c in ('ethereum','arbitrum','optimism','base'):
        return f"https://app.uniswap.org/#/swap?outputCurrency={t}"
    if c in ('bsc',):
        return f"https://pancakeswap.finance/swap?outputCurrency={t}"
    if c in ('polygon',):
        return f"https://quickswap.exchange/#/swap?outputCurrency={t}"
    return None

def _scan_url(chain: str, token: str) -> Optional[str]:
    c = _short_chain(chain)
    host = SCAN_HOST.get(c)
    if not host or not token: return None
    if c == 'solana':
        return f"https://{host}/token/{token}"
    return f"https://{host}/token/{token}"

def _ds_pair_url(chain: str, pair: str) -> Optional[str]:
    c = _short_chain(chain)
    if c == '—' or not pair: return None
    return f"https://dexscreener.com/{c}/{pair}"


def _apply_age_fallback(m: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if not m.get("ageDays"):
            ch = m.get("chain")
            pair = m.get("pairAddress")
            if ch and pair:
                age = resolve_pair_age_days(ch, pair)
                if age is not None:
                    m["ageDays"] = age
                    m["asof"] = int(time.time() * 1000)
    except Exception:
        pass
    return _apply_age_fallback(m)

# ===== DexScreener adapters =====
def _ds_by_pair(chain: str | None, pair: str) -> Dict[str, Any]:
    if not pair: return {"ok": False, "error": "no pair"}
    chain_id = DS_CHAIN_FROM_SHORT.get((chain or '').lower(), (chain or '')).lower() if chain else ''
    path = f"/latest/dex/pairs/{chain_id}/{pair}" if chain_id else f"/latest/dex/pairs/{pair}"
    code, d = _ds_get(path)
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no pairs"}
    best = max(pairs, key=lambda x: ((x.get("liquidity") or {}).get("usd") or 0))
    m = _normalize_market(best); m["ok"] = True
    m = _apply_age_fallback(m)
    return _apply_age_fallback(m)

def _ds_by_token(token: str) -> Dict[str, Any]:
    if not token: return {"ok": False, "error": "no token"}
    code, d = _ds_get(f"/latest/dex/tokens/{token}")
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": f"dexscreener {code}"}
    pairs = d.get("pairs") or []
    if not pairs:
        return {"ok": False, "error": "no pairs"}
    # Prefer best liquidity
    best = max(pairs, key=lambda x: ((x.get("liquidity") or {}).get("usd") or 0))
    m = _normalize_market(best); m["ok"] = True
    m = _apply_age_fallback(m)
    return _apply_age_fallback(m)

# ===== Query parsing =====
ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
PAIR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")  # DS pair address
TX_RE   = re.compile(r"^0x[a-fA-F0-9]{64}$")

def enabled_networks() -> List[str]:
    env = (os.getenv("ENABLED_NETWORKS") or "eth,bsc,polygon").split(",")
    out = []
    for e in env:
        e = e.strip().lower()
        if not e: continue
        out.append(e)
    return out

def _parse_query(q: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    q = (q or "").strip()
    if not q: return None, None, None
    # Plain addresses: token or pair
    if ADDR_RE.match(q):
        # Leave disambiguation to DS calls
        return None, q, None
    # URLs
    try:
        u = urlparse(q)
        if u.scheme and u.netloc:
            h = u.netloc.lower()
            p = u.path
            if "dexscreener.com" in h:
                parts = [x for x in p.split("/") if x]
                if len(parts) >= 3:
                    return parts[0], None, parts[-1]
            if "etherscan.io" in h or "bscscan.com" in h or "polygonscan.com" in h:
                # /token/<addr>
                segs = [x for x in p.split("/") if x]
                if "token" in segs:
                    i = segs.index("token")
                    if i+1 < len(segs) and ADDR_RE.match(segs[i+1]):
                        return None, segs[i+1], None
    except Exception:
        pass
    # TX or unknown -> no market
    if TX_RE.match(q): return None, None, None
    return None, None, None

# ===== Public API =====
def fetch_market(_pos: str | None = None, *, chain: str | None = None, token: str | None = None, pair: str | None = None) -> Dict[str, Any]:
    # Resolve positional
    if _pos and not (chain or token or pair):
        c,t,p = _parse_query(_pos); chain = chain or c; token = token or t; pair = pair or p

    # If 'chain' is actually a token address
    if chain and ADDR_RE.match(chain):
        token = token or chain; chain = None

    # Token only -> best across chains
    if token and not pair:
        m = _ds_by_token(token)
        if m.get("ok"):
            return _apply_age_fallback(m)

    # Pair only -> try with chain hint or across enabled
    if pair and not chain:
        for ch in enabled_networks():
            m = _ds_by_pair(ch, pair)
            if m.get("ok"): return _apply_age_fallback(m)

    # Pair + chain hint
    if pair and chain:
        m = _ds_by_pair(chain, pair)
        if m.get("ok"): return _apply_age_fallback(m)

    # Token + chain hint (rare)
    if token and chain:
        m = _ds_by_token(token)
        if m.get("ok") and (m.get("chain") == DS_CHAIN_FROM_SHORT.get(chain, chain)):
            return _apply_age_fallback(m)

    # Not found -> structured "no pools" market
    out = {"ok": False, "error": "no market found", "sources": ['DexScreener'], "chain": chain or "—", "links": {}}
    if token: out["tokenAddress"] = token
    if pair:  out["pairAddress"] = pair
    return out
