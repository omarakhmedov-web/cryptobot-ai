
import os
import re
import time
from urllib.parse import urlparse, quote_plus

from utils import http_get_json, http_post_json, rdap_domain, wayback_first_capture, ssl_certificate_info, format_kv, locale_text as _

DEX_BASE = os.environ.get("DEX_BASE", "https://api.dexscreener.com").rstrip("/")

def ds_url(path_qs: str) -> str:
    if not path_qs.startswith("/"):
        path_qs = "/" + path_qs
    return f"{DEX_BASE}{path_qs}"

DEX_API_SEARCH = lambda q: ds_url(f"/latest/dex/search?q={quote_plus(q)}")
DEX_API_PAIR   = lambda chain, pair: ds_url(f"/latest/dex/pairs/{chain}/{pair}")
DEX_API_TOKEN_POOLS = lambda chain, token: ds_url(f"/token-pairs/v1/{chain}/{token}")

UNISWAP_V3_SUBGRAPH = "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3"

CHAIN_GUESS = [
    "ethereum", "base", "arbitrum", "optimism", "polygon",
    "bsc", "avalanche", "fantom", "blast", "linea",
    "scroll", "mantle", "zksync", "opbnb"
]

ADDRESS_RE = re.compile(r'(0x[a-fA-F0-9]{40})')
PAIR_RE = re.compile(r'/(?:pair|pairs)/([a-z0-9\-]+)/([A-Za-z0-9]+)')
TOKEN_RE = re.compile(r'/token/([a-z0-9\-]+)/([A-Za-z0-9]+)')

def normalize_input(s: str) -> str:
    s = s.strip()
    m = ADDRESS_RE.search(s)
    if m:
        return m.group(1).lower()
    try:
        u = urlparse(s if "://" in s else ("http://" + s))
        if u.netloc:
            return s
    except Exception:
        pass
    return s

class SafeCache:
    def __init__(self, ttl: int = 600):
        self.ttl = ttl
        self._store = {}

    def get(self, key):
        now = time.time()
        rec = self._store.get(key)
        if rec and rec["exp"] > now:
            return rec["val"]
        if rec:
            self._store.pop(key, None)
        return None

    def set(self, key, val):
        self._store[key] = {"val": val, "exp": time.time() + self.ttl}

cache = SafeCache(ttl=int(os.environ.get("CACHE_TTL_SECONDS", "600")))

def best_pair(pairs):
    if not pairs:
        return None
    def score(p):
        liq = (p.get("liquidity") or {}).get("usd") or 0
        vol24 = (p.get("volume") or {}).get("h24") or 0
        tvl = p.get("tvlUsd") or 0
        return (liq or tvl, vol24)
    return sorted(pairs, key=score, reverse=True)[0]

def summarize_pair(p, window="24h"):
    base = p.get("baseToken", {}) or {}
    quote = p.get("quoteToken", {}) or {}
    lines = []

    if p.get("_src") == "uniswap":
        lines.append(f'{base.get("symbol","?")}/{quote.get("symbol","?")} on Uniswap v3 (ethereum)')
        lines.append(format_kv({
            "TVL (USD)": p.get("tvlUsd"),
            "Fee": p.get("feeTier"),
            "Pool": p.get("poolId")
        }))
        if p.get("site"):
            lines.append("Site: " + p["site"])
        return "\n".join([l for l in lines if l])

    liq = p.get("liquidity") or {}
    vol = p.get("volume") or {}
    chg = p.get("priceChange") or {}
    info = p.get("info") or {}
    lines.append(f'{base.get("symbol","?")}/{quote.get("symbol","?")} on {p.get("dexId","?")} ({p.get("chainId","?")})')
    price_usd = p.get("priceUsd")
    if price_usd:
        lines.append(f'Price: ${price_usd}')
    lines.append(format_kv({
        "FDV": p.get("fdv"),
        "MC": p.get("marketCap"),
        "Liq (USD)": liq.get("usd"),
        "Vol 24h": vol.get("h24")
    }))
    if window in chg:
        lines.append(f'Delta {window}: {chg.get(window)}%')
    wsites = [w.get("url") for w in (info.get("websites") or []) if w.get("url")]
    socials = info.get("socials") or []
    if wsites:
        lines.append("Site: " + wsites[0])
    if socials:
        s0 = socials[0]
        handle = s0.get("handle")
        if handle:
            lines.append(f'{s0.get("platform")}: {handle}')
    return "\n".join([l for l in lines if l])

def extract_contract_and_chain(user_input):
    s = user_input.strip()
    m = PAIR_RE.search(s)
    if m:
        return (m.group(1), None, m.group(2))
    m = TOKEN_RE.search(s)
    if m:
        return (m.group(1), m.group(2), None)
    m = ADDRESS_RE.search(s)
    if m:
        return (None, m.group(1), None)
    return (None, None, None)

def run_uniswap_fallback(token_address):
    q = """
    query($addr: Bytes!) {
      pools0: pools(first: 5, orderBy: totalValueLockedUSD, orderDirection: desc, where:{token0: $addr}) {
        id feeTier totalValueLockedUSD token0 { symbol } token1 { symbol }
      }
      pools1: pools(first: 5, orderBy: totalValueLockedUSD, orderDirection: desc, where:{token1: $addr}) {
        id feeTier totalValueLockedUSD token0 { symbol } token1 { symbol }
      }
    }
    """
    data = http_post_json(UNISWAP_V3_SUBGRAPH, {"query": q, "variables": {"addr": token_address.lower()}})
    pools = []
    try:
        for p in (data.get("data", {}).get("pools0") or []) + (data.get("data", {}).get("pools1") or []):
            pools.append({
                "_src": "uniswap",
                "baseToken": {"symbol": p.get("token0",{}).get("symbol")},
                "quoteToken": {"symbol": p.get("token1",{}).get("symbol")},
                "tvlUsd": float(p.get("totalValueLockedUSD") or 0),
                "feeTier": p.get("feeTier"),
                "poolId": p.get("id"),
                "info": {"websites": [{"url": "https://app.uniswap.org/"}]},
                "chainId": "ethereum",
                "dexId": "uniswap-v3"
            })
    except Exception:
        return []
    return pools

def run_dexscreener(user_input):
    chain, token, pair = extract_contract_and_chain(user_input)
    pairs = []

    # 0) Search-first
    q = token or user_input
    data = http_get_json(DEX_API_SEARCH(q))
    if data and "pairs" in data and data["pairs"]:
        pairs.extend(data["pairs"])

    # 1) Pair URL exact
    if pair and chain and not pairs:
        data = http_get_json(DEX_API_PAIR(chain, pair))
        if data and "pairs" in data:
            pairs.extend(data["pairs"] or [])

    # 2) Token URL exact
    if token and chain and not pairs:
        data = http_get_json(DEX_API_TOKEN_POOLS(chain, token))
        if isinstance(data, list):
            pairs.extend(data)

    # 3) Raw address → probe common chains
    if token and not pairs:
        for ch in CHAIN_GUESS:
            data = http_get_json(DEX_API_TOKEN_POOLS(ch, token))
            if isinstance(data, list) and data:
                pairs.extend(data)
                break

    # 4) Fallback to Uniswap v3 (Ethereum only)
    if token and not pairs:
        pairs = run_uniswap_fallback(token)

    return pairs

def domain_from_pairs(pairs):
    for p in pairs or []:
        info = p.get("info") or {}
        websites = info.get("websites") or []
        for w in websites:
            try:
                u = urlparse(w.get("url",""))
                if u.netloc:
                    return u.netloc
            except Exception:
                continue
    return None

def quickscan_contract(user_input, lang="en", window=None):
    pairs = run_dexscreener(user_input)
    if not pairs:
        return _("en","no_pairs"), None, None

    bp = best_pair(pairs)
    text = summarize_pair(bp, window=window or "24h")
    dom = domain_from_pairs(pairs)
    return text, bp, dom

def enrich_domain(domain):
    if not domain:
        return None, None, None
    rdap = rdap_domain(domain)
    first_cap = wayback_first_capture(domain)
    cert = ssl_certificate_info(domain)
    return rdap, first_cap, cert

def quickscan_entrypoint(user_input, lang="en", force_reuse=None, window=None):
    raw = user_input.strip()
    norm = normalize_input(raw)
    cache_key = f"qs:{norm.lower()}"
    if not force_reuse:
        cached = cache.get(cache_key)
    else:
        cached = force_reuse
    if cached and not window:
        return cached["text"], cached["keyboard"]

    main_text, pair, domain = quickscan_contract(norm, lang=lang, window=window)

    rdap, first_cap, cert = enrich_domain(domain)

    lines = []
    lines.append("Metridex QuickScan (MVP)")
    lines.append(main_text)
    if domain:
        lines.append(f'Domain: {domain}')
    if rdap:
        who = rdap.get("name") or rdap.get("handle") or "-"
        created = rdap.get("created") or "-"
        registrar = rdap.get("registrar") or "-"
        lines.append(f'WHOIS/RDAP: {who} | Created: {created} | Registrar: {registrar}')
    if cert:
        valid = "OK" if cert.get("valid") else "WARN"
        exp = cert.get("notAfter")
        issuer = cert.get("issuer")
        lines.append(f'SSL: {valid} | Expires: {exp} | Issuer: {issuer}')
    if first_cap:
        lines.append(f'Wayback: first {first_cap}')

    buttons = []
    for w in ["24h","7d","30d"]:
        buttons.append([{"text": f"Δ {w}", "callback_data": f"qs:{norm}?window={w}"}])
    keyboard = {"inline_keyboard": buttons}

    out = "\n".join([l for l in lines if l])
    rec = {"text": out, "keyboard": keyboard, "raw_input": raw}
    cache.set(cache_key, rec)
    return out, keyboard
