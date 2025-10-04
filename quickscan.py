# MDX-QUICKSCAN SAFE8 RC4 hotfix-B
import os
import re
import time
from urllib.parse import urlparse, quote_plus

from utils import http_get_json, http_post_json, rdap_domain, wayback_first_capture, ssl_certificate_info, format_kv, locale_text as _tt, get_known_domain_for_address

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

# === Formatting helpers (MVP+) ===
def _abbr(n):
    try:
        n = float(n)
    except Exception:
        return "n/a"
    units = [(1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")]
    for v, s in units:
        if abs(n) >= v:
            return f"{n / v:.2f}{s}"
    return f"{n:.2f}"

def _pct(x):
    try:
        x = float(x)
        sign = "−" if x < 0 else "+"
        return f"{sign}{abs(x):.2f}%"
    except Exception:
        return "n/a"

def _fmt_usd(x):
    try:
        return f"${float(x):,.6f}".rstrip("0").rstrip(".")
    except Exception:
        return "n/a"

WINDOW_MAP = {
    "m5": ("5m", "m5"),
    "1h": ("1h", "h1"),
    "h1": ("1h", "h1"),
    "6h": ("6h", "h6"),
    "h6": ("6h", "h6"),
    "24h": ("24h", "h24"),
    "h24": ("24h", "h24"),
}

def summarize_pair(p, window="24h"):
    base = p.get("baseToken", {}) or {}
    quote = p.get("quoteToken", {}) or {}
    lines = []

    # Fallback: Uniswap v3
    if p.get("_src") == "uniswap":
        lines.append(f'{base.get("symbol","?")}/{quote.get("symbol","?")} on Uniswap v3 (ethereum)')
        lines.append(format_kv({
            "TVL (USD)": p.get("tvlUsd"),
            "Fee": p.get("feeTier"),
            "Pool": p.get("poolId")
        }))
        if p.get("site"):
            lines.append("Site: " + p["site"])
        lines.append("source: Uniswap v3 (fallback)")
        return "\n".join([l for l in lines if l])

    # DexScreener path (MVP+ compact view)
    liq = p.get("liquidity") or {}
    vol = p.get("volume") or {}
    chg = p.get("priceChange") or {}

    label, field = WINDOW_MAP.get(str(window).lower(), ("24h", "h24"))

    lines.append(f'{base.get("symbol","?")}/{quote.get("symbol","?")} on {p.get("dexId","?")} ({p.get("chainId","?")})')

    price_usd = p.get("priceUsd")
    if price_usd is not None:
        lines.append(f'Price: {_fmt_usd(price_usd)}')

    fdv = p.get("fdv")
    mcap = p.get("marketCap")
    liq_usd = liq.get("usd")
    vol24 = vol.get("h24")
    delta = chg.get(field)

    stats = f'FDV {_abbr(fdv)} | MC {_abbr(mcap)} | Liq {_abbr(liq_usd)} | Vol24h {_abbr(vol24)}'
    if delta is not None:
        stats += f' | Δ{label} {_pct(delta)}'
    lines.append(stats)

    lines.append("source: DexScreener")

    # Optional: website/social (unchanged logic)
    info = p.get("info") or {}
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
        return _t("en","no_pairs"), None, None

    bp = best_pair(pairs)
    text = summarize_pair(bp, window=window or "24h")
    dom = domain_from_pairs(pairs)

    # Prefer repository-known domain mapping (stable for well-known tokens)
    try:
        _, token_addr, _ = extract_contract_and_chain(user_input)
        mapped = get_known_domain_for_address(token_addr or "")
        if mapped:
            dom = mapped
    except Exception:
        pass

    return text, bp, dom

def enrich_domain(domain):
    if not domain:
        return None, None, None
    rdap = rdap_domain(domain)
    first_cap = wayback_first_capture(domain)
    cert = ssl_certificate_info(domain)
    return rdap, first_cap, cert

def build_keyboard_for_pair(pair, norm_addr, window_buttons_variant="qs2"):
    buttons = []

    # Row 1: Open on DexScreener (or Uniswap app for fallback)
    url_btn = None
    if isinstance(pair, dict):
        url_btn = pair.get("url")
        if not url_btn:
            info = pair.get("info") or {}
            webs = info.get("websites") or []
            if webs:
                url_btn = webs[0].get("url")
    if url_btn:
        buttons.append([{"text": "Open on DexScreener", "url": url_btn}])

    # Row 2: Δ windows
    # Prefer fast pair-based callbacks (qs2:chain/pair)
    cb_prefix = None
    if window_buttons_variant == "qs2" and isinstance(pair, dict) and pair.get("pairAddress") and pair.get("chainId"):
        cb_prefix = f"qs2:{pair['chainId']}/{pair['pairAddress']}"
    else:
        cb_prefix = f"qs:{norm_addr}"

    win_buttons = [
        {"text": "Δ 5m", "callback_data": f"{cb_prefix}?window=m5"},
        {"text": "Δ 1h", "callback_data": f"{cb_prefix}?window=h1"},
        {"text": "Δ 6h", "callback_data": f"{cb_prefix}?window=h6"},
        {"text": "Δ 24h", "callback_data": f"{cb_prefix}?window=h24"},
    ]
    buttons.append(win_buttons)

    return {"inline_keyboard": buttons}

def quickscan_entrypoint(user_input, lang="en", force_reuse=None, window=None, lean=False):
    raw = user_input.strip()
    norm = normalize_input(raw)
    cache_key = f"qs:{norm.lower()}"
    cached = None if force_reuse is None else force_reuse
    if cached is None:
        cached = cache.get(cache_key)

    # If we have cached and no window change, return quickly
    if cached and window is None:
        return cached["text"], cached["keyboard"]

    # Main summary
    main_text, pair, domain = quickscan_contract(norm, lang=lang, window=window)

    lines = []
    lines.append("Metridex QuickScan (MVP+)")
    lines.append(main_text)

    # Only heavy enrich for non-lean (initial requests). Callback windows stay fast and compact.
    if not lean:
        rdap, first_cap, cert = enrich_domain(domain)
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

    keyboard = build_keyboard_for_pair(pair, norm_addr=norm, window_buttons_variant="qs2")

    out = "\n".join([l for l in lines if l])
    rec = {"text": out, "keyboard": keyboard, "raw_input": raw}
    cache.set(cache_key, rec)
    return out, keyboard

def quickscan_pair_entrypoint(chain: str, pair_addr: str, window: str = "h24"):
    """Fast path for callbacks: fetch exact pair and render lean summary."""
    data = http_get_json(DEX_API_PAIR(chain, pair_addr))
    pairs = (data or {}).get("pairs") or []
    if not pairs:
        return _t("en","no_pairs"), {"inline_keyboard": []}
    bp = best_pair(pairs)
    main_text = summarize_pair(bp, window=window or "h24")
    lines = ["Metridex QuickScan (MVP+)", main_text]
    keyboard = build_keyboard_for_pair(bp, norm_addr=pair_addr, window_buttons_variant="qs2")
    return "\n".join(lines), keyboard
