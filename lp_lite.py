# Metridex OMEGA-713K — LP-lite helper (stdlib-only)
# Public API: check_lp_lock_v2(chain, lp_addr) -> dict
# Computes burned% = (balanceOf(0xdead)+balanceOf(0x0)) / totalSupply
# Adds provider link to LP holders page.

from __future__ import annotations
import os, json, time
from typing import Dict, Any, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEAD = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x0000000000000000000000000000000000000000"

# Public RPC fallbacks (used if JUDGE_RPC_URLS is absent)
_PUBLIC = {
    "eth": "https://rpc.ankr.com/eth",
    "ethereum": "https://rpc.ankr.com/eth",
    "bsc": "https://rpc.ankr.com/bsc",
    "binance": "https://rpc.ankr.com/bsc",
    "polygon": "https://rpc.ankr.com/polygon",
    "pol": "https://rpc.ankr.com/polygon",
    "matic": "https://rpc.ankr.com/polygon",
    "avax": "https://rpc.ankr.com/avalanche",
    "avalanche": "https://rpc.ankr.com/avalanche",
    "op": "https://rpc.ankr.com/optimism",
    "optimism": "https://rpc.ankr.com/optimism",
    "base": "https://mainnet.base.org",
    "ftm": "https://rpc.ankr.com/fantom",
    "fantom": "https://rpc.ankr.com/fantom",
}

def _rpc_map() -> Dict[str, str]:
    j = os.getenv("JUDGE_RPC_URLS", "").strip()
    out: Dict[str, str] = {}
    if j:
        try:
            parsed = json.loads(j)
            if isinstance(parsed, dict):
                out.update({str(k).lower(): str(v) for k, v in parsed.items() if v})
        except Exception:
            pass
    for k, v in _PUBLIC.items():
        out.setdefault(k, v)
    return out

def _pick_explorer(chain: str) -> Tuple[str, str]:
    c = (chain or "").lower()
    if c in ("eth", "ethereum"):
        return "Etherscan", "https://etherscan.io"
    if c in ("bsc", "binance"):
        return "BscScan", "https://bscscan.com"
    if c in ("polygon", "pol", "matic"):
        return "Polygonscan", "https://polygonscan.com"
    if c in ("avax", "avalanche"):
        return "Snowtrace", "https://snowtrace.io"
    if c in ("op", "optimism"):
        return "Optimistic Etherscan", "https://optimistic.etherscan.io"
    if c in ("base",):
        return "BaseScan", "https://basescan.org"
    if c in ("ftm", "fantom"):
        return "FTMScan", "https://ftmscan.com"
    return "Explorer", "https://etherscan.io"

def _post_json(url: str, payload: dict, timeout: int = 4) -> Optional[dict]:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            return json.loads(raw)
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None

def _rpc_call(rpc_url: str, to: str, data: str, timeout: int = 4, retries: int = 1) -> Optional[str]:
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()*1000)%1_000_000,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"]
    }
    j = None
    for _ in range(max(1, retries)):
        j = _post_json(rpc_url, payload, timeout=timeout)
        if j and isinstance(j, dict) and "result" in j:
            break
    if not j: return None
    return j.get("result")

def _pad(addr: str) -> str:
    a = (addr or "").lower().replace("0x", "")
    return a.rjust(64, "0")

def _hex_to_int(x: Optional[str]) -> int:
    if not x or not isinstance(x, str): return 0
    try:
        return int(x, 16)
    except Exception:
        return 0

def _balance_of(rpc: str, token_addr: str, holder: str) -> int:
    data = "0x70a08231" + _pad(holder)
    res = _rpc_call(rpc, token_addr, data, timeout=4, retries=2)
    return _hex_to_int(res)

def _total_supply(rpc: str, token_addr: str) -> int:
    data = "0x18160ddd"
    res = _rpc_call(rpc, token_addr, data, timeout=4, retries=2)
    return _hex_to_int(res)

def check_lp_lock_v2(chain: str, lp_addr: str) -> Dict[str, Any]:
    """Return a lite LP lock view using burn% and a holders page link.
    chain: short code like 'eth','bsc','polygon' (case-insensitive)
    lp_addr: LP token (pair) address
    """
    out: Dict[str, Any] = {
        "provider": "explorer",
        "providerUrl": None,
        "lpAddress": lp_addr or "—",
        "burnedPct": "—",
        "burned": None,
        "totalSupply": None,
        "until": "—",
    }
    chain = (chain or "eth").lower()
    if not lp_addr or not isinstance(lp_addr, str) or len(lp_addr) < 40:
        return out

    rpc_map = _rpc_map()
    rpc = rpc_map.get(chain) or rpc_map.get({"ethereum":"eth","binance":"bsc","polygon":"polygon"}.get(chain, ""))
    name, base = _pick_explorer(chain)
    out["provider"] = name
    out["providerUrl"] = f"{base}/token/{lp_addr}#balances"

    if not rpc:
        return out

    try:
        ts = _total_supply(rpc, lp_addr)
        if ts <= 0:
            return out
        d1 = _balance_of(rpc, lp_addr, DEAD)
        d0 = _balance_of(rpc, lp_addr, ZERO)
        burned = max(0, d1) + max(0, d0)
        out["totalSupply"] = ts
        out["burned"] = burned
        pct = (burned * 10000) // ts  # basis points
        out["burnedPct"] = f"{pct/100:.2f}%"
    except Exception:
        # keep placeholders
        pass
    return out
