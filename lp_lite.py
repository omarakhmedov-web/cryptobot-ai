# Metridex OMEGA-713K — LP-lite helper
# Provides: check_lp_lock_v2(chain_short, lp_addr) -> dict with burned% and provider link.
# No web3 dependency; uses raw JSON-RPC via requests.

from __future__ import annotations
import os, json, time
from typing import Dict, Any, Optional
import requests

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
    # merge fallbacks (do not overwrite explicit)
    for k, v in _PUBLIC.items():
        out.setdefault(k, v)
    return out

def _pick_explorer(chain: str) -> (str, str):
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

def _rpc_call(rpc_url: str, to: str, data: str, timeout: int = 8) -> Optional[str]:
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()*1000)%1_000_000,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"]
    }
    try:
        r = requests.post(rpc_url, json=payload, timeout=timeout)
        if not r.ok:
            return None
        j = r.json()
        return j.get("result")
    except Exception:
        return None

def _pad(addr: str) -> str:
    a = addr.lower().replace("0x", "")
    return a.rjust(64, "0")

def _hex_to_int(x: Optional[str]) -> int:
    if not x or not isinstance(x, str): return 0
    try:
        return int(x, 16)
    except Exception:
        try:
            if x.startswith("0x"): return int(x, 16)
        except Exception:
            return 0
    return 0

def _balance_of(rpc: str, token_addr: str, holder: str) -> int:
    data = "0x70a08231" + _pad(holder)
    res = _rpc_call(rpc, token_addr, data)
    return _hex_to_int(res)

def _total_supply(rpc: str, token_addr: str) -> int:
    data = "0x18160ddd"
    res = _rpc_call(rpc, token_addr, data)
    return _hex_to_int(res)

def check_lp_lock_v2(chain: str, lp_addr: str) -> Dict[str, Any]:
    """Return a lite LP lock view using burn% and a holders page link.
    chain: short code like 'eth','bsc','polygon' (case-insensitive)
    lp_addr: LP token (pair) address
    """
    out = {
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

    rpc = _rpc_map().get(chain)
    name, base = _pick_explorer(chain)
    out["provider"] = name
    out["providerUrl"] = f"{base}/token/{lp_addr}#balances"

    if not rpc:
        return out

    try:
        ts = _total_supply(rpc, lp_addr)
        d1 = _balance_of(rpc, lp_addr, DEAD)
        d0 = _balance_of(rpc, lp_addr, ZERO)
        burned = d1 + d0
        out["totalSupply"] = ts
        out["burned"] = burned
        if ts > 0 and burned >= 0:
            pct = (burned * 10000) // ts  # basis points
            out["burnedPct"] = f"{pct/100:.2f}%"
    except Exception:
        pass
    return out
