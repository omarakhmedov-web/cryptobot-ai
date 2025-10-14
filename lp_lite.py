# Metridex OMEGA-713K — LP-lite helper (PATCH)
# Public API: check_lp_lock_v2(chain, lp_addr) -> dict
# • Computes burned% for ERC‑20 LPs = (balanceOf(0xdead)+balanceOf(0x0)) / totalSupply
# • Detects v3/NFT LPs (no ERC‑20) and returns "n/a (v3/NFT LP)"
# • Uses JUDGE_RPC_URLS (JSON) with stdlib urllib JSON‑RPC; fallbacks to public RPCs
# • Config via ENV: LP_RPC_TIMEOUT_S (default 6), LP_RPC_RETRIES (default 2)

from __future__ import annotations
import os, json, time
from typing import Dict, Any, Optional, Tuple, List
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEAD = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x0000000000000000000000000000000000000000"

# Public RPC fallbacks (used if JUDGE_RPC_URLS is absent/partial)
_PUBLIC = {
    "eth": ["https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    "bsc": ["https://rpc.ankr.com/bsc", "https://bsc-dataseed.binance.org"],
    "polygon": ["https://rpc.ankr.com/polygon", "https://polygon-rpc.com"],
}

def _coalesce_rpcs(chain: str) -> List[str]:
    """Build ordered RPC list from JUDGE_RPC_URLS + _PUBLIC."""
    out: List[str] = []
    try:
        m = json.loads(os.getenv("JUDGE_RPC_URLS","") or "{}")
        # Accept both long and short keys
        aliases = {
            "ethereum":"eth","eth":"eth",
            "binance":"bsc","bsc":"bsc",
            "polygon":"polygon","pol":"polygon","matic":"polygon",
        }
        for k,v in list(m.items()):
            kk = aliases.get(k.lower(), k.lower())
            if kk == _norm_chain(chain):
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, list):
                    out.extend([x for x in v if isinstance(x, str)])
    except Exception:
        pass
    # append public
    out.extend(_PUBLIC.get(_norm_chain(chain), []))
    # dedupe preserving order
    seen = set(); dedup = []
    for u in out:
        if u not in seen and isinstance(u, str) and u.startswith("http"):
            seen.add(u); dedup.append(u)
    return dedup

def _norm_chain(chain: str) -> str:
    c = (chain or "").lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","binance"): return "bsc"
    if c in ("polygon","pol","matic"): return "polygon"
    return c or "eth"

def _pick_explorer(chain: str) -> Tuple[str, str]:
    c = _norm_chain(chain)
    if c == "eth":
        return "Etherscan", "https://etherscan.io"
    if c == "bsc":
        return "BscScan", "https://bscscan.com"
    if c == "polygon":
        return "Polygonscan", "https://polygonscan.com"
    return "Explorer", ""

def _holders_path(base: str, token: str) -> str:
    if not base:
        return ""
    # token holders page (works for major scans)
    return f"{base}/token/{token}#balances"

def _jsonrpc_call(rpc: str, to: str, data_hex: str, timeout: float) -> Optional[str]:
    """Low-level eth_call returning hex result or None on failure."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [ {"to": to, "data": data_hex}, "latest" ],
    }
    req = Request(rpc, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type":"application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            j = json.loads(raw)
            if "error" in j:  # method missing or revert
                return None
            return j.get("result")
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None

def _hex_to_int(x: Optional[str]) -> int:
    if not x or not isinstance(x, str) or not x.startswith("0x"):
        return -1
    try:
        return int(x, 16)
    except Exception:
        return -1

# ERC-20 function selectors
SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF  = "0x70a08231"

def _encode_balance_of(addr: str) -> str:
    # pad 32 bytes
    a = addr.lower().replace("0x","").rjust(64,"0")
    return SIG_BALANCE_OF + a

def _is_erc20_like(rpc: str, token: str, timeout: float) -> bool:
    # If both totalSupply and balanceOf(dead) fail → very likely non‑ERC20 (v3/NFT LP)
    ts = _jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout)
    bo = _jsonrpc_call(rpc, token, _encode_balance_of(DEAD), timeout)
    return ts is not None and bo is not None

def _erc20_total_supply(rpc: str, token: str, timeout: float) -> int:
    return _hex_to_int(_jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout))

def _erc20_balance_of(rpc: str, token: str, owner: str, timeout: float) -> int:
    return _hex_to_int(_jsonrpc_call(rpc, token, _encode_balance_of(owner), timeout))

def _calc_burned_pct(chain: str, lp_addr: str, timeout_s: float, retries: int) -> Dict[str, Any]:
    rpcs = _coalesce_rpcs(chain)
    out: Dict[str,Any] = {
        "lpToken": lp_addr,
        "totalSupply": None,
        "burned": None,
        "burnedPct": "—",
        "notes": "",
    }
    if not lp_addr or lp_addr == ZERO:
        out["notes"] = "invalid LP address"
        return out
    for rpc in rpcs:
        # Multi-try per RPC (for transient errors)
        for _ in range(max(1, retries)):
            # ERC-20 presence check
            if not _is_erc20_like(rpc, lp_addr, timeout_s):
                out["notes"] = "v3/NFT LP — no ERC‑20 balances"
                out["burnedPct"] = "n/a (v3/NFT LP)"
                return out
            ts = _erc20_total_supply(rpc, lp_addr, timeout_s)
            if ts <= 0:
                continue
            d1 = _erc20_balance_of(rpc, lp_addr, DEAD, timeout_s)
            d0 = _erc20_balance_of(rpc, lp_addr, ZERO, timeout_s)
            burned = max(0, d1) + max(0, d0)
            out["totalSupply"] = ts
            out["burned"] = burned
            pct_bp = (burned * 10000) // ts
            out["burnedPct"] = f"{pct_bp/100:.2f}%"
            return out
    # exhausted
    out["notes"] = out.get("notes") or "rpc/timeout"
    return out

def check_lp_lock_v2(chain: str, lp_addr: str) -> Dict[str, Any]:
    """
    Main entry used by the server / renderers.
    Returns dict with: burnedPct (str), lpToken, holdersUrl, explorer (name), notes, totalSupply, burned.
    """
    timeout_s = float(os.getenv("LP_RPC_TIMEOUT_S", "6"))
    retries = int(os.getenv("LP_RPC_RETRIES", "2"))
    explorer_name, explorer_base = _pick_explorer(chain)
    res = _calc_burned_pct(chain, lp_addr, timeout_s, retries)
    res["explorer"] = explorer_name
    res["holdersUrl"] = _holders_path(explorer_base, lp_addr) if explorer_base else ""
    return res
