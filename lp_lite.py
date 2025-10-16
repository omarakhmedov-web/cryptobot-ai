# lp_lite_v2.py — Metridex LP-lite v2 (no new ENV)
# Public API:
#   check_lp_lock_v2(chain: str, lp_addr: str, rpc_urls: list[str] | None = None,
#                    timeout_s: float = 6.0, retries: int = 2) -> dict
# Returns:
#   {
#     "status": "burned" | "locked-partial" | "unknown" | "v3-nft",
#     "burnedPct": float|None,
#     "lockedPct": float|None,
#     "lpToken": str,
#     "explorerName": str,
#     "holdersUrl": str,
#     "uncxUrl": str,
#     "teamfinanceUrl": str,
#     "dataSource": "on-chain (ERC-20)" | "—",
#     "notes": list[str]
#   }
#
# Notes:
# - Uses only stdlib (urllib) for JSON-RPC. No external deps.
# - If ERC-20 methods unavailable, treats LP as v3/NFT pool.
# - Locked% optionally computed against a static list of known locker addresses
#   (UNCX/TeamFinance). By default the list is empty to avoid guessing; you can
#   populate LOCKER_ADDRESSES below without adding any new ENV.
from __future__ import annotations
import json, time
from typing import List, Dict, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEAD = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x0000000000000000000000000000000000000000"

# Minimal public RPC fallbacks (rate-limited; OK for lite checks)
_PUBLIC_RPC = {
    "eth": ["https://cloudflare-eth.com", "https://rpc.ankr.com/eth"],
    "bsc": ["https://bsc-dataseed.binance.org", "https://rpc.ankr.com/bsc"],
    "polygon": ["https://polygon-rpc.com", "https://rpc.ankr.com/polygon"],
}

# Explorers (holders pages)
_EXPLORERS = {
    "eth": ("Etherscan", "https://etherscan.io"),
    "bsc": ("BscScan", "https://bscscan.com"),
    "polygon": ("Polygonscan", "https://polygonscan.com"),
}

# Optional static locker addresses (empty by default).
# If you want Locked% — fill with verified addresses (per chain/provider).
LOCKER_ADDRESSES: Dict[str, Dict[str, List[str]]] = {
    "eth": {"UNCX": [], "TeamFinance": []},
    "bsc": {"UNCX": [], "TeamFinance": []},
    "polygon": {"UNCX": [], "TeamFinance": []},
}

SIG_TOTAL_SUPPLY = "0x18160ddd"  # totalSupply()
SIG_BALANCE_OF   = "0x70a08231"  # balanceOf(address)

def _norm_chain(chain: str) -> str:
    c = (chain or "").strip().lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","binance","binance-smart-chain"): return "bsc"
    if c in ("polygon","matic"): return "polygon"
    return c or "eth"

def _to_checksum(addr: str) -> str:
    # Keep simple lowercase to avoid importing eth_utils. Checksumming is cosmetic here.
    return (addr or "").strip()

def _truncate(addr: str) -> str:
    a = (addr or "")
    if len(a) <= 10: return a
    return f"{a[:6]}…{a[-4:]}"

def _holders_url(explorer_base: str, token: str) -> str:
    if not explorer_base or not token: return ""
    return f"{explorer_base}/token/{token}#balances"

def _jsonrpc_call(rpc: str, to_addr: str, data: str, timeout: float) -> Optional[str]:
    payload = {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to_addr,"data":data},"latest"]}
    req = Request(rpc, data=json.dumps(payload).encode("utf-8"),
                  headers={"Content-Type":"application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            obj = json.loads(resp.read().decode("utf-8"))
            if "result" in obj and isinstance(obj["result"], str):
                return obj["result"]
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None
    return None

def _hex_to_int(x: Optional[str]) -> Optional[int]:
    if not x or not isinstance(x, str) or not x.startswith("0x"): return None
    try:
        return int(x, 16)
    except Exception:
        return None

def _encode_balance_of(addr: str) -> str:
    a = (addr or "").lower().replace("0x","").rjust(64,"0")
    return SIG_BALANCE_OF + a

def _is_erc20_like(rpc: str, token: str, timeout: float) -> bool:
    ts = _jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout)
    bo = _jsonrpc_call(rpc, token, _encode_balance_of(DEAD), timeout)
    return ts is not None and bo is not None

def _erc20_total_supply(rpc: str, token: str, timeout: float) -> Optional[int]:
    return _hex_to_int(_jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout))

def _erc20_balance_of(rpc: str, token: str, holder: str, timeout: float) -> Optional[int]:
    return _hex_to_int(_jsonrpc_call(rpc, token, _encode_balance_of(holder), timeout))

def _pick_rpcs(chain: str, rpc_urls: Optional[List[str]]) -> List[str]:
    if rpc_urls and isinstance(rpc_urls, list) and rpc_urls:
        return rpc_urls
    return _PUBLIC_RPC.get(_norm_chain(chain), [])

def _pick_explorer(chain: str) -> tuple[str,str]:
    name, base = _EXPLORERS.get(_norm_chain(chain), ("",""))
    return name, base

def _try_each_rpc(func, rpc_list: List[str], retries: int, *args, **kwargs):
    last = None
    for rpc in rpc_list:
        for _ in range(max(1, retries)):
            last = func(rpc, *args, **kwargs)
            if last is not None:
                return last
    return last

def _calc_burned_pct(chain: str, lp_addr: str, rpc_list: List[str], timeout: float, retries: int) -> tuple[Optional[float], Optional[int], Optional[int]]:
    # Returns (burned_pct, burned_amount, total_supply)
    # 1) Detect ERC-20
    is_erc20 = _try_each_rpc(lambda rpc: True if _is_erc20_like(rpc, lp_addr, timeout) else None,
                             rpc_list, retries)
    if not is_erc20:
        return None, None, None  # v3/NFT or not accessible

    ts = _try_each_rpc(lambda rpc: _erc20_total_supply(rpc, lp_addr, timeout),
                       rpc_list, retries)
    if not ts or ts <= 0:
        return None, None, None

    dead_bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, DEAD, timeout),
                             rpc_list, retries) or 0
    zero_bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, ZERO, timeout),
                             rpc_list, retries) or 0
    burned = dead_bal + zero_bal
    burned_pct = (burned / ts) * 100.0 if ts else None
    return burned_pct, burned, ts

def _calc_locked_pct(chain: str, lp_addr: str, rpc_list: List[str], timeout: float, retries: int) -> tuple[Optional[float], Optional[str]]:
    # Sum balances over known lockers (if any). Returns (locked_pct, provider_label|None).
    lockers = LOCKER_ADDRESSES.get(_norm_chain(chain), {})
    if not lockers:
        return None, None
    # We count only the first provider with non-zero balance (priority order UNCX -> TeamFinance).
    for provider in ("UNCX","TeamFinance"):
        addrs = lockers.get(provider, [])
        total = 0
        for holder in addrs:
            bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, holder, timeout),
                                rpc_list, retries) or 0
            total += bal
        if total > 0:
            ts = _try_each_rpc(lambda rpc: _erc20_total_supply(rpc, lp_addr, timeout),
                               rpc_list, retries)
            if ts and ts > 0:
                return (total / ts) * 100.0, provider
    return None, None

def check_lp_lock_v2(chain: str, lp_addr: str, rpc_urls: Optional[List[str]] = None,
                     timeout_s: float = 6.0, retries: int = 2) -> Dict[str, Any]:
    chain_n = _norm_chain(chain)
    lp_addr = _to_checksum(lp_addr)
    rpcs = _pick_rpcs(chain_n, rpc_urls)
    explorer_name, explorer_base = _pick_explorer(chain_n)

    burned_pct, burned_amt, total_supply = _calc_burned_pct(chain_n, lp_addr, rpcs, timeout_s, retries)

    if burned_pct is None:
        # Either v3/NFT or RPC unavailable
        return {
            "status": "v3-nft" if rpcs else "unknown",
            "burnedPct": None,
            "lockedPct": None,
            "lpToken": lp_addr,
            "explorerName": explorer_name,
            "holdersUrl": _holders_url(explorer_base, lp_addr) if explorer_base else "",
            "uncxUrl": "https://app.unicrypt.network/",
            "teamfinanceUrl": "https://app.team.finance/",
            "dataSource": "—",
            "notes": ["ERC‑20 methods unavailable (v3/NFT LP or RPC blocked)"],
        }

    locked_pct, provider = _calc_locked_pct(chain_n, lp_addr, rpcs, timeout_s, retries)

    status = "unknown"
    if burned_pct is not None and burned_pct >= 95.0:
        status = "burned"
    elif locked_pct is not None and locked_pct > 0.0:
        status = "locked-partial"
    else:
        status = "unknown"

    return {
        "status": status,
        "burnedPct": round(burned_pct, 2) if burned_pct is not None else None,
        "lockedPct": round(locked_pct, 2) if locked_pct is not None else None,
        "lpToken": lp_addr,
        "explorerName": explorer_name,
        "holdersUrl": _holders_url(explorer_base, lp_addr) if explorer_base else "",
        "uncxUrl": "https://app.unicrypt.network/",
        "teamfinanceUrl": "https://app.team.finance/",
        "dataSource": "on-chain (ERC-20)",
        "notes": [f"Total supply: {total_supply}" if total_supply is not None else ""].copy(),
        "lockedBy": provider if provider else None,
    }
