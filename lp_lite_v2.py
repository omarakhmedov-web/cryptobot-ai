# lp_lite_v2.py — Metridex LP-lite v2 (robust, no new ENV)
# Public API:
#   check_lp_lock_v2(chain: str, lp_addr: str, rpc_urls: list[str] | None = None,
#                    timeout_s: float = 6.0, retries: int = 2) -> dict
#
# Returns a dict with keys:
#   status: "burned" | "locked-partial" | "unknown" | "v3-nft"
#   burnedPct: float|None
#   lockedPct: float|None
#   lockedBy: "UNCX" | "TeamFinance" | None
#   lpToken: str
#   explorerName: str
#   holdersUrl: str
#   uncxUrl: str
#   teamfinanceUrl: str
#   dataSource: "on-chain (ERC-20)" | "on-chain (contract present)" | "—"
#   notes: list[str]
#
# Design notes
# - Only stdlib (urllib) for JSON-RPC. No external deps.
# - Uses public RPC fallbacks; rate-limited but fine for lite checks.
# - Differentiates true v3/NFT from "RPC/ABI issue" using eth_getCode.
# - Locked% optionally computed by summing balances on known locker contracts (static list).

from __future__ import annotations
from typing import List, Dict, Any, Optional
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEAD = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x0000000000000000000000000000000000000000"

# Public RPCs (short but diverse)
_PUBLIC_RPC = {
    "eth": [
        "https://cloudflare-eth.com",
        "https://rpc.ankr.com/eth",
        "https://rpc.flashbots.net",
        "https://eth.llamarpc.com",
        "https://ethereum.publicnode.com",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://rpc.ankr.com/bsc",
        "https://binance.llamarpc.com",
        "https://bsc.publicnode.com",
    ],
    "polygon": [
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygon.llamarpc.com",
        "https://polygon-rpc.publicnode.com",
    ],
}

# Explorers (holders pages)
_EXPLORERS = {
    "eth": ("Etherscan", "https://etherscan.io"),
    "bsc": ("BscScan", "https://bscscan.com"),
    "polygon": ("Polygonscan", "https://polygonscan.com"),
}

# Optional static locker addresses.
# ETH entries are populated; BSC/Polygon left empty by default.
LOCKER_ADDRESSES: Dict[str, Dict[str, List[str]]] = {
    "eth": {
        "UNCX": [
            "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",  # UNCX V2 (ETH, Uniswap v2)
            "0xFD235968e65B0990584585763f837A5b5330e6DE",  # UNCX V3 (ETH)
        ],
        "TeamFinance": [
            "0xe2fe530c047f2d85298b07d9333c05737f1435fb",  # TeamFinance Lock (ETH)
        ],
    },
    "bsc": {"UNCX": [], "TeamFinance": []},
    "polygon": {"UNCX": [], "TeamFinance": []},
}

# ERC-20 selectors
SIG_TOTAL_SUPPLY = "0x18160ddd"  # totalSupply()
SIG_BALANCE_OF   = "0x70a08231"  # balanceOf(address)

def _norm_chain(chain: str) -> str:
    c = (chain or "").strip().lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","binance","binance-smart-chain"): return "bsc"
    if c in ("polygon","matic"): return "polygon"
    return c or "eth"

def _to_checksum(addr: str) -> str:
    # Keep simple lowercase to avoid external deps. Cosmetic only.
    return (addr or "").strip()

def _holders_url(explorer_base: str, token: str) -> str:
    if not explorer_base or not token: return ""
    return f"{explorer_base}/token/{token}#balances"

def _jsonrpc_call(rpc: str, method: str, params: list, timeout: float) -> Optional[dict]:
    payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    req = Request(rpc, data=json.dumps(payload).encode("utf-8"),
                  headers={
                      "Content-Type":"application/json",
                      "User-Agent":"Metridex/LPv2 (+https://metridex.com)",
                      "Accept":"application/json",
                  })
    try:
        with urlopen(req, timeout=timeout) as resp:
            obj = json.loads(resp.read().decode("utf-8"))
            return obj
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None

def _eth_call(rpc: str, to_addr: str, data: str, timeout: float) -> Optional[str]:
    obj = _jsonrpc_call(rpc, "eth_call", [{"to": to_addr, "data": data}, "latest"], timeout)
    if obj and isinstance(obj.get("result"), str):
        return obj["result"]
    return None

def _eth_get_code(rpc: str, addr: str, timeout: float) -> Optional[str]:
    obj = _jsonrpc_call(rpc, "eth_getCode", [addr, "latest"], timeout)
    if obj and isinstance(obj.get("result"), str):
        return obj["result"]
    return None

def _eth_get_storage_at(rpc: str, addr: str, slot: str, timeout: float) -> Optional[str]:
    obj = _jsonrpc_call(rpc, "eth_getStorageAt", [addr, slot, "latest"], timeout)
    if obj and isinstance(obj.get("result"), str):
        return obj["result"]
    return None

def _hex_to_int(x: Optional[str]) -> Optional[int]:
    if not x or not isinstance(x, str) or not x.startswith("0x"): return None
    try:
        return int(x, 16)
    except Exception:
        return None

def _encode_balance_of(addr: str) -> str:
    # abi.encode(address) (left-padded to 32 bytes)
    a = (addr or "").lower().replace("0x","").rjust(64,"0")
    return SIG_BALANCE_OF + a

def _pick_rpcs(chain: str, rpc_urls: Optional[List[str]]) -> List[str]:
    if rpc_urls and isinstance(rpc_urls, list) and rpc_urls:
        return rpc_urls
    return _PUBLIC_RPC.get(_norm_chain(chain), [])

def _pick_explorer(chain: str) -> tuple[str,str]:
    name, base = _EXPLORERS.get(_norm_chain(chain), ("",""))
    return name, base

def _try_each_rpc(fn, rpc_list: List[str], retries: int, *args, **kwargs):
    last = None
    for rpc in rpc_list:
        for _ in range(max(1, retries)):
            last = fn(rpc, *args, **kwargs)
            if last is not None:
                return last
    return last

def _erc20_total_supply(rpc: str, token: str, timeout: float) -> Optional[int]:
    return _hex_to_int(_eth_call(rpc, token, SIG_TOTAL_SUPPLY, timeout))

def _erc20_balance_of(rpc: str, token: str, holder: str, timeout: float) -> Optional[int]:
    return _hex_to_int(_eth_call(rpc, token, _encode_balance_of(holder), timeout))

def _calc_burned_pct(chain: str, lp_addr: str, rpc_list: List[str], timeout: float, retries: int) -> tuple[Optional[float], Optional[int], Optional[int]]:
    # Returns (burned_pct, burned_amount, total_supply)
    ts = _try_each_rpc(lambda rpc: _erc20_total_supply(rpc, lp_addr, timeout), rpc_list, retries)
    if not ts or ts <= 0:
        return None, None, None
    dead_bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, DEAD, timeout), rpc_list, retries) or 0
    zero_bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, ZERO, timeout), rpc_list, retries) or 0
    burned = dead_bal + zero_bal
    burned_pct = (burned / ts) * 100.0 if ts else None
    return burned_pct, burned, ts

def _calc_locked_pct(chain: str, lp_addr: str, rpc_list: List[str], timeout: float, retries: int) -> tuple[Optional[float], Optional[str]]:
    # Sum balances over known lockers (if any). Returns (locked_pct, provider_label|None).
    lockers = LOCKER_ADDRESSES.get(_norm_chain(chain), {})
    if not lockers:
        return None, None
    # Priority: UNCX -> TeamFinance
    for provider in ("UNCX","TeamFinance"):
        addrs = lockers.get(provider, [])
        total = 0
        for holder in addrs:
            bal = _try_each_rpc(lambda rpc: _erc20_balance_of(rpc, lp_addr, holder, timeout), rpc_list, retries) or 0
            total += bal
        if total > 0:
            ts = _try_each_rpc(lambda rpc: _erc20_total_supply(rpc, lp_addr, timeout), rpc_list, retries)
            if ts and ts > 0:
                return (total / ts) * 100.0, provider
    # If lockers known but total is zero, return 0.0 to make UI clearer
    return 0.0, None

def check_lp_lock_v2(chain: str, lp_addr: str, rpc_urls: Optional[List[str]] = None,
                     timeout_s: float = 6.0, retries: int = 2) -> Dict[str, Any]:
    chain_n = _norm_chain(chain)
    lp_addr = _to_checksum(lp_addr)
    rpcs = _pick_rpcs(chain_n, rpc_urls)
    explorer_name, explorer_base = _pick_explorer(chain_n)

    burned_pct, burned_amt, total_supply = _calc_burned_pct(chain_n, lp_addr, rpcs, timeout_s, retries)

    if burned_pct is None:
        # Try to distinguish RPC/ABI issues from true v3/NFT by checking contract code
        code_hex = _try_each_rpc(lambda rpc: _eth_get_code(rpc, lp_addr, timeout_s), rpcs, retries)
        has_code = isinstance(code_hex, str) and code_hex.startswith("0x") and len(code_hex) > 2 and code_hex != "0x"
        status = "unknown" if has_code else ("v3-nft" if rpcs else "unknown")
        ds = "on-chain (contract present)" if has_code else "—"
        note = "Total supply not readable (RPC limit or non-ERC20 LP)"
        return {
            "status": status,
            "burnedPct": None,
            "lockedPct": None,
            "lockedBy": None,
            "lpToken": lp_addr,
            "explorerName": explorer_name,
            "holdersUrl": _holders_url(explorer_base, lp_addr) if explorer_base else "",
            "uncxUrl": "https://app.unicrypt.network/",
            "teamfinanceUrl": "https://app.team.finance/",
            "dataSource": ds,
            "notes": [note],
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
        "lockedBy": provider if provider else None,
        "lpToken": lp_addr,
        "explorerName": explorer_name,
        "holdersUrl": _holders_url(explorer_base, lp_addr) if explorer_base else "",
        "uncxUrl": "https://app.unicrypt.network/",
        "teamfinanceUrl": "https://app.team.finance/",
        "dataSource": "on-chain (ERC-20)",
        "notes": [f"Total supply: {total_supply}" if total_supply is not None else ""],
    }
