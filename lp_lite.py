# lp_lite.py — OMEGA-713K patch 2 (renderer-compatible)
from __future__ import annotations
import os, json
from typing import Dict, Any, Optional, Tuple, List
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEAD = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x0000000000000000000000000000000000000000"

_PUBLIC = {
    "eth": ["https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    "bsc": ["https://rpc.ankr.com/bsc", "https://bsc-dataseed.binance.org"],
    "polygon": ["https://rpc.ankr.com/polygon", "https://polygon-rpc.com"],
}

def _norm_chain(chain: str) -> str:
    c = (chain or "").lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","binance"): return "bsc"
    if c in ("polygon","pol","matic"): return "polygon"
    return c or "eth"

def _coalesce_rpcs(chain: str) -> List[str]:
    out: List[str] = []
    try:
        m = json.loads(os.getenv("JUDGE_RPC_URLS","") or "{}")
        aliases = {"ethereum":"eth","eth":"eth","binance":"bsc","bsc":"bsc","polygon":"polygon","pol":"polygon","matic":"polygon"}
        for k,v in list(m.items()):
            kk = aliases.get(k.lower(), k.lower())
            if kk == _norm_chain(chain):
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, list):
                    out.extend([x for x in v if isinstance(x, str)])
    except Exception:
        pass
    out.extend(_PUBLIC.get(_norm_chain(chain), []))
    # dedupe
    seen=set(); dedup=[]
    for u in out:
        if u and u not in seen and str(u).startswith("http"):
            seen.add(u); dedup.append(u)
    return dedup

def _pick_explorer(chain: str) -> Tuple[str, str]:
    c = _norm_chain(chain)
    if c == "eth": return "Etherscan", "https://etherscan.io"
    if c == "bsc": return "BscScan", "https://bscscan.com"
    if c == "polygon": return "Polygonscan", "https://polygonscan.com"
    return "Explorer", ""

def _holders_path(base: str, token: str) -> str:
    return f"{base}/token/{token}#balances" if base else ""

def _jsonrpc_call(rpc: str, to: str, data_hex: str, timeout: float) -> Optional[str]:
    payload = {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data_hex},"latest"]}
    req = Request(rpc, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type":"application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8","ignore")
            j = json.loads(raw)
            if "error" in j: return None
            return j.get("result")
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None

def _hex_to_int(x: Optional[str]) -> int:
    if not x or not isinstance(x, str) or not x.startswith("0x"): return -1
    try: return int(x, 16)
    except Exception: return -1

SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF  = "0x70a08231"

def _encode_balance_of(addr: str) -> str:
    a = (addr or "").lower().replace("0x","").rjust(64,"0")
    return SIG_BALANCE_OF + a

def _is_erc20_like(rpc: str, token: str, timeout: float) -> bool:
    ts = _jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout)
    bo = _jsonrpc_call(rpc, token, _encode_balance_of(DEAD), timeout)
    return ts is not None and bo is not None

def _erc20_total_supply(rpc: str, token: str, timeout: float) -> int:
    return _hex_to_int(_jsonrpc_call(rpc, token, SIG_TOTAL_SUPPLY, timeout))

def _erc20_balance_of(rpc: str, token: str, owner: str, timeout: float) -> int:
    return _hex_to_int(_jsonrpc_call(rpc, token, _encode_balance_of(owner), timeout))

def _calc(chain: str, lp_addr: str, timeout_s: float, retries: int) -> Dict[str, Any]:
    rpcs = _coalesce_rpcs(chain)
    result: Dict[str, Any] = {
        "lpAddress": lp_addr or "—",
        "burnedPct": None,  # numeric expected by renderer
        "burned": False,
        "lockedPct": None,
        "lockers": [],
        "until": "—",
        "status": "",
        "notes": "",
    }
    if not lp_addr or lp_addr == ZERO:
        result["status"] = "no-lp"
        result["notes"] = "invalid LP address"
        return result
    for rpc in rpcs:
        for _ in range(max(1, retries)):
            # Detect v3/NFT pool (no ERC-20 balanceOf/totalSupply)
            if not _is_erc20_like(rpc, lp_addr, timeout_s):
                result["status"] = "v3-nft"
                result["notes"] = "no ERC-20 balances; likely Uniswap v3 pool"
                # leave burnedPct=None, burned=False
                return result
            ts = _erc20_total_supply(rpc, lp_addr, timeout_s)
            if ts <= 0:
                continue
            d1 = _erc20_balance_of(rpc, lp_addr, DEAD, timeout_s)
            d0 = _erc20_balance_of(rpc, lp_addr, ZERO, timeout_s)
            burned = max(0, d1) + max(0, d0)
            # numeric percent 0..100
            burned_pct = (burned / ts) * 100.0 if ts > 0 else 0.0
            result["burnedPct"] = float(f"{burned_pct:.6f}")
            result["burned"] = burned_pct >= 95.0
            result["status"] = "ok"
            return result
    result["status"] = result["status"] or "rpc/timeout"
    result["notes"] = result.get("notes") or "all RPC attempts failed"
    return result

def check_lp_lock_v2(chain: str, lp_addr: str) -> Dict[str, Any]:
    timeout_s = float(os.getenv("LP_RPC_TIMEOUT_S", "6"))
    retries = int(os.getenv("LP_RPC_RETRIES", "2"))
    explorer_name, explorer_base = _pick_explorer(chain)
    res = _calc(chain, lp_addr, timeout_s, retries)
    res["explorer"] = explorer_name
    res["holdersUrl"] = _holders_path(explorer_base, lp_addr) if explorer_base else ""
    return res
