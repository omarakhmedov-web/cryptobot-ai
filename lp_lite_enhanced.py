# lp_lite_enhanced.py — OMEGA-713K (expanded metrics, UNCX/TeamFinance via ENV)
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

SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF  = "0x70a08231"

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
                if isinstance(v, str): out.append(v)
                elif isinstance(v, list): out.extend([x for x in v if isinstance(x, str)])
    except Exception:
        pass
    out.extend(_PUBLIC.get(_norm_chain(chain), []))
    # dedupe
    seen=set(); dedup=[]
    for u in out:
        if u and u not in seen and str(u).startswith("http"):
            seen.add(u); dedup.append(u)
    return dedup

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

def _collect_lockers(chain: str) -> Dict[str, List[str]]:
    """
    Load configured locker addresses from ENV LP_LOCKER_ADDRESSES.
    Example:
    LP_LOCKER_ADDRESSES={"eth":{"UNCX":["0x...","0x..."],"TeamFinance":["0x..."]},"bsc":{"UNCX":["0x..."]}}
    """
    try:
        data = json.loads(os.getenv("LP_LOCKER_ADDRESSES","") or "{}")
        m = data.get(_norm_chain(chain)) or {}
        # only keep dict[str, list[str]]
        out = {}
        for name, arr in list(m.items()):
            if isinstance(name, str):
                lst = [x for x in (arr or []) if isinstance(x, str) and x.startswith("0x")]
                if lst: out[name] = lst
        return out
    except Exception:
        return {}

def check_lp_lock_v2(chain: str, lp_addr: str) -> Dict[str, Any]:
    timeout_s = float(os.getenv("LP_RPC_TIMEOUT_S", "6"))
    retries = int(os.getenv("LP_RPC_RETRIES", "2"))
    verdict_burned_threshold = float(os.getenv("LP_BURNED_VERDICT_PCT","95"))
    rpcs = _coalesce_rpcs(chain)
    res: Dict[str, Any] = {
        "lpAddress": lp_addr or "—",
        "burnedPct": None,  # float
        "burned": False,
        "lockedPct": None,  # float (sum of known lockers)
        "lockers": [],      # list of {locker, balance, pct}
        "until": "—",
        "status": "",
        "notes": "",
        "dataSource": "on-chain (ERC-20 + configured lockers)",
    }
    if not lp_addr or lp_addr == ZERO:
        res["status"] = "no-lp"; res["notes"] = "invalid LP address"; return res
    # try RPCs
    for rpc in rpcs:
        for _ in range(max(1, retries)):
            # v3/NFT detection
            if not _is_erc20_like(rpc, lp_addr, timeout_s):
                res["status"] = "v3-nft"
                res["notes"] = "no ERC-20 balances; likely Uniswap v3 pool"
                return res
            ts = _erc20_total_supply(rpc, lp_addr, timeout_s)
            if ts <= 0:
                continue
            dead = _erc20_balance_of(rpc, lp_addr, DEAD, timeout_s)
            zero = _erc20_balance_of(rpc, lp_addr, ZERO, timeout_s)
            burned = max(0, dead) + max(0, zero)
            burned_pct = (burned / ts) * 100.0 if ts > 0 else 0.0
            res["burnedPct"] = float(f"{burned_pct:.6f}")
            res["burned"] = burned_pct >= verdict_burned_threshold

            # Lockers by configured addresses
            lockers_cfg = _collect_lockers(chain)
            total_locked = 0
            lockers_out = []
            for name, addrs in lockers_cfg.items():
                bal_sum = 0
                for a in addrs:
                    b = _erc20_balance_of(rpc, lp_addr, a, timeout_s)
                    if b > 0:
                        bal_sum += b
                pct = (bal_sum / ts) * 100.0 if ts > 0 else 0.0
                lockers_out.append({"locker": name, "balance": int(bal_sum), "pct": float(f"{pct:.6f}")})
                total_locked += bal_sum
            res["lockers"] = [x for x in lockers_out if x.get("balance",0) > 0]
            if total_locked > 0:
                res["lockedPct"] = float(f"{(total_locked/ts)*100.0:.6f}")

            # Status
            if res["burned"]:
                res["status"] = "burned"
            elif (res.get("lockedPct") or 0) >= 50.0:
                res["status"] = "locked-major"
            elif (res.get("lockedPct") or 0) >= 5.0:
                res["status"] = "locked-partial"
            else:
                res["status"] = "unknown"
            return res
    res["status"] = "rpc/timeout"; res["notes"] = "all RPC attempts failed"
    return res
