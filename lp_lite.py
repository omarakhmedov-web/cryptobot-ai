from __future__ import annotations
import os
from typing import Dict, Any, Optional
import requests

SIG_TOTALSUPPLY = "0x18160ddd"
SIG_BALANCEOF   = "0x70a08231"

CHAIN_RPC_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY",
    "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY",
    "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY",
    "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY",
    "ftm":"FTM_RPC_URL_PRIMARY"
}

DEAD_ADDRS = [
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000001",
]

def _rpc(chain: str) -> Optional[str]:
    env = CHAIN_RPC_ENV.get((chain or "").lower().strip())
    return (os.getenv(env, "") or "").strip() or None

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data},"latest"]}
    r = requests.post(rpc, json=j, timeout=8)
    try:
        res = r.json().get("result") or "0x"
    except Exception:
        res = "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _u256(b: bytes) -> int:
    if not b: return 0
    return int.from_bytes(b[-32:], "big", signed=False)

def _balance_of(rpc: str, token: str, holder: str) -> int:
    addr = holder.lower().replace("0x","").rjust(64, "0")
    data = SIG_BALANCEOF + addr
    return _u256(_eth_call(rpc, token, data))

def _total_supply(rpc: str, token: str) -> int:
    return _u256(_eth_call(rpc, token, SIG_TOTALSUPPLY))

def check_lp_lock_v2(chain: str, lp_token_address: str) -> Dict[str, Any]:
    """
    Lite LP lock check: burned % (dead/zero) + optional lockers via env LP_LOCKER_ADDRS.
    """
    rpc = _rpc(chain)
    if not rpc or not lp_token_address:
        return {"provider":"lite-burn-check","lpAddress": lp_token_address or "—","status":"unknown"}

    try:
        ts = _total_supply(rpc, lp_token_address)
        if ts <= 0:
            return {"provider":"lite-burn-check","lpAddress": lp_token_address, "status":"unknown"}

        burned = 0
        parts = {}
        for h in DEAD_ADDRS:
            bal = _balance_of(rpc, lp_token_address, h)
            parts[h] = bal
            burned += bal
        burned_pct = (burned/float(ts))*100.0 if ts else 0.0

        # Known lockers
        lockers_env = (os.getenv("LP_LOCKER_ADDRS","") or "").strip()
        lockers = [x.strip().lower() for x in lockers_env.split(",") if x.strip()]
        locked_total = 0
        details = []
        for lk in lockers:
            bal = _balance_of(rpc, lp_token_address, lk)
            if bal > 0:
                pct_lk = (bal/float(ts))*100.0 if ts else 0.0
                locked_total += bal
                details.append({"locker": lk, "balance": bal, "pct": round(pct_lk,2)})
        locked_pct = (locked_total/float(ts))*100.0 if ts else 0.0

        status = "none"
        if burned_pct >= 95: status = "fully-burned"
        elif burned_pct >= 50: status = "mostly-burned"
        elif burned_pct >= 5: status = "partially-burned"
        else: status = "low-burn"

        return {
            "provider":"lite-burn-check",
            "lpAddress": lp_token_address,
            "burnedPct": round(burned_pct,2),
            "lockedPct": round(locked_pct,2) if lockers else None,
            "lockers": details if details else None,
            "status": status,
            "until": "—",
            "breakdown": parts
        }
    except Exception as e:
        return {"provider":"lite-burn-check","lpAddress": lp_token_address, "status":"error", "error": str(e)}
