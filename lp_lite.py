
from __future__ import annotations
import os
from typing import Dict, Any, Optional, Tuple
import requests

# ERC20 selectors
SIG_BALANCEOF = "0x70a08231"
SIG_TOTALSUPPLY = "0x18160ddd"

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
    env = CHAIN_RPC_ENV.get(chain)
    if not env:
        return None
    return (os.getenv(env,"") or "").strip() or None

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = requests.post(rpc, json={"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data},"latest"]}, timeout=8).json()
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _u256(raw: bytes) -> int:
    if not raw: return 0
    return int.from_bytes(raw[-32:], "big", signed=False)

def _balance_of(rpc: str, token: str, holder: str) -> int:
    # selector + left-padded address
    addr = holder.lower().replace("0x","").rjust(64, "0")
    data = SIG_BALANCEOF + addr
    return _u256(_eth_call(rpc, token, data))

def _total_supply(rpc: str, token: str) -> int:
    return _u256(_eth_call(rpc, token, SIG_TOTALSUPPLY))

def check_lp_lock_v2(chain: str, lp_token_address: str) -> Dict[str, Any]:
    """
    Lite LP lock check via burned balances share.
    Assumes typical V2 LP (18 decimals). No external APIs.
    """
    rpc = _rpc(chain)
    if not rpc or not lp_token_address:
        return {"provider":"lite-burn-check","lpAddress": lp_token_address or "—","status":"unknown"}

    try:
        ts = _total_supply(rpc, lp_token_address)  # 18 decimals in most V2 LPs
        if ts <= 0:
            return {"provider":"lite-burn-check","lpAddress": lp_token_address, "status":"unknown"}
        burned = 0
        parts = {}
        for h in DEAD_ADDRS:
            bal = _balance_of(rpc, lp_token_address, h)
            parts[h] = bal
            burned += bal
        pct = (burned / float(ts)) * 100.0 if ts else 0.0
        status = "none"
        if pct >= 95: status = "fully-burned"
        elif pct >= 50: status = "mostly-burned"
        elif pct >= 5: status = "partially-burned"
        else: status = "low-burn"
        return {
            "provider": "lite-burn-check",
            "lpAddress": lp_token_address,
            "burnedPct": pct,
            "status": status,
            "breakdown": parts
        }
    except Exception as e:
        return {"provider":"lite-burn-check","lpAddress": lp_token_address, "status":"error", "error": str(e)}
