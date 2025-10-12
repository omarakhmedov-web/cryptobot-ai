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

# Known locker contracts per chain (conservative baseline)
DEFAULT_LOCKERS = {
    "eth": [
        "0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214",
        "0x71b5759d73262fbb223956913ecf4ecc51057641",
        "0xe2fe530c047f2d85298b07d9333c05737f1435fb",
    ],
    "bsc": [
        "0xc765bddb93b0d1c1a88282ba0fa6b2d00e3e0c83",
        "0x407993575c91ce7643a4d4ccacc9a98c36ee1bbe",
    ],
    "polygon": [
        "0xadb2437e6f65682b85f814fbc12fec0508a7b1d0",
    ],
    "arb": [
        "0x275720567e5955f5f2d53a7a1ab8a0fc643de50e",
    ],
    "avax": [
        "0xa9f6aefa5d56db1205f36c34e6482a6d4979b3bb",
    ],
    "base": [
        "0xc4e637d37113192f4f1f060daebd7758de7f4131",
    ],
}

def _parse_addr_list(s: str):
    return [x.strip().lower() for x in (s or "").split(",") if x and x.strip().startswith("0x")]

def _known_lockers(chain: str):
    """
    Resolve locker addresses by priority:
      1) LP_LOCKER_ADDRS_<CHAINUPPER> (comma-separated)
      2) LP_LOCKER_ADDRS (global, comma-separated)
      3) DEFAULT_LOCKERS[chain]
    """
    import os
    ch = (chain or "").lower().strip()
    env_chain = os.getenv(f"LP_LOCKER_ADDRS_{ch.upper()}", "") or os.getenv(f"LP_LOCKER_ADDRS_{ch}", "")
    if env_chain:
        lst = _parse_addr_list(env_chain)
        if lst:
            return lst
    env_global = os.getenv("LP_LOCKER_ADDRS", "")
    if env_global:
        lst = _parse_addr_list(env_global)
        if lst:
            return lst
    return list(DEFAULT_LOCKERS.get(ch, []))

DEAD_ADDRS = [
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000001",
]

def _rpc(chain: str) -> Optional[str]:
    ch = (chain or '').lower().strip()
    env_primary = CHAIN_RPC_ENV.get(ch)
    cand = []
    if env_primary:
        cand.append(env_primary)
    # Fallbacks: <CHAIN>_RPC_URL and uppercase variants
    cand.append(f"{ch.upper()}_RPC_URL_PRIMARY")
    cand.append(f"{ch}_RPC_URL_PRIMARY")
    cand.append(f"{ch.upper()}_RPC_URL")
    cand.append(f"{ch}_RPC_URL")
    # Common aliases
    alias = {
        'eth': ['ETHEREUM_RPC_URL', 'MAINNET_RPC_URL'],
        'bsc': ['BSC_MAINNET_RPC_URL', 'BNB_RPC_URL'],
        'polygon': ['POLYGON_MAINNET_RPC_URL', 'MATIC_RPC_URL'],
        'arb': ['ARBITRUM_RPC_URL'],
        'op': ['OPTIMISM_RPC_URL'],
        'avax': ['AVALANCHE_RPC_URL'],
        'ftm': ['FANTOM_RPC_URL'],
        'base': ['BASE_RPC_URL']
    }.get(ch, [])
    cand.extend(alias)
    for key in cand:
        val = (os.getenv(key, '') or '').strip()
        if val:
            return val
    return None

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
        lockers = _known_lockers(chain)
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
