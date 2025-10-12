
"""
age_fallback_safe.py — On-chain age resolver (V2/V3) with lazy deps & safe behavior.
"""
from __future__ import annotations
from typing import Optional
import os, time

# Lazy optional imports
try:
    from web3 import Web3   # type: ignore
except Exception:  # pragma: no cover
    Web3 = None  # type: ignore

try:
    from eth_abi import decode_abi  # type: ignore
except Exception:  # pragma: no cover
    decode_abi = None  # type: ignore

_RPC_ENV_KEYS = {
    "ethereum": ["ETH_RPC_URL_PRIMARY","ETHEREUM_RPC_URL","MAINNET_RPC_URL"],
    "eth":      ["ETH_RPC_URL_PRIMARY","ETHEREUM_RPC_URL","MAINNET_RPC_URL"],
    "bsc":      ["BSC_RPC_URL_PRIMARY","BSC_MAINNET_RPC_URL","BNB_RPC_URL"],
    "polygon":  ["POLYGON_RPC_URL_PRIMARY","POLYGON_MAINNET_RPC_URL","MATIC_RPC_URL"],
    "matic":    ["POLYGON_RPC_URL_PRIMARY","POLYGON_MAINNET_RPC_URL","MATIC_RPC_URL"],
    "base":     ["BASE_RPC_URL_PRIMARY","BASE_RPC_URL"],
    "arbitrum": ["ARB_RPC_URL_PRIMARY","ARBITRUM_RPC_URL"],
    "arb":      ["ARB_RPC_URL_PRIMARY","ARBITRUM_RPC_URL"],
    "optimism": ["OP_RPC_URL_PRIMARY","OPTIMISM_RPC_URL"],
    "op":       ["OP_RPC_URL_PRIMARY","OPTIMISM_RPC_URL"],
    "avalanche":["AVAX_RPC_URL_PRIMARY","AVALANCHE_RPC_URL"],
    "avax":     ["AVAX_RPC_URL_PRIMARY","AVALANCHE_RPC_URL"],
    "fantom":   ["FTM_RPC_URL_PRIMARY","FANTOM_RPC_URL"],
    "ftm":      ["FTM_RPC_URL_PRIMARY","FANTOM_RPC_URL"],
}

def _rpc_for(chain: str) -> Optional[str]:
    keys = _RPC_ENV_KEYS.get((chain or "").lower(), [])
    for k in keys:
        v = os.getenv(k)
        if v: return v.strip()
    return None

def _w3(chain: str):
    if Web3 is None: return None
    url = _rpc_for(chain)
    if not url: return None
    try:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 12}))
        _ = w3.eth.block_number
        return w3
    except Exception:
        return None

PAIR_ABI_MIN = [
    {"name":"factory","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"token0","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"token1","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"getReserves","inputs":[],"outputs":[{"type":"uint112"},{"type":"uint112"},{"type":"uint32"}],"stateMutability":"view","type":"function"},
]
POOL_ABI_MIN = [
    {"name":"factory","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"token0","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"token1","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"name":"slot0","inputs":[],"outputs":[{"type":"int24"},{"type":"int24"},{"type":"uint16"},{"type":"uint16"},{"type":"uint16"},{"type":"uint8"},{"type":"bool"}],"stateMutability":"view","type":"function"},
]

def _sig(text: str):
    if Web3 is None: return None
    try:
        return Web3.keccak(text=text).hex()
    except Exception:
        return None

SIG_PAIR_CREATED = _sig("PairCreated(address,address,address,uint256)")
SIG_POOL_CREATED = _sig("PoolCreated(address,address,uint24,int24,address)")

def _call0(c, name):
    try:
        return getattr(c.functions, name)().call()
    except Exception:
        return None

def _resolve_v2(w3, pair: str):
    if Web3 is None or SIG_PAIR_CREATED is None: return None
    try:
        pair = Web3.to_checksum_address(pair)
        c = w3.eth.contract(address=pair, abi=PAIR_ABI_MIN)
        factory = _call0(c, "factory"); token0 = _call0(c, "token0"); token1 = _call0(c, "token1")
        if not (factory and token0 and token1): return None
        fac = Web3.to_checksum_address(factory)
        topics_base = [SIG_PAIR_CREATED, Web3.to_hex(Web3.to_bytes(hexstr=token0)), Web3.to_hex(Web3.to_bytes(hexstr=token1))]
        topics_rev  = [SIG_PAIR_CREATED, Web3.to_hex(Web3.to_bytes(hexstr=token1)), Web3.to_hex(Web3.to_bytes(hexstr=token0))]
        for topics in (topics_base, topics_rev):
            try:
                logs = w3.eth.get_logs({"fromBlock":1,"toBlock":"latest","address":fac,"topics":topics+[None]})
            except Exception:
                logs = []
            for log in logs:
                try:
                    if log["topics"][0].hex() != SIG_PAIR_CREATED: 
                        continue
                    data_hex = log.get("data", "")
                    if not (isinstance(data_hex, str) and data_hex.startswith("0x")): 
                        continue
                    data = bytes.fromhex(data_hex[2:])
                    if (decode_abi is None) or (len(data) < 64):
                        continue
                    addr, _ = decode_abi(["address","uint256"], data)
                    if Web3.to_checksum_address(addr) == pair:
                        return int(log["blockNumber"])
                except Exception:
                    continue
    except Exception:
        return None
    return None

def _resolve_v3(w3, pool: str):
    if Web3 is None or SIG_POOL_CREATED is None: return None
    try:
        pool = Web3.to_checksum_address(pool)
        c = w3.eth.contract(address=pool, abi=POOL_ABI_MIN)
        factory = _call0(c, "factory"); token0 = _call0(c, "token0"); token1 = _call0(c, "token1")
        if not (factory and token0 and token1): return None
        fac = Web3.to_checksum_address(factory)
        try:
            logs = w3.eth.get_logs({"fromBlock":1,"toBlock":"latest","address":fac,"topics":[SIG_POOL_CREATED]})
        except Exception:
            logs = []
        for log in logs:
            try:
                if log["topics"][0].hex() != SIG_POOL_CREATED:
                    continue
                data_hex = log.get("data", "")
                if not (isinstance(data_hex, str) and data_hex.startswith("0x")):
                    continue
                data = bytes.fromhex(data_hex[2:])
                if len(data) >= 20:
                    pool_addr = "0x" + data[-20:].hex()
                    if Web3.to_checksum_address(pool_addr) == pool:
                        return int(log["blockNumber"])
            except Exception:
                continue
    except Exception:
        return None
    return None

def resolve_pair_age_days(chain: str, pair_address: str) -> Optional[float]:
    if str(os.getenv("AGE_FALLBACK_ENABLED","1")).lower() not in ("1","true","yes"):
        return None
    w3 = _w3(chain)
    if not w3: return None
    bn = _resolve_v2(w3, pair_address)
    if bn is None:
        bn = _resolve_v3(w3, pair_address)
    if bn is None: return None
    try:
        ts = int(w3.eth.get_block(bn)["timestamp"])
        now = int(time.time())
        return max(0.0, (now - ts)/86400.0)
    except Exception:
        return None
