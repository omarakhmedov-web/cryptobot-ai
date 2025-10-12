
"""
age_fallback.py — On-chain age resolver for AMM pairs/pools (V2/V3)

Usage:
    from age_fallback import resolve_pair_age_days
    age_days = resolve_pair_age_days(chain="bsc", pair_address="0x...")

Reads RPC from env (primary + common aliases):
    ETH_RPC_URL_PRIMARY / ETHEREUM_RPC_URL / MAINNET_RPC_URL
    BSC_RPC_URL_PRIMARY / BSC_MAINNET_RPC_URL / BNB_RPC_URL
    POLYGON_RPC_URL_PRIMARY / POLYGON_MAINNET_RPC_URL / MATIC_RPC_URL
    BASE_RPC_URL_PRIMARY / BASE_RPC_URL
    ARB_RPC_URL_PRIMARY / ARBITRUM_RPC_URL
    OP_RPC_URL_PRIMARY / OPTIMISM_RPC_URL
    AVAX_RPC_URL_PRIMARY / AVALANCHE_RPC_URL
    FTM_RPC_URL_PRIMARY / FANTOM_RPC_URL
"""

from __future__ import annotations
from typing import Optional, Dict
import os, time
from web3 import Web3
from web3._utils.events import get_event_data
from eth_abi import decode_abi

# --- ENV helpers ---
_RPC_ENV_KEYS = {
    "ethereum": ["ETH_RPC_URL_PRIMARY","ETHEREUM_RPC_URL","MAINNET_RPC_URL"],
    "bsc":      ["BSC_RPC_URL_PRIMARY","BSC_MAINNET_RPC_URL","BNB_RPC_URL"],
    "polygon":  ["POLYGON_RPC_URL_PRIMARY","POLYGON_MAINNET_RPC_URL","MATIC_RPC_URL"],
    "base":     ["BASE_RPC_URL_PRIMARY","BASE_RPC_URL"],
    "arbitrum": ["ARB_RPC_URL_PRIMARY","ARBITRUM_RPC_URL"],
    "optimism": ["OP_RPC_URL_PRIMARY","OPTIMISM_RPC_URL"],
    "avalanche":["AVAX_RPC_URL_PRIMARY","AVALANCHE_RPC_URL"],
    "fantom":   ["FTM_RPC_URL_PRIMARY","FANTOM_RPC_URL"],
}

def _rpc_for(chain: str) -> Optional[str]:
    keys = _RPC_ENV_KEYS.get(chain.lower(), [])
    for k in keys:
        v = os.getenv(k)
        if v: return v.strip()
    return None

def _w3(chain: str) -> Optional[Web3]:
    url = _rpc_for(chain)
    if not url: return None
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 12}))
    try:
        _ = w3.eth.block_number
        return w3
    except Exception:
        return None

# --- Minimal ABIs ---
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

# Event signatures
SIG_PAIR_CREATED = Web3.keccak(text="PairCreated(address,address,address,uint256)").hex()
SIG_POOL_CREATED = Web3.keccak(text="PoolCreated(address,address,uint24,int24,address)").hex()

def _has_fn(w3: Web3, addr: str, fn_sig4: str) -> bool:
    code = w3.eth.get_code(Web3.to_checksum_address(addr))
    return fn_sig4.encode() in code  # coarse check

def _call_strict(c, fn: str):
    try:
        return getattr(c.functions, fn)().call()
    except Exception:
        return None

def _resolve_v2(w3: Web3, pair: str) -> Optional[int]:
    pair = Web3.to_checksum_address(pair)
    pair_c = w3.eth.contract(address=pair, abi=PAIR_ABI_MIN)
    factory = _call_strict(pair_c, "factory")
    token0  = _call_strict(pair_c, "token0")
    token1  = _call_strict(pair_c, "token1")
    if not (factory and token0 and token1): 
        return None
    fac = Web3.to_checksum_address(factory)

    # Fetch logs for PairCreated(token0, token1, pair, uint)
    # Try both token orderings (some forks invert when creating)
    topics_base = [SIG_PAIR_CREATED, Web3.to_hex(Web3.to_bytes(hexstr=token0)), Web3.to_hex(Web3.to_bytes(hexstr=token1))]
    topics_rev  = [SIG_PAIR_CREATED, Web3.to_hex(Web3.to_bytes(hexstr=token1)), Web3.to_hex(Web3.to_bytes(hexstr=token0))]

    for topics in (topics_base, topics_rev):
        try:
            logs = w3.eth.get_logs({
                "fromBlock": 1,
                "toBlock": "latest",
                "address": fac,
                "topics": topics + [None]  # data contains non-indexed 'pair' and 'uint'
            })
        except Exception:
            logs = []
        # Decode and match pair
        for log in logs:
            if log["topics"][0].hex() != SIG_PAIR_CREATED: 
                continue
            # data: pair (address) + uint (uint256)
            try:
                data = Web3.to_bytes(hexstr=log["data"])
                # decode address (20 bytes) + uint256 (32 bytes) -> nice path:
                # but simpler: take last 32 bytes as uint; the first 32 bytes holds address right-padded.
                # use abi decoder:
                addr, _ = decode_abi(["address","uint256"], data)
                if Web3.to_checksum_address(addr) == pair:
                    return log["blockNumber"]
            except Exception:
                continue
    return None

def _resolve_v3(w3: Web3, pool: str) -> Optional[int]:
    pool = Web3.to_checksum_address(pool)
    pool_c = w3.eth.contract(address=pool, abi=POOL_ABI_MIN)
    factory = _call_strict(pool_c, "factory")
    token0  = _call_strict(pool_c, "token0")
    token1  = _call_strict(pool_c, "token1")
    if not (factory and token0 and token1):
        return None
    fac = Web3.to_checksum_address(factory)
    # Pull PoolCreated logs, can't filter by fee easily, so filter by signature only
    try:
        logs = w3.eth.get_logs({
            "fromBlock": 1,
            "toBlock": "latest",
            "address": fac,
            "topics": [SIG_POOL_CREATED]
        })
    except Exception:
        logs = []
    # Need full event ABI to decode; simple manual parse:
    for log in logs:
        if log["topics"][0].hex() != SIG_POOL_CREATED:
            continue
        try:
            data = Web3.to_bytes(hexstr=log["data"])
            # PoolCreated(address,address,uint24,int24,address)
            # Both token0, token1, fee are indexed in UniV3, pool is non-indexed => in 'data'
            # But many forks index pool as well; fallback: scan 'data' tail for address
            # Easiest: last 32 bytes of data likely holds the pool address (right-padded)
            pool_addr_bytes = data[-32:]
            pool_addr = Web3.to_checksum_address(pool_addr_bytes[-20:].hex())
            if pool_addr == pool:
                return log["blockNumber"]
        except Exception:
            continue
    return None

def resolve_pair_age_days(chain: str, pair_address: str) -> Optional[float]:
    """
    Returns age in days using chain RPC. Tries V2 then V3 resolver.
    """
    w3 = _w3(chain)
    if not w3:
        return None
    # Prefer V2 path first (fast via indexed topics)
    bn = _resolve_v2(w3, pair_address)
    if bn is None:
        bn = _resolve_v3(w3, pair_address)
    if bn is None:
        return None
    try:
        ts = w3.eth.get_block(bn)["timestamp"]
        now = int(time.time())
        return max(0.0, (now - int(ts)) / 86400.0)
    except Exception:
        return None
