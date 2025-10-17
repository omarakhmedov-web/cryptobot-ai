# MDX_PATCH_2025_10_17 v3 — polygon RPCs + timeout 2.5s
# onchain_v2.py — Metridex On-chain (no proxies, no new ENV)
from __future__ import annotations
from typing import Optional, Dict, Any, List
import json, math
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ZERO = "0x0000000000000000000000000000000000000000"

# Public RPCs (rate-limited). Keep short but diverse.
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
        "https://polygon-bor.publicnode.com",
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygon.llamarpc.com",
        "https://polygon-rpc.publicnode.com",
        "https://1rpc.io/polygon",
    ],
}

# ERC-20 selectors
SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_NAME         = "0x06fdde03"
SIG_SYMBOL       = "0x95d89b41"
SIG_DECIMALS     = "0x313ce567"

# Ownable/Pauser selectors
SIG_OWNER        = "0x8da5cb5b"   # owner()
SIG_PAUSED       = "0x5c975abb"   # paused()

# EIP-1967 impl slot = keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC"

def _norm_chain(c: str) -> str:
    c = (c or "").strip().lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","binance","binance-smart-chain"): return "bsc"
    if c in ("polygon","matic"): return "polygon"
    return c or "eth"

def _pick_rpcs(chain: str, rpc_urls: Optional[List[str]]) -> List[str]:
    if rpc_urls and isinstance(rpc_urls, list) and rpc_urls:
        return rpc_urls
    return (_PUBLIC_RPC.get(_norm_chain(chain), []) or [] )[:3]

def _jsonrpc_call(rpc: str, method: str, params: list, timeout: float) -> Optional[dict]:
    payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    req = Request(rpc, data=json.dumps(payload).encode("utf-8"),
                  headers={
                      "Content-Type":"application/json",
                      "User-Agent":"Metridex/OnChain v2 (+https://metridex.com)",
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

def _h2i(x: Optional[str]) -> Optional[int]:
    try:
        if isinstance(x, str) and x.startswith("0x"):
            return int(x, 16)
    except Exception:
        return None
    return None

def _decode_uint(hexdata: Optional[str]) -> Optional[int]:
    v = _h2i(hexdata)
    return v

def _decode_bool(hexdata: Optional[str]) -> Optional[bool]:
    v = _h2i(hexdata)
    if v is None: return None
    return bool(v)

def _decode_string(hexdata: Optional[str]) -> Optional[str]:
    if not hexdata or not isinstance(hexdata, str) or not hexdata.startswith("0x"):
        return None
    try:
        # ABI: dynamic string -> offset at 0x20, length at 0x40
        raw = hexdata[2:]
        if len(raw) >= 128:
            # bytes from 0x40
            strlen = int(raw[64:128], 16)
            start = 128
            end = start + strlen*2
            b = bytes.fromhex(raw[start:end])
            return b.decode("utf-8","ignore").strip("\x00")
        # Fallback: bytes32 padded
        b = bytes.fromhex(raw[-64:])
        return b.rstrip(b"\x00").decode("utf-8","ignore") or None
    except Exception:
        return None

def _try_each(rpcs: List[str], fn, *args):
    for rpc in rpcs:
        out = fn(rpc, *args)
        if out is not None:
            return out
    return None

def _format_supply(total: Optional[int], decimals: Optional[int]) -> Optional[str]:
    if total is None or decimals is None: return None
    try:
        val = total / (10 ** int(decimals))
        # compact formatting
        if val >= 1_000_000_000:
            return f"{val/1_000_000_000:.3f}B"
        if val >= 1_000_000:
            return f"{val/1_000_000:.3f}M"
        return f"{val:,.3f}".replace(",", "_")
    except Exception:
        return None

def check_contract_v2(chain: str, token: str, rpc_urls: Optional[List[str]] = None,
                      timeout_s: float = 2.5) -> Dict[str, Any]:
    rpcs = _pick_rpcs(chain, rpc_urls)
    # Presence
    code = _try_each(rpcs, _eth_get_code, token, timeout_s)
    code_present = bool(code and code != "0x")
    # ERC-20 fields
    name_hex    = _try_each(rpcs, _eth_call, token, SIG_NAME, timeout_s)
    sym_hex     = _try_each(rpcs, _eth_call, token, SIG_SYMBOL, timeout_s)
    dec_hex     = _try_each(rpcs, _eth_call, token, SIG_DECIMALS, timeout_s)
    ts_hex      = _try_each(rpcs, _eth_call, token, SIG_TOTAL_SUPPLY, timeout_s)

    name        = _decode_string(name_hex)
    symbol      = _decode_string(sym_hex)
    decimals    = _decode_uint(dec_hex)
    total       = _decode_uint(ts_hex)

    # Ownable / paused
    owner_hex   = _try_each(rpcs, _eth_call, token, SIG_OWNER, timeout_s)
    paused_hex  = _try_each(rpcs, _eth_call, token, SIG_PAUSED, timeout_s)
    owner       = "—"
    renounced   = None
    if owner_hex and len(owner_hex) >= 66:
        owner_addr = "0x" + owner_hex[-40:]
        owner = owner_addr
        renounced = (owner_addr.lower() == ZERO.lower())

    paused      = _decode_bool(paused_hex)

    # EIP-1967 proxy detection
    impl_hex    = _try_each(rpcs, _eth_get_storage_at, token, EIP1967_IMPL_SLOT, timeout_s)
    upgradeable = bool(impl_hex and impl_hex != "0x" and int(impl_hex,16) != 0)

    info: Dict[str, Any] = {
        "codePresent": code_present,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "totalSupply": total,
        "totalDisplay": _format_supply(total, decimals),
        "owner": owner,
        "renounced": renounced,
        "paused": paused,
        "upgradeable": upgradeable,
    }
    return info
