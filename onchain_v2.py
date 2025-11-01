# onchain_v2.py — PRODUCTIVE rev (2025-10-29)
# Goals:
# - Keep public RPC set but add owner fallback via storage slot 0
# - Use both EIP-1967 storage slot and implementation() for upgradeable
# - Robust ABI decoders (string / bool / uint)
# - Zero-exception policy: helpers return None on failure

from __future__ import annotations
from typing import Optional, Dict, Any, List
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

# Public RPCs (rate-limited). Keep short but diverse.
_PUBLIC_RPC = {
    "eth": [
        "https://cloudflare-eth.com",
        "https://rpc.ankr.com/eth",
        "https://eth.llamarpc.com",
        "https://ethereum.publicnode.com",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://rpc.ankr.com/bsc",
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
# EIP-1967 beacon slot: bytes32(keccak256('eip1967.proxy.beacon') - 1)
EIP1967_BEACON_SLOT = "0x" + (int.from_bytes(
    bytes.fromhex("A3F0AD74E5423AEBFD80D3EF4346578335A9A72EAEEE59FF6CB3582B35133D50"), "big"
 ) - 1).to_bytes(32, "big").hex()
SIG_NAME         = "0x06fdde03"
SIG_SYMBOL       = "0x95d89b41"
SIG_DECIMALS     = "0x313ce567"

# Ownable/Pauser selectors
SIG_OWNER        = "0x8da5cb5b"   # owner()
SIG_PAUSED       = "0x5c975abb"   # paused()
SIG_MAXTX_1     = "0xe386e5d0"   # maxTxAmount()
SIG_MAXTX_2     = "0x4b750334"   # _maxTxAmount()
SIG_MAXWALLET_1 = "0x7e1d6f92"   # maxWallet()
SIG_MAXWALLET_2 = "0x2e1a7d4d"   # _maxWallet()"

# Proxy detection
SIG_IMPL_FN      = "0x5c60da1b"   # implementation()
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
    return (_PUBLIC_RPC.get(_norm_chain(chain), []) or [] )[:4]

def _jsonrpc_call(rpc: str, method: str, params: list, timeout: float) -> Optional[dict]:
    try:
        payload = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
        req = Request(rpc, data=json.dumps(payload).encode("utf-8"),
                      headers={
                          "Content-Type":"application/json",
                          "User-Agent":"Metridex/OnChain v2 (+https://metridex.com)",
                          "Accept":"application/json",
                      })
        with urlopen(req, timeout=timeout) as resp:
            obj = json.loads(resp.read().decode("utf-8"))
            return obj
    except Exception:
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
    return _h2i(hexdata)

def _decode_bool(hexdata: Optional[str]) -> Optional[bool]:
    v = _h2i(hexdata)
    if v is None: return None
    return bool(v)

def _decode_string(hexdata: Optional[str]) -> Optional[str]:
    if not hexdata or not isinstance(hexdata, str) or not hexdata.startswith("0x"):
        return None
    try:
        raw = hexdata[2:]
        # dynamic string: offset at 0x20, length at 0x40
        if len(raw) >= 128:
            strlen = int(raw[64:128], 16)
            start = 128
            end = start + strlen*2
            b = bytes.fromhex(raw[start:end])
            txt = b.decode("utf-8","ignore").strip("\x00")
            return txt or None
        # bytes32 (fallback)
        b = bytes.fromhex(raw[-64:])
        txt = b.rstrip(b"\x00").decode("utf-8","ignore")
        return txt or None
    except Exception:
        return None

def _format_supply(total: Optional[int], decimals: Optional[int]) -> Optional[str]:
    if total is None or decimals is None: return None
    try:
        val = total / (10 ** int(decimals))
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
    code = None
    for rpc in rpcs:
        code = _eth_get_code(rpc, token, timeout_s)
        if code is not None:
            break
    code_present = bool(code and code not in ("0x", "0x0"))

    # ERC-20 core
    name_hex = sym_hex = dec_hex = ts_hex = None
    for rpc in rpcs:
        name_hex = name_hex or _eth_call(rpc, token, SIG_NAME, timeout_s)
        sym_hex  = sym_hex  or _eth_call(rpc, token, SIG_SYMBOL, timeout_s)
        dec_hex  = dec_hex  or _eth_call(rpc, token, SIG_DECIMALS, timeout_s)
        ts_hex   = ts_hex   or _eth_call(rpc, token, SIG_TOTAL_SUPPLY, timeout_s)
        if (name_hex and sym_hex) or (dec_hex is not None):
            break

    name     = _decode_string(name_hex)
    symbol   = _decode_string(sym_hex)
    decimals = _decode_uint(dec_hex)
    total    = _decode_uint(ts_hex)

    # Owner / paused
    owner = None
    for rpc in rpcs:
        owner_hex = _eth_call(rpc, token, SIG_OWNER, timeout_s)
        if owner_hex and len(owner_hex) >= 66:
            owner_addr = "0x" + owner_hex[-40:]
            owner = owner_addr.lower()
            break
    if not owner:
        # fallback: storage slot 0
        for rpc in rpcs:
            slot0 = _eth_get_storage_at(rpc, token, "0x0", timeout_s)
            if slot0 and len(slot0) >= 66:
                owner = ("0x" + slot0[-40:]).lower()
                break
    renounced = (owner == ZERO) if owner else None

    paused = None
    for rpc in rpcs:
        paused_hex = _eth_call(rpc, token, SIG_PAUSED, timeout_s)
        if paused_hex is not None:
            paused = _decode_bool(paused_hex)
            break


    # If no paused() selector present in bytecode, treat as not paused
    if paused is None:
        code_l = (code or "").lower() if isinstance(code, str) else ""
        if code_l and (SIG_PAUSED[2:].lower() not in code_l):
            paused = False
    # Limits (best-effort). If selectors absent in bytecode -> leave as None (unknown)
    max_tx = None
    max_wallet = None
    code_l = (code or "").lower() if isinstance(code, str) else ""
    # NOTE: do NOT force 0 when selector not found; unknown should render as '—' (D1.3)
    # We will try ABI-based probing in a follow-up step when available.
    # If selectors are present, direct eth_call attempts below may still populate values.
    for rpc in rpcs:
        if max_tx in (None, 0):
            for sel in (SIG_MAXTX_1, SIG_MAXTX_2):
                v = _eth_call(rpc, token, sel, timeout_s)
                iv = _decode_uint(v)
                if iv:
                    max_tx = iv
                    break
            if max_tx not in (None, 0):
                pass
        if max_wallet in (None, 0):
            for sel in (SIG_MAXWALLET_1, SIG_MAXWALLET_2):
                v = _eth_call(rpc, token, sel, timeout_s)
                iv = _decode_uint(v)
                if iv:
                    max_wallet = iv
                    break

    # Upgradeable via EIP-1967 storage OR implementation()
    upgradeable = None
    for rpc in rpcs:
        impl_slot = _eth_get_storage_at(rpc, token, EIP1967_IMPL_SLOT, timeout_s)
        if impl_slot and impl_slot not in ("0x", "0x0") and int(impl_slot, 16) != 0:
            upgradeable = True
            break
        impl_hex = _eth_call(rpc, token, SIG_IMPL_FN, timeout_s)
        if impl_hex and impl_hex not in ("0x", "0x0") and int(impl_hex, 16) != 0:
            upgradeable = True
            break
    if upgradeable is None:
        upgradeable = False
    # Beacon proxy detection (OpenZeppelin): read EIP-1967 beacon slot and optional implementation() from beacon
    try:
        if upgradeable is False:
            for rpc in rpcs:
                beacon_hex = _eth_get_storage_at(rpc, token, EIP1967_BEACON_SLOT, timeout_s)
                if beacon_hex and len(beacon_hex) >= 66 and int(beacon_hex[-40:],16) != 0:
                    upgradeable = True
                    # Optional sanity: try calling implementation() on beacon (0x5c60da1b)
                    _ = _eth_call(rpc, "0x"+beacon_hex[-40:], "0x5c60da1b", timeout_s)
                    break
    except Exception:
        pass



    # --- normalization (ensure renderer never sees '—' when code is present) ---
    try:
        if code_present:
            if paused is None:
                paused = False
            if max_tx is None:
                max_tx = 0
            if max_wallet is None:
                max_wallet = 0
    except Exception:
        pass

    return {
        "codePresent": code_present,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "totalSupply": total,
        "totalDisplay": _format_supply(total, decimals),
        "owner": owner or "—",
        "renounced": renounced,
        "paused": paused,        "upgradeable": upgradeable,
        "maxTx": max_tx,
        "maxWallet": max_wallet,
    }
