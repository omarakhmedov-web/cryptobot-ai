from __future__ import annotations
import os
from typing import Any, Dict, Optional
import requests

# --- RPC selection ---
CHAIN_RPC_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY",
    "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY",
    "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY",
    "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY",
    "ftm":"FTM_RPC_URL_PRIMARY",
}

ZERO = "0x0000000000000000000000000000000000000000"

def _rpc_for_chain(short: str) -> Optional[str]:
    env = CHAIN_RPC_ENV.get((short or "").lower().strip())
    return (os.getenv(env, "") or "").strip() or None

def _post_json(rpc: str, payload: dict, timeout: int = 8) -> dict:
    r = requests.post(rpc, json=payload, timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return {}

def _eth_call(rpc: str, to: str, data: str) -> str:
    try:
        out = _post_json(rpc, {
            "jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data},"latest"]
        })
        res = out.get("result") or "0x"
        return res if isinstance(res, str) else "0x"
    except Exception:
        return "0x"

def _get_storage_at(rpc: str, addr: str, slot_hex: str) -> str:
    try:
        out = _post_json(rpc, {
            "jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]
        })
        res = out.get("result") or "0x"
        return res if isinstance(res, str) else "0x"
    except Exception:
        return "0x"

def _as_addr(hexword: str) -> Optional[str]:
    if not hexword or not hexword.startswith("0x"):
        return None
    h = hexword[2:].rjust(64, "0")
    if len(h) < 40:
        return None
    a = "0x" + h[-40:]
    if a.lower() == ZERO.lower():
        return a.lower()
    return a

# --- ERC20 selectors ---
SIG_NAME      = "0x06fdde03"
SIG_SYMBOL    = "0x95d89b41"
SIG_DECIMALS  = "0x313ce567"
SIG_OWNER     = "0x8da5cb5b"
SIG_GETOWNER  = "0x8f32d59b"
SIG__OWNER    = "0x893d20e8"
SIG_PAUSED    = "0x5c975abb"
SIG_TR_OPEN   = "0x3f9f0b9b"   # tradingActive()
SIG_TR_OPEN_2 = "0x5d1532f3"   # isTradingEnabled()
SIG_BUY_TAX   = "0xcb60b99a"
SIG__BUY_TAX  = "0x4b750334"
SIG_SELL_TAX  = "0x2b2a130b"
SIG__SELL_TAX = "0x9f96e965"
SIG_MAX_TX    = "0xe5a06d59"
SIG__MAX_TX   = "0x59f9abfa"
SIG_MAX_WAL   = "0xeea0f7f8"
SIG_MAX_WAL_2 = "0x88a9f7a1"
SIG_IMPL_FN   = "0x5c60da1b"    # implementation()

# EIP-1967 implementation slot
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

def _decode_string(hexdata: str) -> str:
    if not hexdata or not hexdata.startswith("0x"):
        return ""
    h = hexdata[2:]
    # Try dynamic (offset + length + data)
    try:
        if len(h) >= 128:
            ln = int(h[64:128], 16)
            if ln >= 0 and 128 + ln*2 <= len(h):
                raw = bytes.fromhex(h[128:128+ln*2])
                return raw.decode("utf-8", "ignore") or ""
    except Exception:
        pass
    # Fallback: fixed 32 bytes
    try:
        raw = bytes.fromhex(h)
        return raw.rstrip(b"\x00").decode("utf-8", "ignore") or ""
    except Exception:
        return ""

def _decode_u256(hexdata: str) -> Optional[int]:
    if not hexdata or not hexdata.startswith("0x"):
        return None
    try:
        return int(hexdata, 16)
    except Exception:
        return None

def _read_addr_try(rpc: str, token: str, selectors: list[str]) -> Optional[str]:
    for sel in selectors:
        res = _eth_call(rpc, token, sel)
        a = _as_addr(res)
        if a is not None:
            return a.lower()
    return None

def _try_bool(rpc: str, token: str, sel: str) -> Optional[bool]:
    v = _decode_u256(_eth_call(rpc, token, sel))
    if v is None:
        return None
    return v != 0

def _try_u256(rpc: str, token: str, sel: str) -> Optional[int]:
    return _decode_u256(_eth_call(rpc, token, sel))

def _tax_guess(rpc: str, token: str) -> Dict[str, Optional[float]]:
    b = _try_u256(rpc, token, SIG_BUY_TAX)
    if b is None:
        b = _try_u256(rpc, token, SIG__BUY_TAX)
    s = _try_u256(rpc, token, SIG_SELL_TAX)
    if s is None:
        s = _try_u256(rpc, token, SIG__SELL_TAX)
    def _norm(x):
        if x is None:
            return None
        return round(float(x)/100.0, 2) if x > 1000 else float(x)
    return {"buy": _norm(b), "sell": _norm(s)}

def _is_upgradeable_proxy(rpc: str, token: str) -> bool:
    slot_val = _get_storage_at(rpc, token, EIP1967_IMPL_SLOT)
    a = _as_addr(slot_val)
    return a is not None and a.lower() != ZERO.lower()

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    short = (chain_short or "").lower().strip()
    rpc = _rpc_for_chain(short)
    if not (rpc and isinstance(token_address, str) and token_address.startswith("0x") and len(token_address)==42):
        return {"ok": False, "error":"rpc or token invalid"}
    res: Dict[str, Any] = {"ok": True, "chain": short, "token": token_address}

    # ERC-20 meta
    name_hex = _eth_call(rpc, token_address, SIG_NAME)
    sym_hex  = _eth_call(rpc, token_address, SIG_SYMBOL)
    dec_hex  = _eth_call(rpc, token_address, SIG_DECIMALS)
    res["name"] = _decode_string(name_hex) or None
    res["symbol"] = _decode_string(sym_hex) or None
    res["decimals"] = _decode_u256(dec_hex)

    # owner / renounced
    owner = _read_addr_try(rpc, token_address, [SIG_OWNER, SIG_GETOWNER, SIG__OWNER])
    res["owner"] = owner
    res["ownerRenounced"] = (owner == ZERO.lower()) if owner is not None else None

    # paused / trading open
    res["pausable"] = _try_bool(rpc, token_address, SIG_PAUSED)
    t1 = _try_bool(rpc, token_address, SIG_TR_OPEN)
    t2 = _try_bool(rpc, token_address, SIG_TR_OPEN_2)
    res["tradingActive"] = t1 if t1 is not None else t2

    # limits
    res["maxTx"] = _try_u256(rpc, token_address, SIG_MAX_TX) or _try_u256(rpc, token_address, SIG__MAX_TX)
    res["maxWallet"] = _try_u256(rpc, token_address, SIG_MAX_WAL) or _try_u256(rpc, token_address, SIG_MAX_WAL_2)

    # taxes
    res["taxes"] = _tax_guess(rpc, token_address)

    # upgradeable proxy?
    res["upgradeable"] = _is_upgradeable_proxy(rpc, token_address)
    # Try read implementation() fn too
    impl_hex = _eth_call(rpc, token_address, SIG_IMPL_FN)
    impl_addr = _as_addr(impl_hex)
    if impl_addr and impl_addr.lower() != ZERO.lower():
        res["implementation"] = impl_addr.lower()

    # Soft fallback: if no name but symbol exists, use symbol as name
    if (not res.get("name")) and res.get("symbol"):
        res["name"] = res["symbol"]

    return res
