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
    """Resolve RPC for a chain with multiple fallbacks:
    1) *_RPC_URL_PRIMARY env (current behavior)
    2) Alternate envs (e.g., ETH_RPC_URL, POLYGON_RPC_URL, etc.)
    3) RPC_URLS JSON env: {"eth": "...", "bsc": "...", ...}
    4) Known public endpoints (last resort)
    """
    short = (short or "").strip().lower()
    env_key = CHAIN_RPC_ENV.get(short)
    # 1) Primary per-chain env
    cand = []
    if env_key:
        v = (os.getenv(env_key, "") or "").strip()
        if v:
            cand.append(v)

    # 2) Alternate env names (common conventions)
    ALT_ENV = {
        "eth": ["ETH_RPC_URL", "ETHEREUM_RPC_URL"],
        "bsc": ["BSC_RPC_URL", "BNB_RPC_URL", "BSC_RPC"],
        "polygon": ["POLYGON_RPC_URL", "MATIC_RPC_URL"],
        "base": ["BASE_RPC_URL"],
        "arb": ["ARB_RPC_URL", "ARBITRUM_RPC_URL"],
        "op": ["OP_RPC_URL", "OPTIMISM_RPC_URL"],
        "avax": ["AVAX_RPC_URL", "AVALANCHE_RPC_URL"],
        "ftm": ["FTM_RPC_URL", "FANTOM_RPC_URL"],
    }
    for name in ALT_ENV.get(short, []):
        vv = (os.getenv(name, "") or "").strip()
        if vv:
            cand.append(vv)

    # 3) RPC_URLS (JSON map in env)
    try:
        import json as _json
        raw = (os.getenv("RPC_URLS", "") or "").strip()
        if raw:
            j = _json.loads(raw)
            if isinstance(j, dict):
                vv = (j.get(short) or j.get({"eth":"ethereum","arb":"arbitrum","op":"optimism"}.get(short, short)))
                if isinstance(vv, str) and vv.strip():
                    cand.append(vv.strip())
    except Exception:
        pass

    # 4) Known public endpoints (last resort; rate-limited, but enough for lightweight reads)
    PUBLIC = {
        "eth": ["https://ethereum.publicnode.com", "https://rpc.ankr.com/eth"],
        "bsc": ["https://bsc-dataseed.binance.org", "https://rpc.ankr.com/bsc"],
        "polygon": ["https://polygon-rpc.com", "https://rpc.ankr.com/polygon"],
        "arb": ["https://arb1.arbitrum.io/rpc", "https://rpc.ankr.com/arbitrum"],
        "op": ["https://mainnet.optimism.io", "https://rpc.ankr.com/optimism"],
        "base": ["https://mainnet.base.org"],
        "avax": ["https://api.avax.network/ext/bc/C/rpc", "https://rpc.ankr.com/avalanche"],
        "ftm": ["https://rpc.ftm.tools", "https://rpc.ankr.com/fantom"],
    }
    for url in cand + PUBLIC.get(short, []):
        if isinstance(url, str) and url.strip():
            return url.strip()
    return None

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


def _has_code(rpc: str, addr: str) -> bool:
    try:
        out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":[addr,"latest"]})
        code = out.get("result") or "0x"
        return isinstance(code, str) and code not in ("0x", "0x0")
    except Exception:
        return False

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
    # Try fully ABI-compliant dynamic string: [offset][...][length][data]
    try:
        if len(h) >= 64:
            off = int(h[0:64], 16)
            off_hex = off * 2
            if off_hex + 64 <= len(h):
                ln = int(h[off_hex:off_hex+64], 16)
                data_start = off_hex + 64
                data_end = data_start + ln * 2
                if 0 <= ln and data_end <= len(h):
                    raw = bytes.fromhex(h[data_start:data_end])
                    s = raw.decode("utf-8", "ignore")
                    if s:
                        return s
    except Exception:
        pass
    # Fallback: common simplified layout (offset assumed 0x20)
    try:
        if len(h) >= 128:
            ln = int(h[64:128], 16)
            data = h[128:128+ln*2]
            raw = bytes.fromhex(data)
            s = raw.decode("utf-8", "ignore")
            if s:
                return s
    except Exception:
        pass
    # Final fallback: fixed 32-byte
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
