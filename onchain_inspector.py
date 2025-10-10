from __future__ import annotations
import os, re
from typing import Dict, Any, Optional
import requests

UA = os.getenv("HTTP_UA","MetridexBot/1.0 (+https://metridex.com)")
HEADERS = {"User-Agent": UA, "Accept": "application/json"}
RPC_TIMEOUT  = int(os.getenv("PROVIDER_TIMEOUT_SECONDS","8"))

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

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

# EIP-1967 implementation slot
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Common selectors
SIG_OWNER = "0x8da5cb5b"        # owner()
SIG_GETOWNER = "0x893d20e8"     # getOwner()
SIG_PAUSED = "0x5c975abb"       # paused()
SIG_MAX_TX = "0xe590e0d1"       # maxTxAmount()
SIG_MAX_WALLET = "0xdc6dd152"   # maxWalletAmount()
SIG_MINTER_ROLE = "0xd5391393"  # MINTER_ROLE()
SIG_HAS_ROLE = "0x91d14854"     # hasRole(bytes32,address)
SIG_MINT_ENABLED = "0x1a53babb"  # mintEnabled()
SIG_TAX_FEE = "0x3a0f8f39"      # taxFee()
SIG_TOTAL_FEE = "0x7725c0a1"    # totalFee()
SIG_BUY_TAX = "0xd295f62e"      # buyTax()
SIG_SELL_TAX = "0x6f2b3a5f"     # sellTax()
SIG_DENOMINATOR = "0x5dc88c79"  # denominator()
SIG_TRADING_OPEN = "0x84d1a69f" # tradingOpen()
SIG_BLACKLIST = "0xe9f8f4f9"    # isBlacklisted(address)

ZERO = "0x" + "00"*20
DEAD = "0x000000000000000000000000000000000000dEaD"

def _rpc_for_chain(short: str) -> Optional[str]:
    env = CHAIN_RPC_ENV.get(short)
    return (os.getenv(env, "") or "").strip() or None

def _rpc_post(rpc: str, payload: dict) -> dict:
    r = requests.post(rpc, json=payload, timeout=RPC_TIMEOUT, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def _eth_call(rpc: str, to: str, data: str) -> bytes:
    j = _rpc_post(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data},"latest"]})
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _read_addr(b: bytes) -> str:
    if not b or len(b) < 32: return ""
    return "0x" + b[-20:].hex()

def _read_u256(b: bytes) -> int:
    if not b or len(b) < 32: return 0
    return int.from_bytes(b[-32:], "big", signed=False)

def _read_bool(b: bytes) -> Optional[bool]:
    if not b or len(b) < 32: return None
    return bool(int.from_bytes(b[-32:], "big") & 1)

def _storage_at(rpc: str, addr: str, slot_hex: str) -> bytes:
    j = _rpc_post(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]})
    res = j.get("result") or "0x"
    return bytes.fromhex(res[2:]) if res and res.startswith("0x") else b""

def _try_addr(rpc: str, token: str, selector: str) -> Optional[str]:
    try:
        return _read_addr(_eth_call(rpc, token, selector)) or None
    except Exception:
        return None

def _try_u256(rpc: str, token: str, selector: str) -> Optional[int]:
    try:
        return _read_u256(_eth_call(rpc, token, selector)) or None
    except Exception:
        return None

def _try_bool(rpc: str, token: str, selector: str) -> Optional[bool]:
    try:
        return _read_bool(_eth_call(rpc, token, selector))
    except Exception:
        return None

def _is_upgradeable_proxy(rpc: str, token: str) -> bool:
    try:
        impl = _read_addr(_eth_call(rpc, token, "0x5c60da1b"))  # implementation()
        if impl and impl != ZERO: return True
    except Exception:
        pass
    try:
        st = _storage_at(rpc, token, EIP1967_IMPL_SLOT)
        return bool(_read_addr(st))
    except Exception:
        return False

def _detect_denominator(rpc: str, token: str) -> int:
    for sig in (SIG_DENOMINATOR,):
        v = _try_u256(rpc, token, sig)
        if v and v in (10, 100, 1000, 10000, 100000): return v
    return 100  # sane default

def _tax_guess(rpc: str, token: str) -> Dict[str, Optional[float]]:
    denom = _detect_denominator(rpc, token)
    def pct(val: Optional[int]) -> Optional[float]:
        if not val: return None
        try:
            return round(float(val) * 100.0/ float(denom), 2)
        except Exception:
            return None
    # Try several common names
    buy = _try_u256(rpc, token, SIG_BUY_TAX) or _try_u256(rpc, token, SIG_TAX_FEE)
    sell = _try_u256(rpc, token, SIG_SELL_TAX) or _try_u256(rpc, token, SIG_TOTAL_FEE)
    return {"buy": pct(buy), "sell": pct(sell)}

def _mint_capability(rpc: str, token: str) -> Optional[bool]:
    # Heuristic: if MINTER_ROLE() exists and hasRole() exists, assume minting can be configured.
    try:
        role = _eth_call(rpc, token, SIG_MINTER_ROLE)
        if role and len(role) >= 32:
            # check hasRole(role, owner) only to see if function exists (call with zero addr)
            _ = _eth_call(rpc, token, SIG_HAS_ROLE + role.hex() + ("0"*24) + "0"*40)
            return True
    except Exception:
        pass
    # or direct flag
    val = _try_bool(rpc, token, SIG_MINT_ENABLED)
    if val is not None: return val
    return None

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    short = (chain_short or "").lower().strip()
    rpc = _rpc_for_chain(short)
    if not (rpc and ADDR_RE.match(token_address or "")):
        return {"ok": False, "error":"rpc or token invalid"}
    res: Dict[str, Any] = {"ok": True, "chain": short, "token": token_address}

    # owner / renounced
    owner = _try_addr(rpc, token_address, SIG_OWNER) or _try_addr(rpc, token_address, SIG_GETOWNER)
    res["owner"] = owner or None
    if owner:
        res["ownerRenounced"] = owner.lower() in (ZERO.lower(), DEAD.lower())

    # paused / trading open
    res["pausable"] = _try_bool(rpc, token_address, SIG_PAUSED)

    # trading open flag is non-standard; if present, good to expose
    res["tradingOpen"] = _try_bool(rpc, token_address, SIG_TRADING_OPEN)

    # limits
    res["maxTx"] = _try_u256(rpc, token_address, SIG_MAX_TX)
    res["maxWallet"] = _try_u256(rpc, token_address, SIG_MAX_WALLET)

    # taxes
    res["taxes"] = _tax_guess(rpc, token_address)

    # mint / roles
    res["mint"] = _mint_capability(rpc, token_address)

    # blacklist (capability)
    try:
        # isBlacklisted(address(0)) — just to probe selector presence
        b = _eth_call(rpc, token_address, SIG_BLACKLIST + "0"*64)
        res["blacklistCap"] = True if b is not None else None
    except Exception:
        res["blacklistCap"] = None

    # upgradeable proxy?
    res["upgradeable"] = _is_upgradeable_proxy(rpc, token_address)

    return res