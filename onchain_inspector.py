import os, json, typing, requests, re

from typing import Optional, Dict, Any

ZERO = "0x0000000000000000000000000000000000000000"

# Common function selectors
SIG_NAME      = "0x06fdde03"
SIG_SYMBOL    = "0x95d89b41"
SIG_DECIMALS  = "0x313ce567"
SIG_OWNER     = "0x8da5cb5b"
SIG_PAUSED_1  = "0x5c975abb"  # paused()
SIG_IMPL_FN   = "0x5c60da1b"  # implementation()

# EIP-1967 implementation slot:
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

CHAIN_RPC_ENV = {
    "eth": "ETH_RPC_URL_PRIMARY",
    "bsc": "BSC_RPC_URL_PRIMARY",
    "polygon": "POLYGON_RPC_URL_PRIMARY",
    "arb": "ARB_RPC_URL_PRIMARY",
    "op": "OP_RPC_URL_PRIMARY",
    "base": "BASE_RPC_URL_PRIMARY",
    "avax": "AVAX_RPC_URL_PRIMARY",
    "ftm": "FTM_RPC_URL_PRIMARY",
}

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

PUBLIC_RPC = {
    "eth": ["https://ethereum.publicnode.com", "https://rpc.ankr.com/eth"],
    "bsc": ["https://bsc-dataseed.binance.org", "https://rpc.ankr.com/bsc"],
    "polygon": ["https://polygon-rpc.com", "https://rpc.ankr.com/polygon"],
    "arb": ["https://arb1.arbitrum.io/rpc", "https://rpc.ankr.com/arbitrum"],
    "op": ["https://mainnet.optimism.io", "https://rpc.ankr.com/optimism"],
    "base": ["https://mainnet.base.org"],
    "avax": ["https://api.avax.network/ext/bc/C/rpc", "https://rpc.ankr.com/avalanche"],
    "ftm": ["https://rpc.ftm.tools", "https://rpc.ankr.com/fantom"],
}

def _rpc_for_chain(short: str) -> Optional[str]:
    short = (short or "").strip().lower()
    if not short:
        return None
    # 1) Primary
    ek = CHAIN_RPC_ENV.get(short)
    if ek:
        v = (os.getenv(ek, "") or "").strip()
        if v:
            return v
    # 2) Alternates
    for name in ALT_ENV.get(short, []):
        v = (os.getenv(name, "") or "").strip()
        if v:
            return v
    # 3) RPC_URLS JSON map
    try:
        raw = (os.getenv("RPC_URLS", "") or "").strip()
        if raw:
            j = json.loads(raw)
            if isinstance(j, dict):
                v = j.get(short)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    except Exception:
        pass
    # 4) Public
    lst = PUBLIC_RPC.get(short) or []
    return lst[0] if lst else None

def _post_json(rpc: str, payload: dict, timeout: int = 10) -> dict:
    r = requests.post(rpc, json=payload, timeout=timeout, headers={"User-Agent": "Metridex/1.0"})
    r.raise_for_status()
    return r.json()

def _eth_call(rpc: str, addr: str, data: str) -> Optional[str]:
    try:
        out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":addr,"data":data},"latest"]})
        return out.get("result")
    except Exception:
        return None

def _get_storage_at(rpc: str, addr: str, slot_hex: str) -> Optional[str]:
    try:
        out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]})
        return out.get("result")
    except Exception:
        return None

def _decode_string(hexdata: typing.Optional[str]) -> typing.Optional[str]:
    """
    Robustly decode ERC-20 string/bytes32:
    - dynamic string: 0x | 32-byte offset | 32-byte length | data
    - bytes32: first 32 bytes, right-padded with zeros
    - fallback: raw bytes
    Returns None on failure.
    """
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        raw = bytes.fromhex(hexdata[2:])
        data = b""
        if len(raw) >= 64:
            # Try dynamic string layout
            off = int.from_bytes(raw[0:32], "big")
            if off in (32, 0x20) and len(raw) >= 64:
                ln = int.from_bytes(raw[32:64], "big")
                if ln >= 0 and (64 + ln) <= len(raw):
                    data = raw[64:64+ln]
        if not data:
            # Fallback to bytes32-like static
            if len(raw) >= 32:
                data = raw[:32].split(b"\x00", 1)[0]
            else:
                data = raw
        text = data.replace(b"\x00", b"").decode("utf-8", "ignore")
        text = re.sub(r"\s+", " ", text).strip()
        return text or None
    except Exception:
        return None

def _decode_u256(hexdata: Optional[str]) -> Optional[int]:
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        return int(hexdata, 16)
    except Exception:
        return None

def _as_bool(hexdata: Optional[str]) -> Optional[bool]:
    v = _decode_u256(hexdata)
    if v is None: return None
    return bool(v)

def _as_addr(hexdata: Optional[str]) -> Optional[str]:
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        raw = hexdata[2:].rjust(64, "0")  # 32 bytes
        addr = "0x" + raw[-40:]
        return addr.lower()
    except Exception:
        return None

def _has_code(rpc: str, addr: str) -> Optional[bool]:
    try:
        out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":[addr,"latest"]})
        code = out.get("result") or "0x"
        return isinstance(code, str) and code not in ("0x", "0x0")
    except Exception:
        return None

def _is_upgradeable_proxy(rpc: str, addr: str) -> Optional[bool]:
    # Try EIP-1967 slot
    try:
        st = _get_storage_at(rpc, addr, EIP1967_IMPL_SLOT)
        if isinstance(st, str) and st != "0x" and int(st, 16) != 0:
            return True
    except Exception:
        pass
    # Try implementation() method
    impl = _eth_call(rpc, addr, SIG_IMPL_FN)
    impl_addr = _as_addr(impl)
    if impl_addr and impl_addr.lower() != ZERO.lower():
        return True
    return False

def _normalize_owner(owner: Optional[str]) -> Optional[str]:
    if not owner: return None
    o = owner.lower()
    if o == ZERO or o == "0x000000000000000000000000000000000000dead":
        return ZERO
    return o

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    short = (chain_short or "").lower().strip()
    rpc = _rpc_for_chain(short)
    if not (rpc and isinstance(token_address, str) and token_address.startswith("0x") and len(token_address)==42):
        return {"ok": False, "error": "rpc or token invalid"}
    res: Dict[str, Any] = {"ok": True, "chain": short, "token": token_address}

    # ERC-20 meta
    name_hex = _eth_call(rpc, token_address, SIG_NAME)
    sym_hex  = _eth_call(rpc, token_address, SIG_SYMBOL)
    dec_hex  = _eth_call(rpc, token_address, SIG_DECIMALS)
    res["name"] = _decode_string(name_hex) or None
    res["symbol"] = _decode_string(sym_hex) or None
    res["decimals"] = _decode_u256(dec_hex)

    # owner / renounced
    owner_hex = _eth_call(rpc, token_address, SIG_OWNER)
    owner = _as_addr(owner_hex)
    owner = _normalize_owner(owner)
    res["owner"] = owner or ZERO
    res["renounced"] = bool(owner == ZERO)

    # paused
    paused = _as_bool(_eth_call(rpc, token_address, SIG_PAUSED_1))
    res["paused"] = paused if paused is not None else "—"

    # upgradeable
    res["upgradeable"] = _is_upgradeable_proxy(rpc, token_address)

    # soft limits (best-effort; many tokens don't expose these)
    res["maxTx"] = None
    res["maxWallet"] = None

    # taxes (best-effort; leave None)
    res["taxes"] = {}

    # additional helpful flags
    res["contractCodePresent"] = _has_code(rpc, token_address)

    # pretty token label
    nm, sm = res.get("name"), res.get("symbol")
    if nm and sm:
        res["token"] = f"{nm.strip()} ({sm.strip()})" if isinstance(nm, str) and isinstance(sm, str) else f"{nm} ({sm})"
    elif nm:
        res["token"] = str(nm)
    elif sm:
        res["token"] = str(sm)
    # add decimals into the label for UIs that only print `token:`
    if res.get("decimals") is not None:
        res["token"] = (str(res.get("token")) if res.get("token") is not None else "") + " · Decimals: " + str(res.get("decimals"))

    return res
