# onchain_inspector.py — PRODUCTIVE rev (2025-10-29, locker-aware)
# Adds chain-aware LP-locker detection via ENV LP_LOCKER_ADDRESSES (JSON).
# Schema (example):
# {
#   "eth":     {"UNCX": ["0x...","0x..."], "TeamFinance": ["0x..."], "PinkLock": ["0x..."]},
#   "bsc":     {"UNCX": ["0x..."], "TeamFinance": ["0x..."]},
#   "polygon": {"UNCX": ["0x..."], "TeamFinance": ["0x..."], "DeepLock": ["0x..."]},
#   "default": {"Gempad": ["0x..."]}
# }
#
# If "default" is present, it is merged into each chain.
# Unknown/empty -> simply skipped; never throws.
#
import os, json, time, re
from typing import Optional, Dict, Any, Tuple
import requests
from copy import deepcopy

ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

# Selectors
SIG_NAME         = "0x06fdde03"
SIG_SYMBOL       = "0x95d89b41"
SIG_DECIMALS     = "0x313ce567"
SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF   = "0x70a08231"
SIG_OWNER        = "0x8da5cb5b"
SIG_PAUSED       = "0x5c975abb"
SIG_IMPL_FN      = "0x5c60da1b"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# RPC discovery
CHAIN_RPC_ENV = {
    "eth": "ETH_RPC_URL_PRIMARY",
    "bsc": "BSC_RPC_URL_PRIMARY",
    "polygon": "POLYGON_RPC_URL_PRIMARY",
}
ALT_ENV = {
    "eth": ["ETH_RPC_URL","ETHEREUM_RPC_URL"],
    "bsc": ["BSC_RPC_URL","BNB_RPC_URL","BSC_RPC"],
    "polygon": ["POLYGON_RPC_URL","MATIC_RPC_URL"],
}
PUBLIC_RPC = {
    "eth": ["https://ethereum.publicnode.com", "https://rpc.ankr.com/eth"],
    "bsc": ["https://bsc-dataseed.binance.org", "https://rpc.ankr.com/bsc"],
    "polygon": ["https://polygon-bor.publicnode.com", "https://polygon-rpc.com", "https://rpc.ankr.com/polygon"],
}

def _rpc_candidates(short: str) -> list[str]:
    short = (short or "").strip().lower()
    out: list[str] = []
    ek = CHAIN_RPC_ENV.get(short)
    if ek:
        v = (os.getenv(ek, "") or "").strip()
        if v: out.append(v)
    for nm in ALT_ENV.get(short, []):
        v = (os.getenv(nm, "") or "").strip()
        if v and v not in out:
            out.append(v)
    try:
        raw = (os.getenv("RPC_URLS", "") or "").strip()
        if raw:
            j = json.loads(raw)
            v = j.get(short)
            if isinstance(v, str) and v.strip():
                if v not in out:
                    out.append(v.strip())
    except Exception:
        pass
    for v in PUBLIC_RPC.get(short, []):
        if v and v not in out:
            out.append(v)
    return out or PUBLIC_RPC.get(short, [])

def _post_json(rpc: str, payload: dict, timeout: int = 4) -> dict | None:
    try:
        r = requests.post(rpc, json=payload, timeout=timeout, headers={"User-Agent":"Metridex/1.1"})
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None

def _eth_call(rpc: str, addr: str, data: str, timeout: int = 4) -> Optional[str]:
    out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":addr,"data":data},"latest"]}, timeout)
    if isinstance(out, dict):
        res = out.get("result")
        if isinstance(res, str): return res
    return None

def _get_storage_at(rpc: str, addr: str, slot_hex: str, timeout: int = 4) -> Optional[str]:
    out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":[addr, slot_hex, "latest"]}, timeout)
    if isinstance(out, dict):
        res = out.get("result")
        if isinstance(res, str): return res
    return None

def _get_code(rpc: str, addr: str, timeout: int = 4) -> Optional[str]:
    out = _post_json(rpc, {"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":[addr,"latest"]}, timeout)
    if isinstance(out, dict):
        res = out.get("result")
        if isinstance(res, str): return res
    return None

def _decode_string(hexdata: Optional[str]) -> Optional[str]:
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        raw = bytes.fromhex(hexdata[2:])
        if len(raw) >= 64:
            off = int.from_bytes(raw[:32], "big")
            if off in (32, 0x20) and len(raw) >= 64:
                ln = int.from_bytes(raw[32:64], "big")
                if 64+ln <= len(raw):
                    data = raw[64:64+ln]
                    txt = data.replace(b"\x00", b"").decode("utf-8","ignore").strip()
                    return txt or None
        if len(raw) >= 32:
            data = raw[:32].split(b"\x00",1)[0]
            return data.decode("utf-8","ignore") or None
    except Exception:
        return None
    return None

def _u256(hexdata: Optional[str]) -> Optional[int]:
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        return int(hexdata, 16)
    except Exception:
        return None

def _as_bool(hexdata: Optional[str]) -> Optional[bool]:
    v = _u256(hexdata); 
    return (None if v is None else bool(v))

def _as_addr(hexdata: Optional[str]) -> Optional[str]:
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        raw = hexdata[2:].rjust(64, "0")
        return "0x" + raw[-40:]
    except Exception:
        return None

def _format_supply(total: Optional[int], decimals: Optional[int]) -> Optional[str]:
    if total is None or decimals is None: return None
    try:
        val = total / (10 ** int(decimals))
        if val >= 1_000_000_000: return f"{val/1_000_000_000:.3f}B"
        if val >= 1_000_000:     return f"{val/1_000_000:.3f}M"
        return f"{val:,.3f}".replace(",", "_")
    except Exception:
        return None

# Honeypot cached
_HP_CACHE: Dict[tuple, tuple] = {}
_HP_TTL = 120.0

def _honeypot(chain: str, token: str, timeout: int = 12) -> tuple[dict, dict]:
    k = ((chain or "").lower(), (token or "").lower())
    now = time.time()
    hit = _HP_CACHE.get(k)
    if hit and now - hit[0] <= _HP_TTL:
        return hit[1].copy(), hit[2].copy()

    aliases = {"eth":["ethereum","eth"], "bsc":["bsc"], "polygon":["polygon","matic"]}
    endpoints = ["https://api.honeypot.is/v2/IsHoneypot", "https://api.honeypot.is/v1/IsHoneypot"]
    last_reason = None
    for ch in aliases.get((chain or '').lower(), ["ethereum"]):
        for ep in endpoints:
            try:
                url = f"{ep}?address={token}&chain={ch}"
                r = requests.get(url, timeout=timeout, headers={"User-Agent":"Metridex/1.1"})
                if r.status_code == 429:
                    last_reason = "429"; continue
                if r.status_code != 200:
                    last_reason = f"http-{r.status_code}"; continue
                j = r.json()
                sim = None
                if isinstance(j.get("simulation"), dict):
                    sim = j["simulation"].get("success")
                if sim is None and isinstance(j.get("isHoneypot"), bool):
                    sim = (not j["isHoneypot"])
                simulation = "OK" if sim is True else ("FAIL" if sim is False else "—")
                risk = None; level = None
                if isinstance(j.get("honeypotResult"), dict):
                    risk = j["honeypotResult"].get("isHoneypot")
                    level = j["honeypotResult"].get("riskLevel")
                taxes = j.get("taxes") or {}
                out = {
                    "simulation": simulation,
                    "risk": risk,
                    "level": level,
                    "buy": taxes.get("buy"),
                    "sell": taxes.get("sell"),
                    "transfer": taxes.get("transfer"),
                }
                meta = {"reason": None}
                _HP_CACHE[k] = (time.time(), out.copy(), meta.copy())
                return out, meta
            except Exception:
                last_reason = "error"
    _HP_CACHE[k] = (time.time(), {}, {"reason": last_reason})
    return {}, {"reason": last_reason}

def _locker_config_for_chain(chain_short: str) -> dict[str, list[str]]:
    """Read LP_LOCKER_ADDRESSES JSON and return dict[name] -> [addresses] for a chain, merged with 'default'."""
    cfg = (os.getenv("LP_LOCKER_ADDRESSES") or "").strip()
    if not cfg:
        return {}
    try:
        j = json.loads(cfg)
        chain_map = j.get(chain_short) or {}
        default_map = j.get("default") or {}
        out: dict[str, list[str]] = {}
        def _add_from(src: dict):
            for name, addrs in (src or {}).items():
                if not isinstance(addrs, list): 
                    continue
                out.setdefault(name, [])
                # normalize
                for a in addrs:
                    if isinstance(a, str) and a.lower().startswith("0x") and len(a) >= 42:
                        a2 = "0x" + a.lower().replace("0x","")[-40:]
                        if a2 not in out[name]:
                            out[name].append(a2)
        _add_from(default_map)
        _add_from(chain_map)
        return out
    except Exception:
        return {}

def _lp_v2_stats(rpc: str, chain_short: str, pair_addr: str) -> dict:
    """Return LP-lite stats for ERC-20 LP (v2) with chain-aware lockers."""
    out = {"burned_pct": None, "lockers": {}, "top_holder_label": None, "top_holder_pct": None}
    try:
        ts_hex = _eth_call(rpc, pair_addr, SIG_TOTAL_SUPPLY)  # if None -> likely v3
        ts = _u256(ts_hex)
        if not (ts and ts > 0):
            return out
        def _bal(holder: str) -> int:
            data = SIG_BALANCE_OF + "0"*24 + holder.lower().replace("0x","")
            res = _eth_call(rpc, pair_addr, data)
            return _u256(res) or 0
        burned = _bal(DEAD) + _bal(ZERO)
        out["burned_pct"] = round((burned / ts) * 100, 2) if burned else 0.0

        # Chain-aware lockers from ENV
        cfg = _locker_config_for_chain(chain_short)
        # Compute pct per locker name
        for name, addrs in cfg.items():
            acc = 0
            for a in addrs:
                acc += _bal(a)
            pct = round((acc / ts) * 100, 2) if acc else 0.0
            out["lockers"][name] = pct

        # Pick top holder among burned vs lockers
        top_lab, top_val = "burned", (out["burned_pct"] or 0.0)
        for name, pct in out["lockers"].items():
            if (pct or 0.0) > top_val:
                top_val, top_lab = pct, name
        out["top_holder_label"] = top_lab if (top_val and top_val > 0) else None
        out["top_holder_pct"] = top_val if (top_val and top_val > 0) else None
    except Exception:
        return {"burned_pct": None, "lockers": {}, "top_holder_label": None, "top_holder_pct": None}
    return out

_INSPECT_CACHE: Dict[tuple, tuple] = {}
_INSPECT_TTL = 30.0

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    short = (chain_short or "").lower().strip()
    token = (token_address or "").strip()
    pair  = (pair_address or "").strip() if pair_address else ""
    if not (isinstance(token, str) and token.startswith("0x") and len(token) == 42):
        return {"ok": False, "error": "invalid token address", "chain": short, "token": token_address}

    # Cache
    key = (short, token.lower(), pair.lower())
    now = time.time()
    hit = _INSPECT_CACHE.get(key)
    if hit and (now - hit[0] <= _INSPECT_TTL):
        return deepcopy(hit[1])

    rpcs = _rpc_candidates(short)
    rpc = rpcs[0] if rpcs else None
    if not rpc:
        return {"ok": False, "error": "no rpc", "chain": short, "token": token_address}

    # Basic reads
    code = _get_code(rpc, token)
    code_present = (isinstance(code, str) and code not in ("0x","0x0"))
    name = _decode_string(_eth_call(rpc, token, SIG_NAME)) or None
    symbol = _decode_string(_eth_call(rpc, token, SIG_SYMBOL)) or None
    decimals = _u256(_eth_call(rpc, token, SIG_DECIMALS))
    total = _u256(_eth_call(rpc, token, SIG_TOTAL_SUPPLY))

    # Owner
    owner = _as_addr(_eth_call(rpc, token, SIG_OWNER)) or None
    if not owner or owner.lower() == ZERO:
        slot0 = _get_storage_at(rpc, token, "0x0")
        owner = _as_addr(slot0) or owner
    owner = (owner or "—").lower()
    renounced = (owner == ZERO)

    paused = _as_bool(_eth_call(rpc, token, SIG_PAUSED))

    # Upgradeable via slot or impl()
    upg = False
    st = _get_storage_at(rpc, token, EIP1967_IMPL_SLOT)
    if st and st not in ("0x","0x0") and int(st,16) != 0:
        upg = True
    else:
        impl = _eth_call(rpc, token, SIG_IMPL_FN)
        try:
            upg = bool(impl and impl not in ("0x","0x0") and int(impl,16) != 0)
        except Exception:
            upg = False

    # Honeypot
    hp, hp_meta = _honeypot(short, token)

    # LP lite
    lp_block = None
    lp_v3 = False
    if pair:
        # Heuristic: if pair totalSupply is missing → treat as v3 (NFT), else compute v2 lite stats
        ts = _u256(_eth_call(rpc, pair, SIG_TOTAL_SUPPLY))
        if ts is None:
            lp_v3 = True
        else:
            lp_block = _lp_v2_stats(rpc, short, pair)

    out = {
        "ok": True,
        "chain": short,
        "token": token_address,
        "codePresent": code_present,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "totalSupply": total,
        "totalDisplay": _format_supply(total, decimals),
        "owner": owner,
        "renounced": renounced,
        "paused": paused,
        "upgradeable": upg,
        "honeypot": hp,
        "honeypot_meta": hp_meta,
    }
    if lp_block is not None:
        out["lp_lock_lite"] = lp_block
    if lp_v3:
        out["lp_v3"] = True

    _INSPECT_CACHE[key] = (time.time(), deepcopy(out))
    return out

def build_onchain_payload(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    try:
        return inspect_token(chain_short, token_address, pair_address)
    except Exception as e:
        return {"ok": False, "error": str(e), "chain": (chain_short or "").lower(), "token": token_address}
