# onchain_inspector.py — MDX PRODUCTIVE rev (2025-10-29)
# Changes vs your uploaded version:
# • Chain‑aware LP lockers via LP_LOCKER_ADDRESSES (merges "default", accepts "eth"/"ethereum" keys).
# • LP v2/v3 handling: if pair has no totalSupply → treat as v3 NFT (locks not applicable).
# • Robust owner fallback via storage slot 0 (kept) + upgradeable check via EIP‑1967 slot OR implementation().
# • Honeypot cache kept; added _format_supply for totalDisplay (no silent NameError).
# • Safer helpers and never-raise guarantees preserved.

import os, json, typing, time, re
from typing import Optional, Dict, Any, Tuple
from copy import deepcopy
import requests

# ===== Constants & Selectors =====
ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

SIG_NAME         = "0x06fdde03"
SIG_SYMBOL       = "0x95d89b41"
SIG_DECIMALS     = "0x313ce567"
SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF   = "0x70a08231"
SIG_OWNER        = "0x8da5cb5b"
SIG_PAUSED_1     = "0x5c975abb"   # paused()
SIG_IMPL_FN      = "0x5c60da1b"   # implementation()
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# ===== RPC Resolution (kept & slightly hardened) =====
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
    "polygon": [ "https://polygon-bor.publicnode.com", "https://polygon-rpc.com", "https://rpc.ankr.com/polygon", "https://polygon.llamarpc.com", "https://polygon-rpc.publicnode.com" ],
    "arb": ["https://arb1.arbitrum.io/rpc", "https://rpc.ankr.com/arbitrum"],
    "op": ["https://mainnet.optimism.io", "https://rpc.ankr.com/optimism"],
    "base": ["https://mainnet.base.org"],
    "avax": ["https://api.avax.network/ext/bc/C/rpc", "https://rpc.ankr.com/avalanche"],
    "ftm": ["https://rpc.ftm.tools", "https://rpc.ankr.com/fantom"],
}
def _rpc_candidates_for_chain(short: str) -> list[str]:
    short = (short or "").lower().strip()
    cands: list[str] = []
    ek = CHAIN_RPC_ENV.get(short)
    if ek:
        v = (os.getenv(ek, "") or "").strip()
        if v: cands.append(v)
    for name in ALT_ENV.get(short, []):
        v = (os.getenv(name, "") or "").strip()
        if v and v not in cands:
            cands.append(v)
    try:
        raw = (os.getenv("RPC_URLS", "") or "").strip()
        if raw:
            j = json.loads(raw)
            if isinstance(j, dict):
                v = (j.get(short) or "").strip() if isinstance(j.get(short), str) else ""
                if v and v not in cands:
                    cands.append(v)
    except Exception:
        pass
    for v in PUBLIC_RPC.get(short, []):
        if v and v not in cands:
            cands.append(v)
    # Trim overly long lists (observed BSC instability — try a few quickly)
    return cands[:4] if short == "bsc" and len(cands) > 4 else (cands[:3] if len(cands) > 3 else cands)

# ===== JSON-RPC Helpers =====
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

# ===== Decoders / formatters =====
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
                    txt = data.replace(b"\\x00", b"").decode("utf-8","ignore").strip()
                    return txt or None
        if len(raw) >= 32:
            data = raw[:32].split(b"\\x00",1)[0]
            return data.decode("utf-8","ignore") or None
    except Exception:
        return None
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


# === Built-in defaults for LP lockers (used if LP_LOCKER_ADDRESSES is not set) ===
DEFAULT_LOCKERS = {
    "eth": {
        # UNCX Uniswap V2
        "UNCX": ["0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214"],
        # Team Finance (TrustSwap) ETH
        "TeamFinance": ["0xe2fE530C047F2d85298B07D9333C05737f1435fb"]
    },
    "bsc": {
        # UNCX PancakeSwap V2
        "UNCX": ["0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83"],
        # Team Finance BSC
        "TeamFinance": ["0x0C89C0407775dd89B12918B9c0aa42Bf96518820"],
        # PinkLock (popular lockers on BSC)
        "PinkLockV1": ["0x7Ee058420e5937496F5a2096f04cAa7721cF70CC"],
        "PinkLockV2": ["0x407993575c91Ce7643A4D4cCacc9A98c36EE1BbE"]
    },
    "polygon": {
        # UNCX QuickSwap V2 + Uniswap V2 on Polygon
        "UNCX-QuickSwap": ["0xaDB2437e6F65682B85F814fBc12FeC0508A7B1D0"],
        "UNCX-UniswapV2": ["0x939d71ADe0Bf94d3F8cf578413bF2a2f248BF58b"],
        # Team Finance Polygon
        "TeamFinance": ["0x3eF7442dF454bA6b7C1deEc8DdF29Cfb2d6e56c7"]
    }
}

# ===== Honeypot caching (kept) =====
_HP_CACHE: Dict[tuple, tuple] = {}
_HP_TTL = 120.0
def _honeypot_fetch(chain: str, token: str, timeout: int = 12) -> tuple[dict, dict]:
    k = ((chain or "").lower(), (token or "").lower())
    now = time.time()
    hit = _HP_CACHE.get(k)
    if hit and (now - hit[0] <= _HP_TTL):
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

# ===== LP lockers (new chain‑aware config) =====
def _canon_chain_key(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("eth","ethereum","mainnet"): return "eth"
    if s in ("bsc","bnb","binance-smart-chain"): return "bsc"
    if s in ("polygon","matic"): return "polygon"
    return s
def _locker_config_for_chain(chain_short: str) -> dict[str, list[str]]:
    """Read LP_LOCKER_ADDRESSES JSON and return dict[name] -> [addresses] for a chain, merged with 'default'."""
    cfg = (os.getenv("LP_LOCKER_ADDRESSES") or "").strip()
    if not cfg:
        return {}
    try:
        j = json.loads(cfg)
        # Accept both canonical keys and verbose keys
        ch_map = j.get(_canon_chain_key(chain_short)) or j.get(chain_short) or {}
        # Merge defaults if present
        def_map = j.get("default") or {}
        out: dict[str, list[str]] = {}
        def _add_from(src: dict):
            for name, addrs in (src or {}).items():
                if not isinstance(addrs, list): 
                    continue
                out.setdefault(name, [])
                for a in addrs:
                    if isinstance(a, str) and a.lower().startswith("0x") and len(a) >= 42:
                        a2 = "0x" + a.lower().replace("0x","")[-40:]
                        if a2 not in out[name]:
                            out[name].append(a2)
        _add_from(def_map)
        _add_from(ch_map)
        return out
    except Exception:
        return {}

def _erc20_balance_of(rpc: str, token_addr: str, holder: str) -> int:
    try:
        data = SIG_BALANCE_OF + "0"*24 + holder.lower().replace("0x","")
        res = _eth_call(rpc, token_addr, data)
        v = _decode_u256(res)
        return v or 0
    except Exception:
        return 0

def _lp_v2_stats(rpc: str, chain_short: str, pair_addr: str) -> dict:
    """Return LP-lite stats for ERC-20 LP (v2) with chain-aware lockers & topHolder."""
    out = {"burned_pct": None, "lockers": {}, "top_holder_label": None, "top_holder_pct": None}
    try:
        ts_hex = _eth_call(rpc, pair_addr, SIG_TOTAL_SUPPLY)
        ts = _decode_u256(ts_hex)
        if not (ts and ts > 0):
            return out
        burned = _erc20_balance_of(rpc, pair_addr, DEAD) + _erc20_balance_of(rpc, pair_addr, ZERO)
        out["burned_pct"] = round((burned / ts) * 100, 2) if burned else 0.0

        cfg = _locker_config_for_chain(chain_short)
        top_lab, top_val = "burned", (out["burned_pct"] or 0.0)
        for name, addrs in (cfg or {}).items():
            acc = 0
            for a in addrs:
                acc += _erc20_balance_of(rpc, pair_addr, a)
            pct = round((acc / ts) * 100, 2) if acc else 0.0
            out["lockers"][name] = pct
            if pct > top_val:
                top_val, top_lab = pct, name

        out["top_holder_label"] = top_lab if (top_val and top_val > 0) else None
        out["top_holder_pct"] = top_val if (top_val and top_val > 0) else None
    except Exception:
        return {"burned_pct": None, "lockers": {}, "top_holder_label": None, "top_holder_pct": None}
    return out

# ===== Inspect =====
_INSPECT_CACHE: Dict[Tuple[str,str,str], Tuple[float, dict]] = {}
_INSPECT_TTL = 30.0  # seconds

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Hardened on-chain inspector:
    - Tries multiple RPC endpoints (env -> RPC_URLS JSON -> public)
    - Never raises; always returns a dict with ok/error
    - Caches results for a short TTL to protect from spam
    - Adds LP v2/v3 block and dynamic lockers
    """
    short = (chain_short or "").lower().strip()
    token = (token_address or "").strip()
    pair  = (pair_address or "").strip() if pair_address else ""
    if not (isinstance(token, str) and token.startswith("0x") and len(token) == 42):
        return {"ok": False, "error": "invalid token address", "chain": short, "token": token_address}

    cands = _rpc_candidates_for_chain(short)
    if not cands:
        return {"ok": False, "error": "rpc or token invalid", "chain": short, "token": token_address}

    # Cache
    key = (short, token.lower(), pair.lower())
    now = time.time()
    hit = _INSPECT_CACHE.get(key)
    if hit and (now - hit[0] <= _INSPECT_TTL):
        return deepcopy(hit[1])

    # Pick first usable RPC
    rpc_to_use: Optional[str] = None
    code_present: Optional[bool] = None
    decimals_guess: Optional[int] = None
    for rpc in cands:
        try:
            code_present = bool(_get_code(rpc, token) not in (None, "0x", "0x0"))
            dec_hex = _eth_call(rpc, token, SIG_DECIMALS)
            decimals_guess = _decode_u256(dec_hex)
            rpc_to_use = rpc
            break
        except Exception:
            continue
    if rpc_to_use is None:
        rpc_to_use = cands[0]

    # ERC‑20 reads
    name    = _decode_string(_eth_call(rpc_to_use, token, SIG_NAME))
    symbol  = _decode_string(_eth_call(rpc_to_use, token, SIG_SYMBOL))
    decimals= _decode_u256(_eth_call(rpc_to_use, token, SIG_DECIMALS)) or decimals_guess
    total   = _decode_u256(_eth_call(rpc_to_use, token, SIG_TOTAL_SUPPLY))

    # Owner / paused / upgradeable
    owner = _as_addr(_eth_call(rpc_to_use, token, SIG_OWNER)) or None
    if not owner or owner.lower() == ZERO:
        slot0 = _get_storage_at(rpc_to_use, token, "0x0")
        owner = _as_addr(slot0) or owner
    owner = (owner or "—").lower()
    renounced = (owner == ZERO)
    paused    = _as_bool(_eth_call(rpc_to_use, token, SIG_PAUSED_1))

    upg = False
    st = _get_storage_at(rpc_to_use, token, EIP1967_IMPL_SLOT)
    try:
        if st and st not in ("0x","0x0") and int(st,16) != 0:
            upg = True
        else:
            impl = _eth_call(rpc_to_use, token, SIG_IMPL_FN)
            upg = bool(impl and impl not in ("0x","0x0") and int(impl,16) != 0)
    except Exception:
        upg = False

    # Honeypot (cached)
    hp, hp_meta = _honeypot_fetch(short, token)

    # LP block
    lp_block = None
    lp_v3 = False
    if pair:
        ts_pair = _decode_u256(_eth_call(rpc_to_use, pair, SIG_TOTAL_SUPPLY))
        if ts_pair is None:
            lp_v3 = True  # v3 NFT pool, no fungible LP token supply
        else:
            lp_block = _lp_v2_stats(rpc_to_use, short, pair)

    out: Dict[str, Any] = {
        "ok": True,
        "chain": short,
        "token": token_address,
        "codePresent": code_present if code_present is not None else None,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "totalSupply": total,
        "totalDisplay": _format_supply(total, decimals),
        "owner": owner,
        "renounced": renounced,
        "paused": paused,
        "upgradeable": upg,
        "maxTx": None,
        "maxWallet": None,
        "honeypot": hp,
        "honeypot_meta": hp_meta,
    }
    if lp_block is not None:
        out["lp_lock_lite"] = lp_block
    if lp_v3:
        out["lp_v3"] = True

    _INSPECT_CACHE[key] = (now, deepcopy(out))
    return out

# === Back‑compat wrapper (kept) ===============================================
def build_onchain_payload(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    try:
        return inspect_token(chain_short, token_address, pair_address)
    except Exception as e:
        return {"ok": False, "error": str(e), "chain": (chain_short or "").lower(), "token": token_address}
