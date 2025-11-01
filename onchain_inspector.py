# MDX_PATCH_2025_10_17 v4 — inspector polygon RPCs + timeout 2.5s
import os, json, typing, time, re

# Built-in DEFAULT_LOCKERS when LP_LOCKER_ADDRESSES not set
DEFAULT_LOCKERS = {
    "eth": {
        "UNCX": ["0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214"],
        "TeamFinance": ["0xe2fE530C047F2d85298B07D9333C05737f1435fb"]
    },
    "bsc": {
        "UNCX": ["0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83"],
        "TeamFinance": ["0x0C89C0407775dd89B12918B9c0aa42Bf96518820"],
        "PinkLockV1": ["0x7Ee058420e5937496F5a2096f04cAa7721cF70CC"],
        "PinkLockV2": ["0x407993575c91Ce7643A4D4cCacc9A98c36EE1BbE"]
    },
    "polygon": {
        "UNCX-QuickSwap": ["0xaDB2437e6F65682B85F814fBc12FeC0508A7B1D0"],
        "UNCX-UniswapV2": ["0x939d71ADe0Bf94d3F8cf578413bF2a2f248BF58b"],
        "TeamFinance": ["0x3eF7442dF454bA6b7C1deEc8DdF29Cfb2d6e56c7"]
    }
}
from typing import Optional, Dict, Any, Tuple
from copy import deepcopy
import requests

# ===== Constants & Selectors =====
ZERO = "0x0000000000000000000000000000000000000000"

SIG_NAME         = "0x06fdde03"
SIG_SYMBOL       = "0x95d89b41"
SIG_DECIMALS     = "0x313ce567"
SIG_TOTAL_SUPPLY = "0x18160ddd"
SIG_BALANCE_OF   = "0x70a08231"
SIG_OWNER        = "0x8da5cb5b"
SIG_PAUSED_1     = "0x5c975abb"   # paused()
SIG_IMPL_FN      = "0x5c60da1b"   # implementation()

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"



def _is_proxy(rpc: str, addr: str) -> bool:
    try:
        slot = _get_storage_at(rpc, addr, EIP1967_IMPL_SLOT)
        if isinstance(slot, str) and slot.startswith("0x"):
            # any non-zero storage at impl slot is a proxy indicator
            try:
                v = int(slot, 16)
                return v != 0
            except Exception:
                return bool(slot and slot != "0x")
        return False
    except Exception:
        return False

# ===== RPC Resolution =====
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
    """Return a list of RPC endpoints to try for the given chain, ordered by priority.
    Includes primary/alt envs, JSON map, and all known public RPCs for the chain.
    """
    short = (short or "").lower().strip()
    cands: list[str] = []

    # Primary env (highest priority)
    ek = CHAIN_RPC_ENV.get(short)
    if ek:
        v = (os.getenv(ek, "") or "").strip()
        if v: cands.append(v)

    # Alternate envs
    for name in ALT_ENV.get(short, []):
        v = (os.getenv(name, "") or "").strip()
        if v and v not in cands:
            cands.append(v)

    # JSON map
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

    # All public RPCs for the chain
    for v in PUBLIC_RPC.get(short, []):
        if v and v not in cands:
            cands.append(v)

    return cands[:4] if short == "bsc" and len(cands) > 4 else (cands[:2] if len(cands) > 2 else cands)
def _rpc_for_chain(short: str) -> Optional[str]:
    short = (short or "").strip().lower()
    if not short:
        return None
    # 1) Primary env
    ek = CHAIN_RPC_ENV.get(short)
    if ek:
        v = (os.getenv(ek, "") or "").strip()
        if v:
            return v
    # 2) Alternate envs
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

# ===== JSON-RPC Helpers =====
def _post_json(rpc: str, payload: dict, timeout: int = 4) -> dict:
    r = requests.post(rpc, json=payload, timeout=timeout, headers={"User-Agent":"Metridex/1.0"})
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

# ===== Decoders =====
def _decode_string(hexdata: Optional[str]) -> Optional[str]:
    """
    Robustly decode ERC-20 string/bytes32:
    - dynamic string: 0x | 32-byte offset | 32-byte length | data
    - bytes32: first 32 bytes, right-padded with zeros
    - fallback: raw bytes
    """
    if not (isinstance(hexdata, str) and hexdata.startswith("0x")):
        return None
    try:
        raw = bytes.fromhex(hexdata[2:])
        data = b""
        if len(raw) >= 64:
            off = int.from_bytes(raw[0:32], "big")
            if off in (32, 0x20) and len(raw) >= 64:
                ln = int.from_bytes(raw[32:64], "big")
                if ln >= 0 and (64 + ln) <= len(raw):
                    data = raw[64:64+ln]
        if not data:
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
        raw = hexdata[2:].rjust(64, "0")
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
    try:
        st = _get_storage_at(rpc, addr, EIP1967_IMPL_SLOT)
        if isinstance(st, str) and st != "0x" and int(st, 16) != 0:
            return True
    except Exception:
        pass
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

# ===== Honeypot defaults & caching =====
_HP_CACHE: Dict[Tuple[str,str], Tuple[float, dict, dict]] = {}
_HP_TTL = 120.0  # seconds

def _honeypot_defaults(chain: str, token: str) -> Optional[dict]:
    raw = (os.getenv("HONEYPOT_DEFAULTS", "") or "").strip()
    if not raw:
        return None
    try:
        mp = json.loads(raw)
        if not isinstance(mp, dict): return None
        key = f"{(chain or '').lower()}:{(token or '').lower()}"
        val = mp.get(key)
        return val if isinstance(val, dict) else None
    except Exception:
        return None

def _honeypot_check(chain: str, token: str, timeout: int = 12) -> Tuple[dict, dict]:
    """
    Robust Honeypot.is fetch with retries & reason tagging.
    Returns (out, meta) where meta = {"reason": <str|None>} when no data.
    """
    # 0) Defaults override
    d = _honeypot_defaults(chain, token)
    if d:
        out = {
            "simulation": d.get("simulation"),
            "risk": d.get("risk"),
            "level": d.get("level"),
            "buy": d.get("buy"),
            "sell": d.get("sell"),
            "transfer": d.get("transfer"),
        }
        return out, {"reason": "override"}

    aliases = {
        "eth": ["ethereum","eth"],
        "bsc": ["bsc"],
        "polygon": ["polygon","matic"],
        "arb": ["arbitrum","arb"],
        "op": ["optimism","op"],
        "base": ["base"],
        "avax": ["avalanche","avax"],
        "ftm": ["fantom","ftm"],
    }
    chains = aliases.get((chain or "").lower(), ["ethereum"])
    endpoints = [
        "https://api.honeypot.is/v2/IsHoneypot",
        "https://api.honeypot.is/v1/IsHoneypot",
        "https://api.honeypot.is/IsHoneypot",
    ]

    last_reason = None
    # Two attempts across endpoints/aliases (light backoff)
    for attempt in range(2):
        for ch in chains:
            for ep in endpoints:
                try:
                    url = f"{ep}?address={token}&chain={ch}"
                    r = requests.get(url, timeout=timeout, headers={"User-Agent":"Metridex/1.0"})
                    if r.status_code == 429:
                        last_reason = "429"; continue
                    if r.status_code != 200:
                        last_reason = f"http-{r.status_code}"; continue
                    try:
                        j = r.json()
                    except Exception:
                        last_reason = "bad-json"; continue

                    # simulation
                    sim = None
                    if isinstance(j.get("simulation"), dict):
                        sim = j["simulation"].get("success")
                    if sim is None and "isHoneypot" in j and isinstance(j["isHoneypot"], bool):
                        sim = (not j["isHoneypot"])
                    simulation = "OK" if sim is True else ("FAIL" if sim is False else "—")

                    # risk / level
                    risk = None; level = None
                    if isinstance(j.get("honeypotResult"), dict):
                        risk = j["honeypotResult"].get("isHoneypot")
                        level = j["honeypotResult"].get("riskLevel")
                    if risk is None and "isHoneypot" in j and isinstance(j["isHoneypot"], bool):
                        risk = "low" if (j["isHoneypot"] is False) else "high"

                    taxes = j.get("taxes") or {}
                    out = {
                        "simulation": simulation,
                        "risk": risk,
                        "level": level,
                        "buy": round(float(taxes.get("buy")),2) if isinstance(taxes.get("buy"), (int,float)) else None,
                        "sell": round(float(taxes.get("sell")),2) if isinstance(taxes.get("sell"), (int,float)) else None,
                        "transfer": round(float(taxes.get("transfer")),2) if isinstance(taxes.get("transfer"), (int,float)) else None,
                    }
                    return out, {"reason": None}
                except requests.Timeout:
                    last_reason = "timeout"
                except Exception:
                    last_reason = "error"
        time.sleep(0.35)

    # Fallback without chain
    try:
        url = f"https://api.honeypot.is/v2/IsHoneypot?address={token}"
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Metridex/1.0"})
        if r.status_code == 200:
            j = r.json()
            sim = None
            if isinstance(j.get("simulation"), dict):
                sim = j["simulation"].get("success")
            simulation = "OK" if sim is True else ("FAIL" if sim is False else "—")
            taxes = j.get("taxes") or {}
            out = {
                "simulation": simulation,
                "risk": (j.get("honeypotResult") or {}).get("isHoneypot"),
                "level": (j.get("honeypotResult") or {}).get("riskLevel"),
                "buy": taxes.get("buy"),
                "sell": taxes.get("sell"),
                "transfer": taxes.get("transfer"),
            }
            return out, {"reason": None}
    except requests.Timeout:
        last_reason = "timeout"
    except Exception:
        last_reason = "error"

    return {}, {"reason": last_reason}

def _honeypot_fetch_cached(chain: str, token: str) -> Tuple[dict, dict]:
    k = ((chain or "").lower(), (token or "").lower())
    now = time.time()
    hit = _HP_CACHE.get(k)
    if hit and (now - hit[0] <= _HP_TTL):
        return hit[1].copy(), hit[2].copy()
    out, meta = _honeypot_check(chain, token)
    _HP_CACHE[k] = (time.time(), out.copy(), meta.copy())
    return out, meta

# ===== LP Lite =====
def _erc20_balance_of(rpc: str, token_addr: str, holder: str):
    try:
        data = SIG_BALANCE_OF + "0"*24 + holder.lower().replace("0x","")
        res = _eth_call(rpc, token_addr, data)
        return _decode_u256(res)
    except Exception:
        return None

def _lp_lock_lite(rpc: str, pair_addr: str, chain: str):
    """
    Returns dict:
      burned_pct, lockers: {"UNCX": pct, "TeamFinance": pct}, top_holder_label, top_holder_pct
    """
    out = {"burned_pct": None, "lockers": {}, "top_holder_label": None, "top_holder_pct": None}
    if not (rpc and isinstance(pair_addr, str) and pair_addr.startswith("0x")):
        return out
    ts_hex = _eth_call(rpc, pair_addr, SIG_TOTAL_SUPPLY)
    ts = _decode_u256(ts_hex)
    if not ts or ts <= 0:
        return out

    DEAD = "0x000000000000000000000000000000000000dead"
    ZERO = "0x0000000000000000000000000000000000000000"
    burned = 0
    for addr in (DEAD, ZERO):
        bal = _erc20_balance_of(rpc, pair_addr, addr)
        if isinstance(bal, int):
            burned += bal
    out["burned_pct"] = round((burned / ts) * 100, 2) if burned else 0.0

    defaults = {
        "eth": {
            "UNCX": ["0x0fF9d5D7C7f3f271547dF6fC9E1Ff7A3aC3f7b6a"],
            "TeamFinance": ["0x3b77f1b32b66f3ee0D47b7d4dF47E7B06C5744F3"],
        },
        "bsc": {
            "UNCX": ["0x3a4f06431457de873b588846c64041b95df72ea5"],
            "TeamFinance": ["0x0c1cf4f1f1458e8f26b55685b9a78e78d7e4c37c"],
        },
        "polygon": {
            "UNCX": ["0x9ad32b9004c2d5c5bf31eceb0165aaf1cdbf62d0"],
            "TeamFinance": ["0x8c87b7517a4e2b45286da5dadda8e90d518d042d"],
        }
    }
    try:
        cfg = os.getenv("LP_LOCKER_ADDRESSES") or ""
        if cfg.strip():
            j = json.loads(cfg)
            if isinstance(j, dict):
                defaults = j
    except Exception:
        pass

    lockers = defaults.get(chain, {})
    top_label, top_val = None, 0.0
    for name, addrs in lockers.items():
        total = 0
        for a in (addrs or []):
            bal = _erc20_balance_of(rpc, pair_addr, a)
            if isinstance(bal, int):
                total += bal
        pct = round((total / ts) * 100, 2) if total else 0.0
        out["lockers"][name] = pct
        if pct > top_val:
            top_val, top_label = pct, name

    if out["burned_pct"] is not None and out["burned_pct"] > top_val:
        top_val, top_label = out["burned_pct"], "burned"

    out["top_holder_label"] = top_label
    out["top_holder_pct"] = top_val if top_val > 0 else None
    return out

# ===== Inspect =====
_INSPECT_CACHE: Dict[Tuple[str,str,str], Tuple[float, dict]] = {}
_INSPECT_TTL = 30.0  # seconds


def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Hardened on-chain inspector:
    - Tries multiple RPC endpoints (env -> RPC_URLS JSON -> public)
    - Never raises; always returns a dict with ok/error
    - Avoids duplicate RPC calls (previous version duplicated ERC-20 reads)
    - Caches results for a short TTL to protect from spam
    """
    short = (chain_short or "").lower().strip()
    token = (token_address or "").strip()
    pair  = (pair_address or "").strip() if pair_address else ""
    # Validate inputs early
    if not (isinstance(token, str) and token.startswith("0x") and len(token) == 42):
        return {"ok": False, "error": "invalid token address", "chain": short, "token": token_address}
    cands = _rpc_candidates_for_chain(short)
    if not cands:
        # keep compatible error string seen in logs
        return {"ok": False, "error": "rpc or token invalid", "chain": short, "token": token_address}
    # Cache
    key = (short, token.lower(), pair.lower())
    now = time.time()
    hit = _INSPECT_CACHE.get(key)
    if hit and (now - hit[0] <= _INSPECT_TTL):
        return deepcopy(hit[1])

    # Pick a working rpc (first that yields either codePresent or decimals)
    rpc_to_use: Optional[str] = None
    code_present: Optional[bool] = None
    decimals_guess: Optional[int] = None
    for rpc in cands:
        try:
            code_present = _has_code(rpc, token)
            dec_hex = _eth_call(rpc, token, SIG_DECIMALS)
            decimals_guess = _decode_u256(dec_hex)
            if code_present is not None or decimals_guess is not None:
                rpc_to_use = rpc
                break
        except Exception:
            # continue to next rpc
            continue
    if rpc_to_use is None:
        # As a last resort, pick the first candidate but mark as degraded
        rpc_to_use = cands[0]

    # Perform reads (each call is internally guarded and returns None on failure)
    name_hex = _eth_call(rpc_to_use, token, SIG_NAME)
    sym_hex  = _eth_call(rpc_to_use, token, SIG_SYMBOL)
    dec_hex  = _eth_call(rpc_to_use, token, SIG_DECIMALS)
    ts_hex   = _eth_call(rpc_to_use, token, SIG_TOTAL_SUPPLY)

    name    = _decode_string(name_hex)
    symbol  = _decode_string(sym_hex)
    decimals= _decode_u256(dec_hex) if dec_hex is not None else decimals_guess
    total   = _decode_u256(ts_hex)

    # Owner / paused / upgradeable
    owner_raw = _eth_call(rpc_to_use, token, SIG_OWNER)
    owner = _as_addr(owner_raw)
    if not owner or owner.lower() == ZERO:
        slot0 = _get_storage_at(rpc_to_use, token, "0x0")
        slot_owner = _as_addr(slot0)
        if slot_owner and slot_owner.lower() != ZERO:
            owner = slot_owner
    owner = _normalize_owner(owner)

    paused    = _as_bool(_eth_call(rpc_to_use, token, SIG_PAUSED_1))
    impl_hex  = _eth_call(rpc_to_use, token, SIG_IMPL_FN)
    upgradeable = bool(impl_hex and isinstance(impl_hex, str) and impl_hex not in ("0x", "0x0") and int(impl_hex,16) != 0)

    # Honeypot (best-effort; cached)
    hp, hp_meta = _honeypot_fetch_cached(short, token)

    out: Dict[str, Any] = {
        "ok": True,
        "chain": short,
        "token": token_address,
        "codePresent": bool(code_present) if code_present is not None else None,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "totalSupply": total,
        "totalDisplay": None,
        "owner": owner,
        "renounced": owner == ZERO,
        "paused": paused,
        "upgradeable": upgradeable,
        "maxTx": None,
        "maxWallet": None,
        "honeypot": hp,
        "honeypot_meta": hp_meta,
    }
    # Post-formatting
    try:
        out["totalDisplay"] = _format_supply(total, decimals)  # if available in this module
    except Exception:
        pass

    _INSPECT_CACHE[key] = (now, deepcopy(out))



    
    return out


# === Back-compat wrapper =======================================================
def build_onchain_payload(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    """Compatibility shim expected by server diagnostics.
    Delegates to inspect_token(...) and returns the same payload.
    Safe: never raises; mirrors inspect_token's guarantees.
    """
    try:
        return inspect_token(chain_short, token_address, pair_address)
    except Exception as e:
        return {"ok": False, "error": str(e), "chain": (chain_short or "").lower(), "token": token_address}

TIMEOUT_SECONDS = 2.5  # MDX_PATCH_2025_10_17 v4


def _canon_chain_key(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("eth","ethereum","mainnet"): return "eth"
    if s in ("bsc","bnb","binance-smart-chain"): return "bsc"
    if s in ("polygon","matic"): return "polygon"
    return s

def _locker_config_for_chain(chain_short: str):
    import os, json
    cfg = (os.getenv("LP_LOCKER_ADDRESSES") or "").strip()
    out = {}
    def _add_from(src):
        for name, addrs in (src or {}).items():
            if not isinstance(addrs, list): 
                continue
            out.setdefault(name, [])
            for a in addrs:
                if isinstance(a, str) and a.lower().startswith("0x") and len(a) >= 42:
                    a2 = "0x" + a.lower().replace("0x","")[-40:]
                    if a2 not in out[name]:
                        out[name].append(a2)
    if cfg:
        try:
            j = json.loads(cfg)
            ch_map = j.get(_canon_chain_key(chain_short)) or j.get(chain_short) or {}
            def_map = j.get("default") or {}
            _add_from(def_map); _add_from(ch_map)
        except Exception:
            pass
    if not out:
        _add_from(DEFAULT_LOCKERS.get(_canon_chain_key(chain_short)) or {})
    return out


# =======================
# D1 COMPAT PATCH (append-only, non-destructive)
# Version: 0.4.1-D1-COMPAT (2025-11-01)
# Rationale:
#  - Keep the entire original module intact.
#  - Append a hardened implementation and override ONLY the public entry points:
#       inspect_token(...), build_onchain_payload(...)
#  - Do not remove or change any other functions/consts used elsewhere.
#  - Safe to drop-in; if needed, revert by restoring the original file.

from typing import Dict, Any, Optional, List
import os, json

try:
    from cache import cache_get, cache_set
except Exception:
    def cache_get(_k: str): return None
    def cache_set(_k: str, _v: str, _ttl: int=300): return None

try:
    from web3 import Web3
except Exception:
    Web3 = None  # allows graceful degradation

# --- Local helpers (prefixed to avoid clashing with originals) ---

def _d1_canon_chain(c: str) -> str:
    c = (c or "").strip().lower()
    if c in ("eth","ethereum"): return "eth"
    if c in ("bsc","bep20","binance"): return "bsc"
    if c in ("polygon","matic"): return "polygon"
    return c or "eth"

def _d1_rpc_candidates_for_chain(chain: str) -> List[str]:
    short = _d1_canon_chain(chain)
    out: List[str] = []
    raw = (os.getenv("RPC_URLS") or "").strip()
    if raw:
        try:
            j = json.loads(raw)
            arr = j.get(short) or j.get(chain) or []
            if isinstance(arr, list):
                out += [str(x).strip() for x in arr]
        except Exception:
            pass
    # Per-chain single envs
    env_map = {
        "eth": os.getenv("ETH_RPC_URL","").strip(),
        "bsc": os.getenv("BSC_RPC_URL","").strip(),
        "polygon": os.getenv("POLYGON_RPC_URL","").strip(),
    }
    if env_map.get(short):
        out.append(env_map[short])
    # Public fallbacks
    public = {
        "eth": ["https://ethereum.publicnode.com","https://rpc.ankr.com/eth"],
        "bsc": ["https://bsc.publicnode.com","https://rpc.ankr.com/bsc"],
        "polygon": ["https://polygon-rpc.com","https://rpc.ankr.com/polygon"],
    }
    out += public.get(short, [])
    # dedup preserve order
    seen=set(); dedup=[]
    for u in out:
        if u and u not in seen: seen.add(u); dedup.append(u)
    return dedup

def _d1_w3_for(url: str):
    if not Web3: return None
    try:
        return Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": float(os.getenv("RPC_TIMEOUT_SECONDS","8"))}))
    except Exception:
        return None

def _d1_eth_call(w3, to_addr: str, data: str):
    try:
        payload = {"to": to_addr, "data": data}
        res = w3.eth.call(payload)
        if isinstance(res,(bytes,bytearray)): return bytes(res)
        if isinstance(res,str) and res.startswith("0x"):
            return bytes.fromhex(res[2:])
    except Exception:
        return None
    return None

def _d1_u32(res):  # uint256 tail
    if not res: return None
    try: return int.from_bytes(res[-32:], "big")
    except Exception: return None

def _d1_bool(res):
    v = _d1_u32(res)
    return None if v is None else bool(v)

def _d1_str(res):
    if not res: return None
    try:
        if len(res) >= 64:
            off = int.from_bytes(res[0:32], "big")
            if off + 32 <= len(res):
                ln = int.from_bytes(res[off:off+32], "big")
                raw = res[off+32:off+32+ln]
                return raw.decode("utf-8","ignore").strip("\\x00")
        s = res[-32:].rstrip(b"\\x00").decode("utf-8","ignore")
        return s if s else None
    except Exception:
        return None

# EIP-1967 impl slot
_EIP1967_IMPL_SLOT = "0x" + (int.from_bytes(
    bytes.fromhex("360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC"), "big"
) - 1).to_bytes(32, "big").hex()

def _d1_get_code_present(w3, addr: str) -> bool:
    try:
        code = w3.eth.get_code(addr)
        return bool(code and len(code)>0)
    except Exception:
        return False

def _d1_get_impl(w3, addr: str):
    try:
        res = w3.eth.get_storage_at(addr, _EIP1967_IMPL_SLOT)
        if res and len(res)>=32 and int(res[-20:].hex(), 16)!=0:
            return "0x" + res[-20:].hex()
    except Exception:
        return None
    return None

# 4-byte selector of mint(address,uint256)
_SIG_MINT = "40c10f19"
def _d1_mint_sig(w3, addr: str):
    try:
        code = w3.eth.get_code(addr)
        return _SIG_MINT.encode() in code.hex().encode()
    except Exception:
        return None

# --- D1 public overrides ------------------------------------------------------

def inspect_token(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    chain = _d1_canon_chain(chain_short)
    token = (token_address or "").strip()
    pair  = (pair_address or "").strip() if pair_address else ""
    if not (isinstance(token, str) and token.startswith("0x") and len(token)==42):
        return {"ok": False, "chain": chain, "token": token_address, "error": "invalid token address"}

    # cache
    ck = f"oc:{chain}:{token}"
    cached = cache_get(ck)
    if cached:
        try:
            j = json.loads(cached); j["cacheHit"] = True; return j
        except Exception:
            pass

    out: Dict[str, Any] = {
        "ok": False,
        "chain": chain, "token": token, "pair": pair or None,
        "codePresent": False, "name": None, "symbol": None, "decimals": None, "totalSupply": None,
        "owner": None, "renounced": None, "paused": None,
        "proxy": None, "implementation": None, "hasMintSignature": None,
        "maxTx": None, "maxWallet": None,
        "errors": [],
    }

    if Web3 is None:
        out["errors"].append("web3-not-installed"); return out

    w3 = None
    for url in _d1_rpc_candidates_for_chain(chain):
        w3 = _d1_w3_for(url)
        if w3: break
    if not w3:
        out["errors"].append("no-rpc"); return out

    # Selectors
    DEC="0x313ce567"; NAME="0x06fdde03"; SYM="0x95d89b41"; SUP="0x18160ddd"; OWN="0x8da5cb5b"; PAU="0x5c975abb"
    MAXTX=["0xe386e5d0","0x4b750334"]; MAXW=["0x7e1d6f92","0x2e1a7d4d"]

    try: out["codePresent"] = _d1_get_code_present(w3, token)
    except Exception as e: out["errors"].append(f"code:{e}")
    try: out["decimals"] = _d1_u32(_d1_eth_call(w3, token, DEC))
    except Exception as e: out["errors"].append(f"decimals:{e}")
    try: out["name"] = _d1_str(_d1_eth_call(w3, token, NAME))
    except Exception as e: out["errors"].append(f"name:{e}")
    try: out["symbol"] = _d1_str(_d1_eth_call(w3, token, SYM))
    except Exception as e: out["errors"].append(f"symbol:{e}")
    try: out["totalSupply"] = _d1_u32(_d1_eth_call(w3, token, SUP))
    except Exception as e: out["errors"].append(f"supply:{e}")

    try:
        owner = _d1_eth_call(w3, token, OWN)
        if owner and len(owner)>=32:
            addr = "0x" + owner[-20:].hex()
            out["owner"] = Web3.to_checksum_address(addr)
            out["renounced"] = (int(owner[-20:].hex(),16) == 0)
    except Exception as e: out["errors"].append(f"owner:{e}")

    try: out["paused"] = _d1_bool(_d1_eth_call(w3, token, PAU))
    except Exception as e: out["errors"].append(f"paused:{e}")

    try:
        impl = _d1_get_impl(w3, token)
        out["implementation"] = impl; out["proxy"] = bool(impl)
    except Exception as e: out["errors"].append(f"proxy:{e}")

    try: out["hasMintSignature"] = _d1_mint_sig(w3, token)
    except Exception as e: out["errors"].append(f"mintsig:{e}")

    try:
        for sel in MAXTX:
            v = _d1_u32(_d1_eth_call(w3, token, sel))
            if v: out["maxTx"]=v; break
    except Exception as e: out["errors"].append(f"maxTx:{e}")
    try:
        for sel in MAXW:
            v = _d1_u32(_d1_eth_call(w3, token, sel))
            if v: out["maxWallet"]=v; break
    except Exception as e: out["errors"].append(f"maxWallet:{e}")

    out["ok"] = bool(out.get("codePresent") or out.get("decimals") is not None or out.get("name") or out.get("symbol"))

    try: cache_set(ck, json.dumps(out, separators=(",",":")), int(os.getenv("ONCHAIN_CACHE_TTL_SEC","180")))
    except Exception: pass
    return out

def build_onchain_payload(chain_short: str, token_address: str, pair_address: Optional[str] = None) -> Dict[str, Any]:
    try:
        return inspect_token(chain_short, token_address, pair_address)
    except Exception as e:
        return {"ok": False, "chain": _d1_canon_chain(chain_short), "token": token_address, "error": str(e)}
# ======================= END OF D1 COMPAT PATCH ===============================
