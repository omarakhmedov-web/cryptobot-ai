
import os, time, json
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlencode
import requests

from common import explorer_providers

_USER_AGENT = os.getenv("HTTP_UA", "MetridexBot/1.0 (+https://metridex.com)")
_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
_RETRY = 1

ETHERSCAN_BASES = {
    # minimal set used by fallback; extend as needed
    "ftmscan": "https://api.ftmscan.com/api",
    "snowtrace": "https://api.snowtrace.io/api",
    "arbiscan": "https://api.arbiscan.io/api",
    "basescan": "https://api.basescan.org/api",
    "etherscan": "https://api.etherscan.io/api",
    "bscscan": "https://api.bscscan.com/api",
    "polygonscan": "https://api.polygonscan.com/api",
    "optimistic-etherscan": "https://api-optimistic.etherscan.io/api",
}

def _http_get(url: str, params: Dict[str, Any]) -> Tuple[int, Any]:
    headers = {"User-Agent": _USER_AGENT}
    for i in range(_RETRY + 1):
        try:
            r = requests.get(url, params=params, timeout=_TIMEOUT, headers=headers)
            ct = r.headers.get("content-type","")
            if "json" in ct:
                return r.status_code, r.json()
            return r.status_code, r.text
        except Exception as e:
            err = str(e)
            if i >= _RETRY:
                return 599, {"error": err}
            time.sleep(0.2 * (i+1))
    return 599, {"error": "unknown"}

def _etherscan_like(provider: Dict[str, Any], params: Dict[str, Any]) -> Tuple[int, Any]:
    name = (provider.get("name") or "").lower()
    base = provider.get("base") or ETHERSCAN_BASES.get(name)
    if not base:
        return 0, {"error": f"no base for {name}"}
    apikey_env = provider.get("api_key_env")
    if apikey_env:
        key = os.getenv(apikey_env, "").strip()
        if key:
            params = dict(params)
            params["apikey"] = key
    return _http_get(base, params)

def call(chain: str, module: str, action: str, **params) -> Dict[str, Any]:
    """Generic explorer call with automatic fallbacks.
    Supports Etherscan-like providers and Blockscout (Etherscan-compatible API).
    Returns dict: {'ok': bool, 'provider': name, 'status_code': int, 'data': Any}
    """
    providers = explorer_providers(chain) or []
    if not providers:
        return {'ok': False, 'provider': None, 'status_code': 0, 'data': {'error':'no providers'}}

    q = dict(params)
    q["module"] = module
    q["action"] = action

    # Try in order
    last = None
    for pr in providers:
        name = (pr.get("name") or "").lower()
        compat = (pr.get("compat") or "etherscan").lower()
        if compat in ("etherscan","blockscout"):
            code, data = _etherscan_like(pr, q)
        else:
            # skip unknown contract for now
            code, data = 0, {"error": f"compat {compat} not supported"}
        last = (name, code, data)
        # Success heuristics
        ok = False
        if isinstance(data, dict) and "status" in data and str(data.get("status")) in ("1","0"):
            # Many Etherscan endpoints return status '1' for ok, '0' for not found, treat 0 as ok-ish
            ok = True
        elif code == 200:
            ok = True
        if ok:
            return {'ok': True, 'provider': name, 'status_code': code, 'data': data}
    # If reached here, all failed
    if last:
        return {'ok': False, 'provider': last[0], 'status_code': last[1], 'data': last[2]}
    return {'ok': False, 'provider': None, 'status_code': 0, 'data': {'error':'no attempts'}}

def get_abi(chain: str, address: str) -> Dict[str, Any]:
    res = call(chain, "contract", "getabi", address=address)
    if not res.get("ok"):
        return res
    data = res["data"]
    if isinstance(data, dict) and "result" in data:
        res["abi"] = data["result"]
    return res

def get_source(chain: str, address: str) -> Dict[str, Any]:
    res = call(chain, "contract", "getsourcecode", address=address)
    if not res.get("ok"):
        return res
    data = res["data"]
    if isinstance(data, dict) and "result" in data:
        res["source"] = data["result"]
    return res
