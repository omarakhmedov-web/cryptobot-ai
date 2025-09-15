"""
polydebug_rpc.py — Safe diagnostics for Polygon RPC in Metridex QuickScan server.

Usage (add near the top of server.py, after imports):
    try:
        from polydebug_rpc import init_polydebug
        init_polydebug()  # runs only if POLY_DEBUG=1
    except Exception as e:
        print(f"[POLYDEBUG] init skipped: {e}")

What it does (when POLY_DEBUG=1):
  • Resolves effective Polygon RPC URL using precedence:
        RPC_URLS["polygon"] > POLYGON_RPC_URL > MATIC_RPC_URL
  • Logs a redacted form of the URL (keeps keys secret).
  • Checks chainId (expects 0x89 for Polygon PoS).
  • Calls eth_getCode on a known contract (QUICK token) and logs result length.
  • If anything fails, it logs the reason and never raises.

Env flags:
  • POLY_DEBUG=1         — enable diagnostics (else it no-ops).
  • POLY_RPC_FALLBACK=1  — if no RPC found, fallback to https://polygon-rpc.com/

This module is read-only: it does not modify global behavior or your on-chain logic.
"""

import json
import os
import time
import hashlib
from typing import Optional
import requests

QUICK_POLYGON = "0x831753DD7087CaC61aB5644b308642cc1c33Dc13"  # known contract address
POLYGON_CHAIN_ID_HEX = "0x89"  # 137
DEFAULT_PUBLIC_RPC = "https://polygon-rpc.com"

def _redact_url(url: str) -> str:
    if not url:
        return "(empty)"
    # Redact API keys / tokens if present after '/v2/...' or as query params
    # Keep domain and first/last 4 chars of any token-like segment
    parts = url.split("/")
    redacted = []
    for p in parts:
        if len(p) > 20 and any(c.isalpha() for c in p):  # likely a token
            redacted.append(p[:4] + "…" + p[-4:])
        else:
            redacted.append(p)
    return "/".join(redacted)

def _h(s: str) -> str:
    try:
        return hashlib.sha1(s.encode()).hexdigest()[:8]
    except Exception:
        return "????????"

def _load_rpc_urls_json() -> dict:
    raw = os.environ.get("RPC_URLS", "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception as e:
        print(f"[POLYDEBUG] RPC_URLS JSON parse error: {e}")
        return {}

def _resolve_polygon_rpc_url() -> Optional[str]:
    # Precedence: RPC_URLS['polygon'] > POLYGON_RPC_URL > MATIC_RPC_URL > optional fallback
    rpc_urls = _load_rpc_urls_json()
    url = rpc_urls.get("polygon") or os.environ.get("POLYGON_RPC_URL") or os.environ.get("MATIC_RPC_URL")
    if (not url) and os.environ.get("POLY_RPC_FALLBACK") == "1":
        url = DEFAULT_PUBLIC_RPC
    return (url or "").strip()

def _rpc_call(url: str, method: str, params: list, timeout: float = 4.0) -> dict:
    try:
        r = requests.post(
            url,
            json={"jsonrpc": "2.0", "id": int(time.time()), "method": method, "params": params},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def init_polydebug() -> None:
    if os.environ.get("POLY_DEBUG") != "1":
        return  # no-op by default

    url = _resolve_polygon_rpc_url()
    red = _redact_url(url)
    print(f"[POLYDEBUG] Polygon RPC (effective): {red} | hash={_h(url)}")

    if not url:
        print("[POLYDEBUG] No Polygon RPC URL resolved. Set RPC_URLS['polygon'] or POLYGON_RPC_URL.")
        return

    # 1) Chain Id
    chain = _rpc_call(url, "eth_chainId", [])
    if "result" in chain:
        print(f"[POLYDEBUG] eth_chainId -> {chain['result']} (expect {POLYGON_CHAIN_ID_HEX})")
        if chain["result"] != POLYGON_CHAIN_ID_HEX:
            print("[POLYDEBUG] WARNING: chainId mismatch — are you hitting non-Polygon endpoint?")
    else:
        print(f"[POLYDEBUG] eth_chainId error: {chain.get('error')}")

    # 2) getCode for known contract on Polygon
    code = _rpc_call(url, "eth_getCode", [QUICK_POLYGON, "latest"])
    if "result" in code:
        res = code["result"]
        if isinstance(res, str):
            l = len(res)
            print(f"[POLYDEBUG] eth_getCode(len) for QUICK: {l} ("0x" => no bytecode)")
            if res == "0x":
                print("[POLYDEBUG] Bytecode absent — either EOA (not a contract) or wrong network/endpoint.")
        else:
            print(f"[POLYDEBUG] eth_getCode unexpected type: {type(res)}")
    else:
        print(f"[POLYDEBUG] eth_getCode error: {code.get('error')}")

    # 3) Optional gas price ping (sanity check, does not affect behavior)
    gp = _rpc_call(url, "eth_gasPrice", [])
    if "result" in gp:
        print(f"[POLYDEBUG] eth_gasPrice -> {gp['result']}")
    else:
        print(f"[POLYDEBUG] eth_gasPrice error: {gp.get('error')}")
