#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metridex Self-Check
Run on your server (Render) to quickly diagnose deployment & connectivity issues.

Usage:
  python selfcheck.py [--token 0x...] [--probe-webhook 0|1]

Environment (read-only):
  BOT_WEBHOOK_SECRET, BOT_TOKEN (masked), ENABLED_NETWORKS,
  DEXSCREENER_PROXY_BASE (or DS_PROXY_BASE),
  *_RPC_URL_PRIMARY (ETH/BSC/POLYGON/BASE/ARB/OP/AVAX/FTM),
  SELFTEST_CHAT_ID (optional, used for --probe-webhook=1)
"""

from __future__ import annotations
import os, sys, re, json, time
import pathlib
from typing import Optional, Tuple, Dict, Any

# ---- HTTP helpers -----------------------------------------------------------

def _mask(s: Optional[str], keep=4) -> str:
    if not s: return ""
    if len(s) <= keep: return "*" * len(s)
    return s[:keep] + "…" + "*" * max(0, len(s)-keep)

def _ua() -> str:
    return os.getenv("HTTP_UA", "MetridexSelfcheck/1.0")

def _http_get_json(url: str, timeout: int = 10, headers: Optional[dict] = None) -> Tuple[int, Any, str]:
    headers = {**({"User-Agent": _ua(), "Accept": "application/json"}), **(headers or {})}
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers=headers)
        ctype = r.headers.get("content-type","")
        text = r.text
        try:
            return r.status_code, r.json(), ctype
        except Exception:
            return r.status_code, text, ctype
    except Exception as e:
        return 599, {"error": str(e)}, ""

def _http_post_json(url: str, payload: dict, timeout: int = 10, headers: Optional[dict] = None) -> Tuple[int, Any, str]:
    headers = {**({"User-Agent": _ua(), "Accept": "application/json"}), **(headers or {})}
    try:
        import requests
        r = requests.post(url, json=payload, timeout=timeout, headers=headers)
        ctype = r.headers.get("content-type","")
        text = r.text
        try:
            return r.status_code, r.json(), ctype
        except Exception:
            return r.status_code, text, ctype
    except Exception as e:
        return 599, {"error": str(e)}, ""

def _rpc_call(rpc: str, method: str, params: list, timeout: int = 8) -> Dict[str, Any]:
    try:
        import requests
        r = requests.post(rpc, json={"jsonrpc":"2.0","id":1,"method":method,"params":params}, timeout=timeout, headers={"User-Agent": _ua()})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ---- Coloring & printing ----------------------------------------------------
def c(s, col):
    colors = {"g":"\033[92m","y":"\033[93m","r":"\033[91m","b":"\033[94m","n":"\033[0m"}
    return colors.get(col,"")+str(s)+colors["n"]

def PASS(msg): print(c("✔ "+msg, "g"))
def WARN(msg): print(c("• "+msg, "y"))
def FAIL(msg): print(c("✘ "+msg, "r"))

# ---- File system checks -----------------------------------------------------
def find_repo_root() -> pathlib.Path:
    cwd = pathlib.Path.cwd()
    candidates = [cwd, cwd/"src", pathlib.Path("/opt/render/project/src")]
    for p in candidates:
        if (p/"server.py").exists():
            return p
    # fallback
    return cwd

def read_text_if(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def check_files(root: pathlib.Path) -> dict:
    print(c(f"\n[1/5] Files under: {root}", "b"))
    result = {"server": False, "buttons": False, "dex_client": False, "onchain": False, "onchain_handler": False, "fetch_market": False}
    # server.py
    sp = root / "server.py"
    if sp.exists():
        result["server"] = True
        txt = read_text_if(sp)
        if 'elif action == "ONCHAIN"' in txt:
            result["onchain_handler"] = True
            PASS("server.py: ONCHAIN handler found")
        else:
            FAIL("server.py: ONCHAIN handler NOT found")
    else:
        FAIL("server.py not found")

    # buttons
    bp = root / "buttons.py"
    if not bp.exists():
        # try alternative naming
        alt = [p for p in root.glob("buttons*.py")]
        bp = alt[0] if alt else bp
    if bp.exists():
        result["buttons"] = True
        txt = read_text_if(bp)
        if "ONCHAIN" in txt:
            PASS(f"{bp.name}: ONCHAIN button/callback present")
        else:
            WARN(f"{bp.name}: ONCHAIN label not detected (check keyboard build)")
    else:
        FAIL("buttons.py not found")

    # dex_client
    dp = root / "dex_client.py"
    if dp.exists():
        result["dex_client"] = True
        txt = read_text_if(dp)
        if "def fetch_market(" in txt:
            result["fetch_market"] = True
            PASS("dex_client.py: fetch_market() found")
        else:
            FAIL("dex_client.py: fetch_market() NOT found")
    else:
        FAIL("dex_client.py not found")

    # onchain
    op = root / "onchain_inspector.py"
    if op.exists():
        result["onchain"] = True
        PASS("onchain_inspector.py found")
    else:
        WARN("onchain_inspector.py not found (ONCHAIN will be disabled)")

    return result

# ---- Environment checks -----------------------------------------------------
def check_env() -> dict:
    print(c("\n[2/5] Environment", "b"))
    env = {
        "BOT_WEBHOOK_SECRET": os.getenv("BOT_WEBHOOK_SECRET",""),
        "BOT_TOKEN": os.getenv("BOT_TOKEN",""),
        "ENABLED_NETWORKS": os.getenv("ENABLED_NETWORKS",""),
        "DEXSCREENER_PROXY_BASE": os.getenv("DEXSCREENER_PROXY_BASE") or os.getenv("DS_PROXY_BASE") or "",
    }
    # RPCs
    for k in ["ETH","BSC","POLYGON","BASE","ARB","OP","AVAX","FTM"]:
        env[f"{k}_RPC_URL_PRIMARY"] = os.getenv(f"{k}_RPC_URL_PRIMARY","")
    print(f"BOT_WEBHOOK_SECRET = {_mask(env['BOT_WEBHOOK_SECRET'])}")
    print(f"BOT_TOKEN          = {_mask(env['BOT_TOKEN'])}")
    print(f"ENABLED_NETWORKS   = {env['ENABLED_NETWORKS'] or '(default)'}")
    print(f"DEXSCREENER_PROXY  = {env['DEXSCREENER_PROXY_BASE'] or '(not set)'}")
    ok_rpc = False
    for k,v in env.items():
        if k.endswith("_RPC_URL_PRIMARY") and v:
            ok_rpc = True
            print(f"{k:22s} = {_mask(v, keep=12)}")
    if not ok_rpc:
        WARN("No *_RPC_URL_PRIMARY set — ONCHAIN may be limited")
    return env

# ---- DexScreener checks -----------------------------------------------------
DEFAULT_TOKEN = "0x6982508145454Ce325dDbE47a25d4ec3d2311933"  # PEPE

def check_dexscreener(env: dict, token: str) -> dict:
    print(c("\n[3/5] DexScreener connectivity", "b"))
    res = {"direct": None, "proxy": None}
    # Direct
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token}"
    code, body, ctype = _http_get_json(url, timeout=10)
    if code == 200 and isinstance(body, dict) and body.get("pairs"):
        PASS(f"Direct OK: {len(body.get('pairs',[]))} pairs returned")
        res["direct"] = True
    else:
        WARN(f"Direct FAIL (status={code}, type={ctype}); trying proxy…")
        res["direct"] = False

    # Proxy
    proxy = env.get("DEXSCREENER_PROXY_BASE","").strip("/")
    if proxy:
        purl = f"{proxy}/latest/dex/tokens/{token}"
        code2, body2, ctype2 = _http_get_json(purl, timeout=12)
        if code2 == 200 and isinstance(body2, dict) and body2.get("pairs"):
            PASS(f"Proxy OK via {proxy}: {len(body2.get('pairs',[]))} pairs")
            res["proxy"] = True
        else:
            FAIL(f"Proxy FAIL via {proxy} (status={code2}, type={ctype2})")
            res["proxy"] = False
    else:
        WARN("Proxy not set; skip proxy test")
    return res

# ---- RPC checks -------------------------------------------------------------
CHAIN_ENV = {
    "eth":"ETH_RPC_URL_PRIMARY",
    "bsc":"BSC_RPC_URL_PRIMARY",
    "polygon":"POLYGON_RPC_URL_PRIMARY",
    "base":"BASE_RPC_URL_PRIMARY",
    "arb":"ARB_RPC_URL_PRIMARY",
    "op":"OP_RPC_URL_PRIMARY",
    "avax":"AVAX_RPC_URL_PRIMARY",
    "ftm":"FTM_RPC_URL_PRIMARY",
}

def check_rpc(env: dict) -> dict:
    print(c("\n[4/5] RPC connectivity", "b"))
    enabled = (env.get("ENABLED_NETWORKS") or "eth,bsc,polygon,base,arb,op,avax,ftm").split(",")
    enabled = [x.strip() for x in enabled if x.strip()]
    out = {}
    for short in enabled:
        key = CHAIN_ENV.get(short)
        if not key: 
            WARN(f"{short}: no mapping for *_RPC_URL_PRIMARY; skip")
            continue
        rpc = env.get(key)
        if not rpc:
            WARN(f"{short}: {key} is not set")
            continue
        j1 = _rpc_call(rpc, "eth_chainId", [])
        j2 = _rpc_call(rpc, "eth_blockNumber", [])
        ok = ("result" in j1) and ("result" in j2)
        if ok:
            PASS(f"{short}: chainId={j1['result']} block={int(j2['result'],16)}")
        else:
            FAIL(f"{short}: RPC error: {j1.get('error') or j2.get('error')}")
        out[short] = ok
    return out

# ---- Webhook probe (optional) ----------------------------------------------
def check_webhook(env: dict, probe: bool) -> dict:
    print(c("\n[5/5] Webhook route", "b"))
    secret = env.get("BOT_WEBHOOK_SECRET","")
    if not secret:
        WARN("BOT_WEBHOOK_SECRET is empty — cannot probe")
        return {"probed": False}
    url = f"/webhook/{secret}"
    # Best effort: Render often mounts at root domain for app; we try absolute path from ENV PUBLIC_URL else skip
    base = os.getenv("PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL") or ""
    if not base:
        WARN("PUBLIC_URL/RENDER_EXTERNAL_URL not set — probing relative path only (skip network call)")
        return {"probed": False}
    full = (base.rstrip('/') + url)
    if not probe:
        print(f"Webhook endpoint looks like: {full} (set --probe-webhook=1 to test)");
        return {"probed": False, "url": full}
    chat_id = os.getenv("SELFTEST_CHAT_ID")
    if not chat_id:
        WARN("SELFTEST_CHAT_ID not set; using 0")
        chat_id = "0"
    payload = {
        "callback_query": {
            "id": "selfcheck",
            "data": f"v1:WHY:0:{chat_id}",
            "message": {"message_id": 1, "chat": {"id": int(chat_id)}}
        }
    }
    code, body, ctype = _http_post_json(full, payload, timeout=8)
    if code == 200:
        PASS(f"Webhook responded 200 ({ctype})")
        return {"probed": True, "status": code}
    else:
        FAIL(f"Webhook responded {code} ({ctype}) -> {body}")
        return {"probed": True, "status": code, "body": body}

# ---- Main -------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=DEFAULT_TOKEN, help="ERC-20 token address for DS test")
    ap.add_argument("--probe-webhook", default="0", choices=["0","1"], help="POST test payload into /webhook/<secret> (requires PUBLIC_URL and SELFTEST_CHAT_ID)")
    args = ap.parse_args()

    root = find_repo_root()
    files = check_files(root)
    env = check_env()
    ds = check_dexscreener(env, args.token)
    rpc = check_rpc(env)
    wh = check_webhook(env, probe=(args.probe_webhook == "1"))

    print("\n" + "="*70)
    print("SUMMARY:")
    print(f"server.py            : {'OK' if files.get('server') else 'MISSING'} / ONCHAIN handler: {files.get('onchain_handler')}")
    print(f"buttons.py           : {'OK' if files.get('buttons') else 'MISSING'}")
    print(f"dex_client.py        : {'OK' if files.get('dex_client') else 'MISSING'} / fetch_market(): {files.get('fetch_market')}")
    print(f"onchain_inspector.py : {'OK' if files.get('onchain') else 'MISSING'}")
    print(f"DexScreener direct   : {ds.get('direct')} ; proxy: {ds.get('proxy')}")
    print(f"RPC reachable        : {', '.join([k for k,v in rpc.items() if v]) or 'none'}")
    print(f"Webhook probed       : {wh.get('probed')}")

    # Final suggestion
    problems = []
    if not files.get('onchain_handler'): problems.append("server.py lacks ONCHAIN handler")
    if not files.get('fetch_market'):    problems.append("dex_client.py lacks fetch_market()")
    if ds.get('direct') is False and ds.get('proxy') is not True:
        problems.append("DexScreener blocked — configure DEXSCREENER_PROXY_BASE")
    if not any(rpc.values()): problems.append("No RPC reachable — ONCHAIN will be empty")

    if problems:
        print("\n" + c("NEXT STEPS:", "b"))
        for i, p in enumerate(problems, start=1):
            print(f"{i}. {p}")
    else:
        print("\n" + c("All core checks passed. If Telegram still shows dashes, it's likely a render-time env mismatch.", "g"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")