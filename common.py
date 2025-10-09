import os
import re
import time
import json
import logging
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any

def getenv_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")

def getenv_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")

def classify_input(text: str) -> Tuple[str, str]:
    """
    Returns (kind, value): kind in {"address","tx","url","unknown"}
    """
    t = (text or "").strip()
    if ADDR_RE.match(t):
        return ("address", t)
    if TX_RE.match(t):
        return ("tx", t)
    if t.startswith("http://") or t.startswith("https://"):
        return ("url", t)
    return ("unknown", t)

def chain_from_hint(addr_or_chain: str) -> str:
    # naive default
    return "ethereum"

def short(s: str, n: int = 120) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n-1] + "…"

def now_ts() -> int:
    return int(time.time())

def dt_utc_iso(ts: Optional[int] = None) -> str:
    if ts is None:
        ts = now_ts()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

def parse_iso8601(s: str) -> Optional[int]:
    try:
        from datetime import datetime, timezone
        return int(datetime.fromisoformat(s.replace("Z","+00:00")).timestamp())
    except Exception:
        return None

def build_scan_link(chain: str, address: str) -> str:
    chain = (chain or "ethereum").lower()
    if chain in ("eth","ethereum","mainnet"):
        return f"https://etherscan.io/token/{address}"
    if chain in ("bsc","bscscan","bnb"):
        return f"https://bscscan.com/token/{address}"
    return f"https://etherscan.io/address/{address}"

def normalize_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "https://" + url
