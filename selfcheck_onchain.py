
# selfcheck_onchain.py — offline smoke test for On-chain modules (no network)
import sys, types, json
from pprint import pprint

# Monkeypatch requests.post used by onchain_inspector
class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload
    def raise_for_status(self): return None
    def json(self): return self._payload

def _fake_post(url, json=None, timeout=12, headers=None):
    # Return zeros for everything; codePresent = "0x"
    method = (json or {}).get("method")
    if method == "eth_getCode":
        return _FakeResponse({"jsonrpc":"2.0","id":1,"result":"0x"})
    return _FakeResponse({"jsonrpc":"2.0","id":1,"result":"0x"})

import requests
requests.post = _fake_post  # type: ignore

# Monkeypatch urllib in onchain_v2
from urllib.error import URLError, HTTPError

def _fake_urlopen(req, timeout=6.0):
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return b'{"jsonrpc":"2.0","id":1,"result":"0x"}'
    return R()

import builtins
# Ensure our package path
sys.path.insert(0, ".")

import onchain_inspector as oi
import onchain_v2 as oc2
import renderers_onchain_v2 as r2

# Replace urlopen used inside oc2
oc2.urlopen = _fake_urlopen  # type: ignore

# Run two sample addresses
tests = [
    ("bsc", "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"),
    ("eth", "0x9fc53c75046900d1f58209f50f534852ae9f912a"),
]

out = {}
for chain, addr in tests:
    info = oi.inspect_token(chain, addr)
    out[(chain, addr)] = info

print("INSPECT_TOKEN_RESULTS:")
for k,v in out.items():
    print(k, "=>", {"ok": v.get("ok"), "codePresent": v.get("codePresent"),
                     "name": v.get("name"), "symbol": v.get("symbol"),
                     "decimals": v.get("decimals")})

print("\nRENDERERS_V2_RESULTS:")
for chain, addr in tests:
    text = r2.render_onchain_v2(chain, addr, info={"codePresent": False, "name": None, "symbol": None, "decimals": None, "totalDisplay": None, "owner": None, "renounced": False, "paused": None, "upgradeable": None})
    print(f"--- {chain} {addr[:10]}... ---")
    print(text)
