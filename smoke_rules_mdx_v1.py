
"""Metridex smoke test for renderers (age & Δ24h rules, registrar alias, RDAP placeholder).
Run:  python smoke_rules_mdx_v1.py
"""
import importlib, sys

def _fail(msg):
    print("FAIL:", msg); sys.exit(1)

# Import renderers.py from the same directory
R = importlib.import_module("renderers")

def test_registrar_alias_and_rdap():
    if not hasattr(R, "_fmt_registrar"):
        _fail("missing _fmt_registrar alias")
    out = R._fmt_registrar("namecheap, inc")
    if "Namecheap" not in out or "Inc." not in out:
        _fail(f"registrar format unexpected: {out}")
    if not getattr(R, "_RDAP_COUNTRY_PLACEHOLDER", False):
        _fail("RDAP country placeholder default is OFF (expected ON)")

def test_why_normalization():
    class V: pass
    v = V()
    v.reasons = [
        "Healthy liquidity ($45,000,000)",
        "Moderate 24h move (-5%)",
        "Established >1 week (~916.1d)",
    ]
    market = {
        "liq": 45_000_000,
        "vol24h": 1_400_000,
        "priceChanges": {"h24": -4.0},
        "ageDays": 916.1,
        "pair": "TEST/WETH",
        "asof": "2025-10-16 20:10 UTC",
    }
    out = R.render_why(v, market, "en")
    if "Contained daily move (|Δ24h| ≈ 5%)" not in out:
        _fail("Why? delta normalization failed")
    if ">2 years" not in out:
        _fail("Why? age bucket normalization failed")

def test_whypp_buckets():
    market = {"liq": 45_000_000, "vol24h": 1_300_000, "priceChanges": {"h24": -4.0}, "ageDays": 916.1}
    out = R.render_whypp(None, market, "en")
    if "Stable day (|Δ24h| ≤ 6%)" not in out:
        _fail("Why++ stable day positive missing for |Δ24h|=4%")
    if "volatility" in out.lower():
        _fail("Why++ should not include volatility risk for |Δ24h|=4%")
    market["priceChanges"]["h24"] = 15.0
    out = R.render_whypp(None, market, "en")
    if "Elevated daily volatility (|Δ24h| ≈ 15%)" not in out:
        _fail("Why++ elevated volatility risk missing for |Δ24h|=15%")
    market["priceChanges"]["h24"] = -30.0
    out = R.render_whypp(None, market, "en")
    if "High daily volatility (|Δ24h| ≈ 30%)" not in out:
        _fail("Why++ high volatility risk missing for |Δ24h|=30%")

def main():
    test_registrar_alias_and_rdap()
    test_why_normalization()
    test_whypp_buckets()
    print("OK: smoke tests passed")

if __name__ == "__main__":
    main()
