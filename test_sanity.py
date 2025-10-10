import os, time
from types import SimpleNamespace

# Render quick should be stable and include 'as of' and sources line
def test_render_quick_skeleton():
    os.environ['TWO_SOURCE_RULE'] = '1'
    # Lazy import to pick env
    import importlib
    r = importlib.import_module('renderers (4)'.replace(' ', '_'))
    market = {
        "pairSymbol": "PEPE/WETH",
        "chain": "ethereum",
        "price": 0.00001,
        "fdv": 3_970_000_000,
        "mc": 3_970_000_000,
        "liq": 58_440_000,
        "vol24h": 1_420_000,
        "priceChanges": {"h24": -0.39, "h1": 0.0, "m5": 0.0},
        "ageDays": 540,
        "source": "DexScreener",
        "sources": ["DexScreener","Explorer"],
        "asof": "2099-01-01 00:00 UTC"
    }
    verdict = SimpleNamespace(score=72, level="LOW", reasons=["LP locked", "Verified contract", "No mint"])
    txt = r.render_quick(verdict, market, {}, "en")
    assert "as of 2099-01-01 00:00 UTC" in txt
    assert "Sources:" in txt or "Source:" in txt
    assert "Metridex QuickScan" in txt

def test_common_helpers():
    import importlib
    c = importlib.import_module('common (2)'.replace(' ', '_'))
    assert isinstance(c.enabled_networks(), list)
    assert c.two_source_required() in (True, False)
    assert c.normalize_url("example.com").startswith("https://")
