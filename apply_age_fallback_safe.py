
"""
apply_age_fallback_safe.py — injects optional age fallback into dex_client.py
Usage:
  python apply_age_fallback_safe.py /path/to/dex_client.py
"""
import sys, re
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python apply_age_fallback_safe.py /path/to/dex_client.py")
        sys.exit(2)
    p = Path(sys.argv[1])
    s = p.read_text(encoding="utf-8")

    # Optional import (no hard fail)
    if "_resolve_pair_age_days" not in s:
        s = re.sub(
            r"(^import[^\n]*\n(?:from[^\n]*\n|import[^\n]*\n)*)",
            r"\1try:\n    from age_fallback_safe import resolve_pair_age_days as _resolve_pair_age_days\nexcept Exception:\n    _resolve_pair_age_days = None\n",
            s, count=1, flags=re.M
        )

    # Helper
    if "_apply_age_fallback" not in s:
        helper = (
            "\n"
            "def _apply_age_fallback(m: dict) -> dict:\n"
            "    import os, time\n"
            "    try:\n"
            "        if not isinstance(m, dict) or not m:\n"
            "            return m\n"
            "        if str(os.getenv(\"AGE_FALLBACK_ENABLED\",\"1\")).lower() not in (\"1\",\"true\",\"yes\"):\n"
            "            return m\n"
            "        if not m.get(\"ageDays\"):\n"
            "            ch = (m.get(\"chain\") or \"\").lower()\n"
            "            pair = m.get(\"pairAddress\") or m.get(\"pair\") or \"\"\n"
            "            if (_resolve_pair_age_days\n"
            "                and ch in (\"bsc\",\"ethereum\",\"eth\",\"polygon\",\"matic\",\"base\",\"arbitrum\",\"arb\",\"optimism\",\"op\",\"avalanche\",\"avax\",\"fantom\",\"ftm\")\n"
            "                and isinstance(pair, str) and pair.startswith(\"0x\") and len(pair)==42):\n"
            "                age = _resolve_pair_age_days(ch, pair)\n"
            "                if age is not None:\n"
            "                    m[\"ageDays\"] = float(age)\n"
            "                    m[\"asof\"] = int(time.time()*1000)\n"
            "    except Exception:\n"
            "        pass\n"
            "    return m\n"
        )
        if "# ===== DexScreener" in s:
            s = s.replace("# ===== DexScreener", helper + "\n# ===== DexScreener")
        else:
            s = s + helper

    # Inject helper usage in success paths
    s = re.sub(
        r"(m\s*=\s*_normalize_market\(\s*best\s*\)\s*;\s*m\[\s*[\"']ok[\"']\s*\]\s*=\s*True\s*)(\n\s*return\s*m)",
        r"\1\n    m = _apply_age_fallback(m)\2",
        s
    )

    p.write_text(s, encoding="utf-8")
    print("Patched:", p)

if __name__ == "__main__":
    main()
