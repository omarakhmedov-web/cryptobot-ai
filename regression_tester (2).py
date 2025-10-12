
import re, os, json, sys, datetime as dt
from pathlib import Path

ROOT = Path(os.environ.get("TEST_ROOT", "/mnt/data"))
CONFIG = ROOT / "tests_config.json"

def read(p):
    return Path(p).read_text(encoding="utf-8", errors="ignore")

def find(pattern, text):
    m = re.search(pattern, text, re.I|re.S)
    return m.group(0) if m else None

def domain_ok(href, domain):
    if not href or not domain: 
        return domain is None  # both None → OK for Unknown case
    return (domain in href)

def check_case(case):
    name = case["name"]
    fn = ROOT / case["file"]
    exp = case["expected"]
    res = {"name": name, "file": str(fn), "checks": []}

    if not fn.exists():
        res["checks"].append(("FILE_EXISTS", False, f"missing {fn.name}"))
        return res
    res["checks"].append(("FILE_EXISTS", True, fn.name))

    html = read(fn)

    # Score in header
    score_txt = find(r"Score:\s*([0-9]+)", html)
    score_val = None
    if score_txt:
        m = re.search(r"Score:\s*([0-9]+)", score_txt)
        if m: score_val = m.group(1)
    res["checks"].append(("SCORE", score_val == exp["score"], f"{score_val} == {exp['score']}"))

    # Chain label
    chain_txt = find(r"Chain:\s*([A-Za-z0-9 /-]+)", html) or "Chain: —"
    chain_val = chain_txt.split("Chain:")[-1].strip() if "Chain:" in chain_txt else "—"
    res["checks"].append(("CHAIN", chain_val == exp["chain"], f"{chain_val} == {exp['chain']}"))

    # Pair
    pair_txt = find(r"Symbol:\s*([^\n<]+)", html) or ""
    pair_val = pair_txt.split("Symbol:")[-1].strip() if "Symbol:" in pair_txt else ""
    res["checks"].append(("PAIR", (exp["pair_contains"] in pair_val), f"{pair_val} contains {exp['pair_contains']}"))

    # Age line (presence & non-empty)
    age_line = find(r"Age:\s*([^\n<]+)", html)
    age_ok = True
    if exp["age_required"]:
        age_ok = bool(age_line) and (age_line.strip() not in ("Age: —","Age:—","—"))
    res["checks"].append(("AGE", age_ok, f"{age_line or 'Age: —'}"))

    # Links
    dex_link = find(r"https?://[^\s\"']+quickswap\.exchange[^\s\"']*", html) or \
               find(r"https?://[^\s\"']+pancakeswap\.finance[^\s\"']*", html) or \
               find(r"https?://[^\s\"']+app\.uniswap\.org[^\s\"']*", html)
    scan_link = find(r"https?://[^\s\"']+etherscan\.io[^\s\"']*", html) or \
                find(r"https?://[^\s\"']+bscscan\.com[^\s\"']*", html) or \
                find(r"https?://[^\s\"']+polygonscan\.com[^\s\"']*", html)
    ds_link = find(r"https?://[^\s\"']*dexscreener\.com[^\s\"']*", html)

    res["checks"].append(("DEX_LINK", domain_ok(dex_link, exp["dex_domain"]), f"{dex_link or '—'} ~ {exp['dex_domain']}"))
    res["checks"].append(("SCAN_LINK", domain_ok(scan_link, exp["scan_domain"]), f"{scan_link or '—'} ~ {exp['scan_domain']}"))
    res["checks"].append(("DS_LINK", domain_ok(ds_link, exp["ds_domain"]), f"{ds_link or '—'} ~ {exp['ds_domain']}"))

    # Snapshot lines present
    for label in ["Price:", "FDV:", "MC:", "Liquidity:", "24h Volume:", "Δ5m", "Δ1h", "Δ24h", "As of:"]:
        ok = (label in html)
        res["checks"].append((f"SNAPSHOT_{label.replace(' ','_').replace(':','')}", ok, "present" if ok else "missing"))

    return res

def main():
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    out_lines = []
    total_ok = 0
    total = 0
    for case in cfg["cases"]:
        r = check_case(case)
        out_lines.append(f"=== {r['name']} ===")
        for (k, ok, note) in r["checks"]:
            total += 1
            total_ok += int(bool(ok))
            out_lines.append(f"[{'OK' if ok else 'FAIL'}] {k} — {note}")
        out_lines.append("")

    summary = f"Summary: {total_ok}/{total} checks passed"
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = ROOT / f"Regression_Report_{ts}.txt"
    report_path.write_text("\n".join(out_lines + [summary]), encoding="utf-8")
    print(summary)
    print(report_path)
    # Exit non‑zero if not all checks passed (for CI)
    import sys
    sys.exit(0 if total_ok == total else 1)

if __name__ == "__main__":
    main()
