#!/usr/bin/env python3
import sys, re
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("Usage: python apply_rdap_patch.py <path/to/server.py>")
        sys.exit(1)
    p = Path(sys.argv[1])
    if not p.exists():
        print("File not found:", p)
        sys.exit(1)
    src = p.read_text(encoding="utf-8", errors="ignore")

    # Insert import alias after first import block
    lines = src.splitlines()
    insert_at = 0
    for i, ln in enumerate(lines[:300]):
        s = ln.strip()
        if s.startswith("from ") or s.startswith("import "):
            insert_at = i + 1
        elif s and not (s.startswith("#") or s.startswith("from ") or s.startswith("import ")):
            break
    inject = "from metri_domain_rdap import _rdap as __rdap_impl  # injected"
    if inject not in src:
        lines.insert(insert_at, inject)
    new_src = "\n".join(lines)

    # Replace def _rdap(...) with delegating wrapper
    pat = re.compile(r"(?ms)^def\s+_rdap\s*\(\s*domain\s*(:\s*str)?\s*\)\s*:\s*.*?(?=^\S)", re.M)
    wrapper = "def _rdap(domain: str):\n    return __rdap_impl(domain)\n"
    if pat.search(new_src):
        new_src = pat.sub(wrapper + "\n", new_src, count=1)
    else:
        new_src = new_src.rstrip() + "\n\n" + wrapper

    # Save backup and patched file
    backup = p.with_suffix(".backup.py")
    backup.write_text(src, encoding="utf-8")
    out = p.with_name(p.stem + "_patched.py")
    out.write_text(new_src, encoding="utf-8")
    print("Patched:", out)

if __name__ == "__main__":
    main()
