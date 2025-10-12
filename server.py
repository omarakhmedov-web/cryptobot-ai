# -*- coding: utf-8 -*-
"""
Usage:
    python server_patch_regex.py /path/to/server.py

What it does:
  1) In LP callback, forces reply_markup=None (no buttons)
  2) Simplifies _mk_copy_keyboard() to remove DEX/Scan in copy keyboard
  3) Replaces/creates _build_html_report() with robust dark+gold HTML
"""
import sys, re, io

HTML_FUNC = r"""def _build_html_report(bundle: dict) -> bytes:
    import datetime as _dt, html
    b = bundle or {}
    v = b.get("verdict") or {}
    m = b.get("market") or {}
    why = b.get("why") or ""
    whypp = b.get("whypp") or ""
    lp = b.get("lp") or ""
    links = b.get("links") or {}
    web = b.get("webintel") or {}
    def _s(x): 
        try: return str(x) if x is not None else "—"
        except Exception: return "—"
    def _fmt(n, p=""):
        try:
            if n is None: return "—"
            n = float(n)
            a = abs(n)
            if a >= 1_000_000_000: s = f"{n/1_000_000_000:.2f}B"
            elif a >= 1_000_000: s = f"{n/1_000_000:.2f}M"
            elif a >= 1_000: s = f"{n/1_000:.2f}K"
            else: s = f"{n:.6f}" if a < 1 else f"{n:.2f}"
            return p + s
        except Exception:
            return "—"
    def _pct(x):
        try:
            if x is None: return "—"
            n = float(x); arrow = "▲" if n>0 else ("▼" if n<0 else "•")
            return f"{arrow} {n:+.2f}%"
        except Exception:
            return "—"
    def _time(ts):
        try:
            if ts is None: return "—"
            t = int(ts)
            if t < 10**12: t *= 1000
            return _dt.datetime.utcfromtimestamp(t/1000.0).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return "—"
    pair = _s(m.get("pairSymbol"))
    lvl = _s(v.get("level"))
    score = _s(v.get("score"))
    html_head = """<!doctype html><html lang="en">
    <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Metridex QuickScan Report</title>
    <style>
    :root{--bg:#0b0e12;--panel:#12161c;--text:#e6e6e6;--muted:#9aa4b2;--accent:#d4af37;--ok:#3fb950;--warn:#d4af37;--bad:#ff4d4f}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif}
    .wrap{max-width:980px;margin:24px auto;padding:0 16px}
    h1{margin:0 0 4px 0;font-size:28px}
    h2{margin:14px 0 8px 0;font-size:18px;color:var(--muted)}
    .card{background:var(--panel);border:1px solid #1c232e;border-radius:14px;padding:16px;margin:14px 0;box-shadow:0 0 0 1px rgba(255,255,255,0.02) inset}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .k{color:var(--muted);font-size:12px}
    .v{font-weight:600}
    .links a{color:var(--accent);text-decoration:none}
    pre{white-space:pre-wrap;word-break:break-word;background:#0e1319;border:1px solid #1b2430;border-radius:8px;padding:12px}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2a3340;background:#10151c;margin-left:8px}
    .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
    </style></head><body><div class="wrap">"""
    head = f"<h1>Metridex QuickScan — {html.escape(pair)}</h1>"
    sub  = f"<div class='badge'>Risk: {html.escape(lvl)} ({html.escape(str(score))})</div>"
    # Snapshot
    ch = m.get("priceChanges") or {}
    grid = f"""<div class="grid">
      <div><div class="k">Price</div><div class="v">{_fmt(m.get('price'),'$')}</div></div>
      <div><div class="k">Liquidity</div><div class="v">{_fmt(m.get('liq'),'$')}</div></div>
      <div><div class="k">FDV</div><div class="v">{_fmt(m.get('fdv'),'$')}</div></div>
      <div><div class="k">Market Cap</div><div class="v">{_fmt(m.get('mc'),'$')}</div></div>
      <div><div class="k">Δ 5m</div><div class="v">{_pct(ch.get('m5'))}</div></div>
      <div><div class="k">Δ 1h</div><div class="v">{_pct(ch.get('h1'))}</div></div>
      <div><div class="k">Δ 6h</div><div class="v">{_pct(ch.get('h6'))}</div></div>
      <div><div class="k">Δ 24h</div><div class="v">{_pct(ch.get('h24'))}</div></div>
      <div><div class="k">Age</div><div class="v">{_s(m.get('ageDays'))} d</div></div>
      <div><div class="k">As of</div><div class="v">{_time(m.get('asof'))}</div></div>
    </div>"""
    l_dex  = links.get("dex")
    l_scan = links.get("scan")
    l_ds   = links.get("dexscreener")
    l_site = links.get("site")
    def a(u,label):
        return f"<a href='{html.escape(u)}' target='_blank' rel='noopener'>{html.escape(label)}</a>" if u else "—"
    links_html = f"<div class='links'>{a(l_dex,'Open in DEX')} &middot; {a(l_scan,'Open in Scan')} &middot; {a(l_ds,'DexScreener')} &middot; {a(l_site,'Website')}</div>"
    sec_snapshot = f"<div class='card'>{grid}</div>"
    sec_ids = f"<div class='card'><h2>Identifiers</h2><div>Token: {html.escape(_s(m.get('tokenAddress')))}</div><div>Pair: {html.escape(_s(m.get('pairAddress')))}</div><div>Chain: {html.escape(_s(m.get('chain')))}</div></div>"
    sec_links = f"<div class='card'><h2>Links</h2>{links_html}</div>"
    sec_why = f"<div class='card'><h2>Why?</h2><pre>{html.escape(_s(why))}</pre></div>" if why else ""
    sec_whypp = f"<div class='card'><h2>Why++</h2><pre>{html.escape(_s(whypp))}</pre></div>" if whypp else ""
    sec_lp = f"<div class='card'><h2>LP lock (lite)</h2><pre>{html.escape(_s(lp))}</pre></div>" if lp else ""
    who = (web.get('whois') or {}); ssl = (web.get('ssl') or {}); way = (web.get('wayback') or {})
    sec_web = f"<div class='card'><h2>Website intel</h2>"
    sec_web += f"<div>WHOIS: created {_s(who.get('created'))}, registrar {_s(who.get('registrar'))}</div>"
    sec_web += f"<div>SSL: ok={_s(ssl.get('ok'))}, expires {_s(ssl.get('expires'))}, issuer {_s(ssl.get('issuer'))}</div>"
    sec_web += f"<div>Wayback first: {_s(way.get('first'))}</div></div>"
    html_end = "</div></body></html>"
    doc = (html_head + head + sub + sec_snapshot + sec_ids + sec_links + sec_why + sec_whypp + sec_lp + sec_web + html_end)
    return doc.encode("utf-8")"""

def main(path):
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()

    # LP -> no keyboard
    txt = re.sub(
        r"(elif\s+action\s*==\s*['\"]LP['\"]:\s*[\s\S]*?send_message\(\s*chat_id\s*,\s*text\s*,\s*reply_markup=)build_keyboard\([^\)]*\)",
        r"\1None",
        txt
    )
    txt = re.sub(
        r"(elif\s+action\s*==\s*['\"]LP['\"]:\s*[\s\S]*?send_message\(\s*chat_id\s*,\s*text\s*,\s*)reply_markup=.*?\)",
        r"\1reply_markup=None)",
        txt
    )

    # _mk_copy_keyboard -> remove nav
    txt = re.sub(
        r"def\s+_mk_copy_keyboard\([^)]*\):[\s\S]*?return\s+kb",
        """def _mk_copy_keyboard(token: str, links: dict | None):
    links = links or {}
    kb = {"inline_keyboard": []}
    if token and token != "—":
        kb["inline_keyboard"].append([{
            "text": "📋 Copy to input",
            "switch_inline_query_current_chat": token
        }])
    return kb""", 
        txt
    )

    # Robust HTML builder
    if "def _build_html_report(" in txt:
        txt = re.sub(r"def\s+_build_html_report\([\s\S]*?\)\s*:[\s\S]*?(?=\n\ndef|\Z)", HTML_FUNC, txt)
    else:
        txt += "\n\n" + HTML_FUNC

    out = path.replace(".py", ".CLEAN.py")
    with open(out, "w", encoding="utf-8") as f:
        f.write(txt)
    print("Patched ->", out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python server_patch_regex.py /path/to/server.py")
        raise SystemExit(2)
    main(sys.argv[1])
