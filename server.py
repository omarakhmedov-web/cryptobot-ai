"""
server_WOW3_applied.py
Drop-in helpers for premium HTML report, PDF export, delta toasts (+ sparkline),
and *heavy-only* throttling logic.
This module is framework-agnostic: integrate by calling helpers from your handlers.
"""

from __future__ import annotations
from typing import Callable, Optional, Dict, Any, Tuple
import json
import re
import datetime as _dt
import html as _html

__all__ = [
    "_build_html_report",
    "html_report_filename",
    "_html_to_pdf",
    "delta_toast_text",
    "append_delta_point",
    "should_throttle",
]

# ------------------------- HTML REPORT (no logo; Copy CA next to links) -------------------------

def _esc(x: Any) -> str:
    return _html.escape("" if x is None else str(x))

def _fmt_money(x: Any) -> str:
    try:
        n = float(x)
    except Exception:
        return "—"
    a = abs(n)
    if a >= 1_000_000_000: return f"${n/1_000_000_000:.2f}B"
    if a >= 1_000_000:     return f"${n/1_000_000:.2f}M"
    if a >= 1_000:         return f"${n/1_000:.2f}K"
    return f"${n:.6f}" if a < 1 else f"${n:.2f}"

def _fmt_pct(x: Any) -> str:
    try:
        n = float(x)
        if n > 0:  return f"▲ {n:+.2f}%"
        if n < 0:  return f"▼ {n:+.2f}%"
        return f"• {n:+.2f}%"
    except Exception:
        return "—"

def _badge(level: str) -> str:
    lv = (level or "").upper()
    if "HIGH" in lv:    cls, txt = "high", "HIGH"
    elif "MED" in lv:   cls, txt = "med", "MEDIUM"
    elif "LOW" in lv:   cls, txt = "low", "LOW"
    elif "UNKNOWN" in lv: cls, txt = "unk", "UNKNOWN"
    else:               cls, txt = "unk", "—"
    return f'<span class="badge {cls}">{txt}</span>'

def _asof(ts_ms: Any) -> str:
    if isinstance(ts_ms, (int, float)):
        try:
            return _dt.datetime.utcfromtimestamp(int(ts_ms)/1000.0).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass
    return "—"

def _get(d: Dict[str, Any], *path, default="—"):
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return default if cur is None else cur

def _build_html_report(bundle: Dict[str, Any]) -> bytes:
    """
    Premium dark+gold HTML; no logo; Copy CA is placed next to DEX/Scan links.
    """
    b = bundle or {}
    v = b.get("verdict") or {}
    m = b.get("market") or {}
    links = b.get("links") or {}

    pair  = _get(m, "pairSymbol")
    chain = _get(m, "chain")
    price = _get(m, "price")
    fdv   = _get(m, "fdv", default=None)
    mc    = _get(m, "mc", default=None)
    liq   = _get(m, "liq", default=None) or _get(m, "liquidityUSD", default=None)
    vol24 = _get(m, "vol24h", default=None) or _get(m, "volume24hUSD", default=None)
    ch5   = _get(m, "priceChanges", default={}).get("m5")
    ch1   = _get(m, "priceChanges", default={}).get("h1")
    ch24  = _get(m, "priceChanges", default={}).get("h24")
    token = _get(m, "tokenAddress")
    asof_s = _asof(_get(m, "asof", default=None))
    dex_link  = _esc(_get(links, "dex", default="#"))
    scan_link = _esc(_get(links, "scan", default="#"))
    site_link = _get(links, "site", default="—")

    style = """
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">
<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">
<style>
  :root{
    --bg:#0a0a0c; --card:#111217; --muted:#b8bbc7; --text:#e9e9ee;
    --gold:#d4af37; --ok:#2fd178; --med:#e5c04d; --bad:#ff5d5d; --unk:#9aa0ab;
    --chip:#1a1b22; --chipb:#20222b;
    --mono:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;
    --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;padding:32px;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);}
  .wrap{max-width:980px;margin:0 auto}
  h1{font-size:20px;margin:0 0 2px 0;font-weight:600;letter-spacing:.1px}
  .sub{color:var(--muted);font-size:12px}
  .badge{display:inline-block;padding:3px 8px;border-radius:14px;margin-left:8px;font-weight:600;font-size:11px;letter-spacing:.3px}
  .badge.low{background:rgba(47,209,120,.12);color:var(--ok)}
  .badge.med{background:rgba(229,192,77,.14);color:var(--med)}
  .badge.high{background:rgba(255,93,93,.14);color:var(--bad)}
  .badge.unk{background:rgba(154,160,171,.14);color:var(--unk)}
  .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0 22px}
  .kpi{background:var(--card);border-radius:14px;padding:14px 14px 12px;box-shadow:0 1px 0 #1c1e2a inset,0 8px 24px rgba(0,0,0,.3)}
  .kpi .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
  .kpi .v{font-size:16px;font-weight:600}
  .card{background:var(--card);border-radius:16px;padding:16px 16px;box-shadow:0 1px 0 #1c1e2a inset,0 10px 32px rgba(0,0,0,.38);margin-bottom:14px}
  .links{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px}
  a{color:var(--gold);text-decoration:none} a:hover{text-decoration:underline}
  footer{margin-top:26px;color:var(--muted);font-size:12px}
</style>
<script>
  function copyCA(txt){
    try{
      navigator.clipboard.writeText(txt).then(()=>{ alert('Contract address copied'); });
    }catch(e){ alert(txt); }
  }
</script>
"""

    head = f"<!doctype html><html><head>{style}</head><body><div class='wrap'>"
    head += f"<h1>{_esc(pair)} {_badge(_get(v, 'level',''))}</h1>"
    head += f"<div class='sub'>{_esc(chain)} • As of {asof_s}</div>"

    grid = f"""
<div class="grid">
  <div class="kpi"><div class="k">Price</div><div class="v">{_esc(price)}</div></div>
  <div class="kpi"><div class="k">FDV</div><div class="v">{_fmt_money(fdv)}</div></div>
  <div class="kpi"><div class="k">MC</div><div class="v">{_fmt_money(mc)}</div></div>
  <div class="kpi"><div class="k">Liquidity</div><div class="v">{_fmt_money(liq)}</div></div>
  <div class="kpi"><div class="k">Volume 24h</div><div class="v">{_fmt_money(vol24)}</div></div>
  <div class="kpi"><div class="k">Δ 5m</div><div class="v">{_fmt_pct(ch5)}</div></div>
  <div class="kpi"><div class="k">Δ 1h</div><div class="v">{_fmt_pct(ch1)}</div></div>
  <div class="kpi"><div class="k">Δ 24h</div><div class="v">{_fmt_pct(ch24)}</div></div>
</div>
"""

    why = _get(b, "why")
    whypp = _get(b, "whypp")

    links_html = "<div class='links'>"
    if dex_link and dex_link != "#":
        links_html += f"<a href='{dex_link}'>🟢 Open in DEX</a>"
    if scan_link and scan_link != "#":
        links_html += f"<a href='{scan_link}'>🔍 Open in Scan</a>"
    if site_link and site_link not in (None, "—"):
        links_html += f"<a href='{_esc(site_link)}'>🌐 Website</a>"
    if token and token != "—":
        tok = _esc(token)
        links_html += f"<a class='mono' href='javascript:copyCA(\"{tok}\")'>📋 Copy CA</a>"
    links_html += "</div>"

    doc = (
        head
        + grid
        + f"<div class='card'><div class='k'>Why?</div><div>{_esc(why)}</div></div>"
        + f"<div class='card'><div class='k'>Why++</div><div>{_esc(whypp)}</div></div>"
        + links_html
        + "<footer>Generated by Metridex • QuickScan</footer>"
        + "</div></body></html>"
    )
    return doc.encode("utf-8")


def html_report_filename(pair_symbol: str, asof_ms: Optional[int]) -> str:
    """Human-friendly filename."""
    try:
        ts = _dt.datetime.utcfromtimestamp(int(asof_ms)/1000.0).strftime("%Y-%m-%d_%H%M")
    except Exception:
        ts = "now"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(pair_symbol or "Report"))
    return f"{safe}_Report_{ts}.html"


# ------------------------- PDF EXPORT (best-effort, optional deps) -------------------------

def _html_to_pdf(html_bytes: bytes) -> Optional[bytes]:
    """
    Try converting HTML to PDF using available engines.
    Order: WeasyPrint -> xhtml2pdf -> pdfkit.
    Returns PDF bytes or None if conversion not possible.
    """
    html_str = html_bytes.decode("utf-8", errors="replace")

    try:
        from weasyprint import HTML  # type: ignore
        pdf = HTML(string=html_str).write_pdf()
        if pdf:
            return pdf
    except Exception:
        pass

    try:
        from xhtml2pdf import pisa  # type: ignore
        import io
        out = io.BytesIO()
        pisa.CreatePDF(io.StringIO(html_str), dest=out)
        pdf = out.getvalue()
        if pdf and len(pdf) > 1000:
            return pdf
    except Exception:
        pass

    try:
        import pdfkit  # type: ignore
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=True, encoding="utf-8") as tmp:
            tmp.write(html_str); tmp.flush()
            pdf = pdfkit.from_file(tmp.name, False)
            if pdf:
                return pdf
    except Exception:
        pass

    return None


# ------------------------- Delta toasts (with sparkline) -------------------------

_SPARK = "▁▂▃▄▅▆▇█"

def _spark(values):
    xs = [float(x) for x in values if x is not None]
    if len(xs) < 2: return ""
    lo, hi = min(xs), max(xs)
    if hi - lo < 1e-12:
        return _SPARK[0] * len(xs)
    res = []
    for v in xs:
        idx = int((v - lo) / (hi - lo) * (len(_SPARK)-1))
        res.append(_SPARK[max(0, min(idx, len(_SPARK)-1))])
    return "".join(res)

def append_delta_point(cache_get: Callable[[str], Optional[str]], cache_set: Callable[[str, str, int], None],
                       key: str, value: Optional[float], maxlen: int = 8, ttl_sec: int = 6*60*60) -> list:
    try:
        raw = cache_get(key)
        arr = json.loads(raw) if raw else []
        if not isinstance(arr, list): arr = []
    except Exception:
        arr = []
    try:
        arr.append(None if value is None else float(value))
    except Exception:
        arr.append(None)
    if len(arr) > maxlen:
        arr = arr[-maxlen:]
    cache_set(key, json.dumps(arr), ttl_sec)
    return arr

def delta_toast_text(bundle: Dict[str, Any], label: str,
                     cache_get: Callable[[str], Optional[str]],
                     cache_set: Callable[[str, str, int], None]) -> str:
    key_map = {"5M": "m5", "1H": "h1", "6H": "h6", "24H": "h24"}
    pc_key = key_map.get(label.upper())
    mkt = (bundle.get("market") or {})
    val = None
    try:
        val = ((mkt.get("priceChanges") or {}) or {}).get(pc_key)
    except Exception:
        val = None

    pair = (mkt.get("pairSymbol") or "—")
    asof_ms = mkt.get("asof")
    asof_s = "—"
    if isinstance(asof_ms, (int, float)):
        try:
            asof_s = _dt.datetime.utcfromtimestamp(int(asof_ms)/1000.0).strftime("%H:%M UTC")
        except Exception:
            pass

    # series + sparkline
    series_key = f"spark:{(mkt.get('tokenAddress') or pair)}:{label}"
    arr = append_delta_point(cache_get, cache_set, series_key, val)
    sp = _spark(arr)

    def _pct(x):
        try:
            n = float(x)
            if n > 0: return f"▲ {n:+.2f}%"
            if n < 0: return f"▼ {n:+.2f}%"
            return f"• {n:+.2f}%"
        except Exception:
            return "—"

    return f"{label}: {_pct(val)} {sp} ({pair}, {asof_s})"


# ------------------------- Throttle only HEAVY actions -------------------------

_HEAVY = {"DETAILS", "ONCHAIN", "REPORT", "REPORT_PDF"}

def should_throttle(cache_get: Callable[[str], Optional[str]], cache_set: Callable[[str, str, int], None],
                    key: str, action: str, ttl_sec: int = 5) -> bool:
    if action not in _HEAVY:
        return False
    if cache_get(key):
        return True
    cache_set(key, "1", ttl_sec)
    return False
