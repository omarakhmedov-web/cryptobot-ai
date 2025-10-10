from typing import Dict, Any
from risk_engine import Verdict

def _fmt_usd(x):
    if x is None: return "—"
    try:
        v = float(x)
    except Exception:
        return str(x)
    if v >= 1e9: return f"${v/1e9:.2f}B"
    if v >= 1e6: return f"${v/1e6:.2f}M"
    if v >= 1e3: return f"${v/1e3:.2f}K"
    return f"${v:.6f}" if v < 1 else f"${v:.2f}"

def _fmt_pct(x):
    if x is None: return "—"
    try:
        return f"{float(x):+.2f}%"
    except Exception:
        return str(x)

def _fmt_days(d):
    if d is None: return "—"
    try:
        d = float(d)
        if d < 1: return f"{int(d*24)}h"
        return f"{d:.1f}d"
    except Exception:
        return "—"

def _sev_emoji(level: str) -> str:
    lvl = (level or "").upper()
    return {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(lvl, "ℹ️")

def render_quick(verdict: Verdict, market: Dict[str,Any], links: Dict[str,str], lang: str = "en") -> str:
    chain = market.get("chain","?")
    pair = market.get("pairSymbol","?")
    price = market.get("price")
    fdv = market.get("fdv"); mc = market.get("mc"); liq = market.get("liq")
    vol24 = market.get("vol24h")
    chg = market.get("priceChanges") or {}
    age = market.get("ageDays")

    dex = (links or {}).get("dex") or "https://dexscreener.com"
    scan = (links or {}).get("scan") or "—"
    site = (links or {}).get("site") or "—"

    emoji = _sev_emoji(getattr(verdict, "level", ""))
    score = getattr(verdict, "score", "?")

    return (
f"*Metridex QuickScan — {pair}* {emoji} ({score})\n"
f"`{chain}`  •  Price: *{_fmt_usd(price)}*\n"
f"FDV: {_fmt_usd(fdv)}  •  MC: {_fmt_usd(mc)}  •  Liq: {_fmt_usd(liq)}\n"
f"Vol 24h: {_fmt_usd(vol24)}  •  Δ5m {_fmt_pct(chg.get('m5'))}  •  Δ1h {_fmt_pct(chg.get('h1'))}  •  Δ24h {_fmt_pct(chg.get('h24'))}\n"
f"Age: {_fmt_days(age)}  •  Source: {market.get('source','partial')}\n\n"
f"[Open in DEX]({dex})  |  [Scan]({scan})  |  Site: {site}"
    )

def render_details(verdict: Verdict, market: Dict[str,Any], webintel: Dict[str,Any], lang: str = "en") -> str:
    t = market.get("tokenAddress") or "—"
    p = market.get("pairAddress") or "—"
    chg = market.get("priceChanges") or {}
    vol = market.get("volumes") or {}
    return (
f"*More details*\n"
f"Verdict: *{verdict.level}* ({verdict.score})\n\n"
f"*Price change:* Δ5m {_fmt_pct(chg.get('m5'))} • Δ1h {_fmt_pct(chg.get('h1'))} • Δ6h {_fmt_pct(chg.get('h6'))} • Δ24h {_fmt_pct(chg.get('h24'))}\n"
f"*Volumes:* 5m {_fmt_usd(vol.get('m5'))} • 1h {_fmt_usd(vol.get('h1'))} • 6h {_fmt_usd(vol.get('h6'))} • 24h {_fmt_usd(vol.get('h24'))}\n\n"
f"*Token:* `{t}`\n"
f"*Pair:*  `{p}`"
    )

def render_why(verdict: Verdict, lang: str = "en") -> str:
    reasons = verdict.reasons or ["No specific risk flags"]
    lines = "\\n".join(f"• {r}" for r in reasons[:6])
    return f"*Why?* {_sev_emoji(verdict.level)}\\n{lines}\\n\\n*Verdict:* {verdict.level} ({verdict.score})"

def render_whypp(verdict: Verdict, factors: dict, lang: str = "en") -> str:
    lines = "\\n".join(f"• {r}" for r in (verdict.reasons or [])[:12])
    return (
        f"*Why++ — extended factors* {_sev_emoji(verdict.level)}\\n"
        f"{lines}\\n\\n"
        f"*Score:* {verdict.score}   *Level:* {verdict.level}"
    )

def render_lp(lp_info: dict | None, lang: str = "en") -> str:
    info = lp_info or {}
    lock = info.get("lock") or {}
    provider = lock.get("provider") or "n/a"
    pct = lock.get("percent") or "—"
    until = lock.get("until") or "—"
    return (
        "🔒 *LP lock (lite)*\\n"
        f"Provider: {provider}\\n"
        f"Locked: {pct}\\n"
        f"Until: {until}"
    )
