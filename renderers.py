from typing import Dict, Any
from risk_engine import Verdict

def render_quick(verdict: Verdict, market: Dict[str,Any], links: Dict[str,str], lang: str = "en") -> str:
    chain = market.get("chain","?")
    pair = market.get("pairSymbol","?")
    price = market.get("price","?")
    fdv = market.get("fdv","?")
    mc = market.get("mc","?")
    liq = market.get("liq","?")
    vol = market.get("vol24h","?")
    d24 = market.get("delta24h","?")
    site = links.get("site") or "—"
    src = market.get("source","partial")
    return (f"Metridex QuickScan (MVP+)\n"
            f"{pair} on {chain}\n"
            f"Price: {price}\n"
            f"FDV {fdv} | MC {mc} | Liq {liq} | Vol24h {vol} | Δ24h {d24}\n"
            f"source: {src}\n"
            f"Site: {site}")

def render_details(verdict: Verdict, market: Dict[str,Any], webintel: Dict[str,Any], lang: str = "en") -> str:
    whois = webintel.get("whois",{})
    ssl = webintel.get("ssl",{})
    wb = webintel.get("wayback",{})
    return ("More details\n"
            f"Verdict: {verdict.level} ({verdict.score})\n"
            f"WHOIS: {whois}\n"
            f"SSL: {ssl}\n"
            f"Wayback: {wb}")

def render_why(verdict: Verdict, lang: str = "en") -> str:
    reasons = verdict.reasons or ["No specific risk flags"]
    lines = "\n".join(f"• {r}" for r in reasons[:5])
    return f"Why?\n{lines}\n\nVerdict: {verdict.level} ({verdict.score})"

def render_whypp(verdict: Verdict, factors: dict, lang: str = "en") -> str:
    lines = "\n".join(f"• {r}" for r in (verdict.reasons or [])[:12])
    return (f"Why++ (factors)\n"
            f"{lines}\n"
            f"score={verdict.score} level={verdict.level}")

def render_lp(lp_info: dict | None, lang: str = "en") -> str:
    if not lp_info:
        return "🔒 LP lock (lite)\nNo LP lock data provider wired. Add a locker API to enrich this."
    return f"🔒 LP lock (lite)\n{lp_info}"
