# -*- coding: utf-8 -*-
"""Metridex inline keyboard (full, with DEX fallback)
- Preserves full layout (start/info/quick/details/onchain)
- Maps actions to server: WHYPP, COPY_CA, DELTA_M5/1H/6H/24H, LP, WHY, DETAILS
- Normalizes link aliases (dex/scan/dexscreener/share/...)
- If 'dex' is missing, derives a DEX link using (chain, token) for ETH/BSC/Polygon
"""
from typing import Optional, Dict, Any, List

def _cb(chat_id: int, msg_id: int, action: str) -> str:
    mid = str(msg_id if msg_id is not None else 0)
    cid = str(chat_id if chat_id is not None else 0)
    return f"v1:{action}:{mid}:{cid}"

def _is_ds(url: Optional[str]) -> bool:
    try:
        return "dexscreener.com" in (url or "").lower()
    except Exception:
        return False

def _first(d: Dict[str, Any], *keys) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _norm_links(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    L = dict(raw or {})
    chain = _first(L, "chain", "CHAIN", "network", "NETWORK", "chainId", "CHAIN_ID")
    token = _first(L, "token", "TOKEN", "address", "ADDRESS", "contract", "CONTRACT", "ca", "CA", "token_address")
    # Base normalized set
    out = {
        "dex": _first(L, "dex","DEX","swap","swap_url","DEX_URL","open_in_dex"),
        "scan": _first(L, "scan","SCAN","scan_url","SCAN_URL","explorer","explorer_url"),
        "dexscreener": _first(L, "dexscreener","ds","DS","dexscreener_url","DS_URL"),
        "share": _first(L, "share","share_url","SHARE_URL"),
        "deep_report": _first(L, "deep_report","DEEP_URL","deep_url"),
        "day_pass": _first(L, "day_pass","DAY_URL","day_url"),
        "pro": _first(L, "pro","PRO_URL"),
        "teams": _first(L, "teams","TEAMS_URL"),
        "help": _first(L, "help","HELP_URL","site","SITE_URL","help_url"),
        "token": token,
        "chain": (chain or "").lower(),
    }
    # Derive DEX if missing and (chain, token) are known
    if not out["dex"] and token:
        ch = (out["chain"] or "").lower()
        t = token
        if ch in ("eth","ethereum"):
            out["dex"] = f"https://app.uniswap.org/swap?outputCurrency={t}"
        elif ch in ("bsc","bscscan","bnb","binance","binance-smart-chain"):
            out["dex"] = f"https://pancakeswap.finance/swap?outputCurrency={t}"
        elif ch in ("polygon","matic","polygonscan"):
            out["dex"] = f"https://quickswap.exchange/#/swap?outputCurrency={t}"
        # else: leave None (other chains can be added later)
    return out

def _nav_rows(links: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    rows: List[List[Dict[str, Any]]] = []
    dex_url  = links.get("dex") or None
    scan_url = links.get("scan") or None
    ds_url   = links.get("dexscreener") or None

    nav: List[Dict[str, Any]] = []
    if dex_url and not _is_ds(dex_url):
        nav.append({"text": "🟢 Open in DEX", "url": dex_url})
    if scan_url:
        nav.append({"text": "🔎 Open in Scan", "url": scan_url})
    if nav:
        rows.append(nav)

    ds_link = ds_url or (dex_url if _is_ds(dex_url) else None)
    if ds_link:
        rows.append([{"text": "🟢 Open on DexScreener", "url": ds_link}])
    return rows

def _delta_row(chat_id: int, msg_id: int) -> List[Dict[str, Any]]:
    return [
        {"text": "Δ 5m",  "callback_data": _cb(chat_id, msg_id, "DELTA_M5")},
        {"text": "Δ 1h",  "callback_data": _cb(chat_id, msg_id, "DELTA_1H")},
        {"text": "Δ 6h",  "callback_data": _cb(chat_id, msg_id, "DELTA_6H")},
        {"text": "Δ 24h", "callback_data": _cb(chat_id, msg_id, "DELTA_24H")},
    ]

def build_keyboard(chat_id: int,
                   msg_id: int,
                   links: Optional[Dict[str, Any]] = None,
                   ctx: str = "quick") -> Dict[str, List[List[Dict[str, Any]]]]:
    """Return Telegram reply_markup dict.
    ctx: 'start' | 'info' | 'quick' | 'details' | 'onchain'
    links can include: dex, scan, dexscreener, share, deep_report, day_pass, pro, teams, help,
                      chain, token (for DEX fallback on ETH/BSC/Polygon)
    """
    links = _norm_links(links)
    rows: List[List[Dict[str, Any]]] = []

    # --- Top utility row (consistent) ---
    rows.append([
        {"text": "Watchlist", "callback_data": _cb(chat_id, msg_id, "WATCHLIST")},
        {"text": "Community", "url": "https://x.com/MetridexBot"},
    ])

    # --- START / INFO context ---
    if ctx in ("start", "info"):
        deep_report = links.get("deep_report")
        day_pass    = links.get("day_pass")
        pro         = links.get("pro")
        teams       = links.get("teams")
        help_url    = links.get("help") or "https://metridex.com/help"

        row1: List[Dict[str, Any]] = []
        if deep_report: row1.append({"text": "🔍 Deep report — $3", "url": deep_report})
        if day_pass:    row1.append({"text": "⏱ Day Pass — $9", "url": day_pass})
        if row1: rows.append(row1)

        row2: List[Dict[str, Any]] = []
        if pro:   row2.append({"text": "⚙️ Pro — $29", "url": pro})
        if teams: row2.append({"text": "👥 Teams — from $99", "url": teams})
        if row2: rows.append(row2)

        if help_url:
            rows.append([{ "text": "ℹ️ How it works?", "url": help_url }])

        rows.extend(_nav_rows(links))
        return {"inline_keyboard": rows}

    # --- COMMON navigation row(s) ---
    rows.extend(_nav_rows(links))

    # --- QUICK context ---
    if ctx == "quick":
        share = links.get("share")
        if share:
            rows.append([{ "text": "🔗 Share this scan", "url": share }])

        rows.append([{ "text": "📄 More details", "callback_data": _cb(chat_id, msg_id, "DETAILS") }])

        rows.append([
            {"text": "❓ Why?",   "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "📘 Why++",  "callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])

        rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])
        rows.append([{ "text": "📋 Copy CA",  "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])

        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])

        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

        rows.append(_delta_row(chat_id, msg_id))
        return {"inline_keyboard": rows}

    # --- DETAILS context ---
    if ctx == "details":
        share = links.get("share")
        if share:
            rows.append([{ "text": "🔗 Share this scan", "url": share }])

        rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])

        rows.append([
            {"text": "❓ Why?",   "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "📘 Why++",  "callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])

        rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])

        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])

        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

        rows.append(_delta_row(chat_id, msg_id))
        return {"inline_keyboard": rows}

    # --- ONCHAIN context ---
    if ctx == "onchain":
        share = links.get("share")
        if share:
            rows.append([{ "text": "🔗 Share this scan", "url": share }])

        rows.append([
            {"text": "❓ Why?",   "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "📘 Why++",  "callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])

        rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])

        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])

        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

        rows.append(_delta_row(chat_id, msg_id))
        return {"inline_keyboard": rows}

    # Fallback
    return {"inline_keyboard": rows}
