# -*- coding: utf-8 -*-
"""Metridex inline keyboard (full)
Preserves rich layout/context while aligning action names with server:
- Why++  -> WHYPP
- Copy CA -> COPY_CA
- Deltas  -> DELTA_M5 / DELTA_1H / DELTA_6H / DELTA_24H
- LP      -> LP
- Why     -> WHY
- Details -> DETAILS
"""
from typing import Optional, Dict, Any, List

def _cb(chat_id: int, msg_id: int, action: str) -> str:
    # Server callback format: v1:<ACTION>:<msgId>:<chatId>
    mid = str(msg_id if msg_id is not None else 0)
    cid = str(chat_id if chat_id is not None else 0)
    return f"v1:{action}:{mid}:{cid}"

def _is_ds(url: Optional[str]) -> bool:
    try:
        return "dexscreener.com" in (url or "").lower()
    except Exception:
        return False

def _nav_rows(links: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    rows: List[List[Dict[str, Any]]] = []
    dex_url  = (links.get("dex") or "").strip() or None
    scan_url = (links.get("scan") or "").strip() or None
    ds_url   = (links.get("dexscreener") or "").strip() or None

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
    links can include: dex, scan, dexscreener, share, deep_report, day_pass, pro, teams, help
    """
    links = links or {}
    rows: List[List[Dict[str, Any]]] = []

    # --- Top utility row (consistent) ---
    rows.append([
        {"text": "Watchlist", "callback_data": _cb(chat_id, msg_id, "WATCHLIST")},
        {"text": "Community", "url": "https://x.com/MetridexBot"},
    ])

    # --- START / INFO context: pricing/help rows (as in your original long file) ---
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

        # Navigation (DEX/Scan/DS) if available
        rows.extend(_nav_rows(links))

        # In start/info we скрываем дельты
        return {"inline_keyboard": rows}

    # --- COMMON navigation row(s) (DEX / Scan / DexScreener) ---
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

        # Reports (if enabled)
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
