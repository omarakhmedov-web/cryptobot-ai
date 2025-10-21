# -*- coding: utf-8 -*-
from typing import Optional, Dict, Any

def _cb(chat_id: int, msg_id: int, action: str) -> str:
    mid = str(msg_id if msg_id is not None else 0)
    cid = str(chat_id if chat_id is not None else 0)
    return f"v1:{action}:{mid}:{cid}"

def build_keyboard(chat_id: int,
                   msg_id: int,
                   links: Optional[Dict[str, Any]] = None,
                   ctx: str = "quick") -> Dict[str, Any]:
    """
    ctx:
      - "start" / "info": pricing/help keyboard before user scans anything
      - "quick": short scan window
      - "details": after 'More details'
      - "onchain": after 'On-chain'
    """
    links = links or {}
    rows: list[list[Dict[str, Any]]] = []

    def is_ds(url: Optional[str]) -> bool:
        try:
            return "dexscreener.com" in (url or "").lower()
        except Exception:
            return False

    # ---------------- START / INFO ----------------
    if ctx in ("start", "info"):
        deep_report = links.get("deep_report")
        day_pass    = links.get("day_pass")
        pro         = links.get("pro")
        teams       = links.get("teams")
        help_url    = links.get("help")

        row1 = []
        if deep_report: row1.append({"text": "🔍 Deep report — $3", "url": deep_report})
        if day_pass:    row1.append({"text": "⏱ Day Pass — $9", "url": day_pass})
        if row1: rows.append(row1)

        row2 = []
        if pro:   row2.append({"text": "⚙️ Pro — $29", "url": pro})
        if teams: row2.append({"text": "👥 Teams — from $99", "url": teams})
        if row2: rows.append(row2)

        if help_url:
            rows.append([{"text": "ℹ️ How it works?", "url": help_url}])

    # Top row: Quick actions
    try:
        rows.insert(0, [
            {"text": "QuickScan", "callback_data": _cb(chat_id, msg_id, "QS")},
            {"text": "Watchlist", "callback_data": _cb(chat_id, msg_id, "WATCHLIST")},
            {"text": "Premium", "url": (links.get("pro") or links.get("day_pass") or help_url)},
            {"text": "Community", "url": (help_url or links.get("help"))},
        ])
    except Exception:
        pass
        return {"inline_keyboard": rows}

    # ---------------- COMMON NAV (DEX/Scan/DS) ----------------
    dex_url  = links.get("dex") or None
    scan_url = links.get("scan") or None
    ds_url   = links.get("dexscreener") or None

    # Primary nav row (DEX + Scan). Keep DEX only if it's a real swap UI (not DexScreener).
    nav = []
    if dex_url and not is_ds(dex_url):
        nav.append({"text": "🟢 Open in DEX", "url": dex_url})
    if scan_url:
        nav.append({"text": "🔎 Open in Scan", "url": scan_url})
    if nav:
        rows.append(nav)

    # Separate DexScreener row (distinct from DEX)
    ds_link = ds_url or (dex_url if is_ds(dex_url) else None)
    if ds_link:
        rows.append([{"text": "🟢 Open on DexScreener", "url": ds_link}])

    # ---------------- CONTEXT-SPECIFIC ACTIONS ----------------
    if ctx == "quick":
        # Optional Share link
        share = (links or {}).get("share")
        if share:
            rows.append([{"text": "🔗 Share this scan", "url": share}])
        rows.append([{"text": "📄 More details", "callback_data": _cb(chat_id, msg_id, "DETAILS")}])
        rows.append([
            {"text": "❓ Why?",  "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++","callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])
        rows.append([{"text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN")}])
        rows.append([{"text": "📋 Copy CA",  "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])
        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    elif ctx == "details":
        share = (links or {}).get("share")
        if share:
            rows.append([{"text": "🔗 Share this scan", "url": share}])
        # Keep only Copy CA here to avoid duplicate DEX/Scan; DS/DEX/Scan come from common nav above
        rows.append([{"text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])

        rows.append([
            {"text": "❓ Why?",  "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++","callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])
        rows.append([{"text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN")}])
        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    elif ctx == "onchain":
        share = (links or {}).get("share")
        if share:
            rows.append([{"text": "🔗 Share this scan", "url": share}])
        # On-chain view retains navigation + insights
        rows.append([
            {"text": "❓ Why?",  "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++","callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])
        rows.append([{"text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])
        rows.append([
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
            {"text": "📄 Report (PDF)",  "callback_data": _cb(chat_id, msg_id, "REPORT_PDF")},
        ])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    # ---------------- DELTA ROW (bottom) ----------------
    rows.append([
        {"text": "Δ 5m",  "callback_data": _cb(chat_id, msg_id, "DELTA_M5")},
        {"text": "Δ 1h",  "callback_data": _cb(chat_id, msg_id, "DELTA_1H")},
        {"text": "Δ 6h",  "callback_data": _cb(chat_id, msg_id, "DELTA_6H")},
        {"text": "Δ 24h", "callback_data": _cb(chat_id, msg_id, "DELTA_24H")},
    ])

    return {"inline_keyboard": rows}
