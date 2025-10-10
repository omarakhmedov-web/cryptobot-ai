from typing import Optional, Dict, Any

def _cb(chat_id: int, msg_id: int, action: str) -> str:
    mid = str(msg_id if msg_id is not None else 0)
    cid = str(chat_id if chat_id is not None else 0)
    return f"v1:{action}:{mid}:{cid}"

def build_keyboard(chat_id: int, msg_id: int, links: Optional[Dict[str, Any]] = None, ctx: str = "quick") -> Dict[str, Any]:
    links = links or {}
    dex_url = links.get("dex") or None
    scan_url = links.get("scan") or None
    rows = []

    # Row 1
    nav = []
    if dex_url: nav.append({"text": "🟢 Open in DEX", "url": dex_url})
    if scan_url: nav.append({"text": "🔎 Open in Scan", "url": scan_url})
    if nav: rows.append(nav)

    if ctx == "quick":
        rows.append([{"text": "📄 More details", "callback_data": _cb(chat_id, msg_id, "DETAILS")}])
        rows.append([
            {"text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP")},
        ])
        rows.append([{"text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN")}])
        rows.append([{"text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    elif ctx == "details":
        rows.append([
            {"text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP")},
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
        ])
        rows.append([{"text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN")}])
        rows.append([{"text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    elif ctx == "onchain":
        rows.append([
            {"text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY")},
            {"text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP")},
            {"text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT")},
        ])
        rows.append([{"text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA")}])
        rows.append([{"text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP")}])

    rows.append([
        {"text": "Δ 5m", "callback_data": _cb(chat_id, msg_id, "DELTA_M5")},
        {"text": "Δ 1h", "callback_data": _cb(chat_id, msg_id, "DELTA_1H")},
        {"text": "Δ 6h", "callback_data": _cb(chat_id, msg_id, "DELTA_6H")},
        {"text": "Δ 24h", "callback_data": _cb(chat_id, msg_id, "DELTA_24H")},
    ])
    return {"inline_keyboard": rows}
