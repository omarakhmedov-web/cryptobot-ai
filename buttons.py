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
    rows = []

    if ctx in ("start", "info"):
        # Expect pricing/help URLs in links
        deep_report = links.get("deep_report")
        day_pass = links.get("day_pass")
        pro = links.get("pro")
        teams = links.get("teams")
        help_url = links.get("help")

        row1 = []
        if deep_report: row1.append({"text": "🔍 Deep report — $3", "url": deep_report})
        if day_pass: row1.append({"text": "⏱ Day Pass — $9", "url": day_pass})
        if row1: rows.append(row1)

        row2 = []
        if pro: row2.append({"text": "⚙️ Pro — $29", "url": pro})
        if teams: row2.append({"text": "👥 Teams — from $99", "url": teams})
        if row2: rows.append(row2)

        if help_url:
            rows.append([{ "text": "ℹ️ How it works?", "url": help_url }])

        return {"inline_keyboard": rows}

    # ---- NAV row(s) ----
    dex_url = links.get("dex") or None
    scan_url = links.get("scan") or None
    ds_url = links.get("dexscreener") or None  # explicit DexScreener link if provided
    # If only one DEX URL is provided and it's DexScreener, reflect that below in dedicated DS row.

    if ctx == "details":
        # First row: Open in DEX | Open in Scan | Copy CA
        row = []
        if dex_url: row.append({"text": "🟢 Open in DEX", "url": dex_url})
        if scan_url: row.append({"text": "🔎 Open in Scan", "url": scan_url})
        row.append({ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") })
        if row: rows.append(row)

        # Separate button: Open on DexScreener (if link available)
        ds_link = ds_url or (dex_url if (dex_url and "dexscreener.com" in dex_url.lower()) else None)
        if ds_link:
            rows.append([{ "text": "🟢 Open on DexScreener", "url": ds_link }])

        # Functional rows
        rows.append([
            { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
            { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") }
        ])
        rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])
        rows.append([
            { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
            { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
        ])
        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

    else:
        # QUICK / ONCHAIN contexts: keep previous layout but add DS button if distinguishable.
        nav = []
        if dex_url:
            nav.append({"text": "🟢 Open in DEX", "url": dex_url})
        if scan_url:
            nav.append({"text": "🔎 Open in Scan", "url": scan_url})
        if nav: rows.append(nav)

        ds_link = ds_url or (dex_url if (dex_url and "dexscreener.com" in dex_url.lower()) else None)
        if ds_link:
            rows.append([{ "text": "🟢 Open on DexScreener", "url": ds_link }])

        if ctx == "quick":
            rows.append([{ "text": "📄 More details", "callback_data": _cb(chat_id, msg_id, "DETAILS") }])
            rows.append([
                { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
                { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") },
            ])
            rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])
            rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])
            rows.append([
                { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
                { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
            ])
            rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])
        elif ctx == "onchain":
            rows.append([
                { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
                { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") }
            ])
            rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])
            rows.append([
                { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
                { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
            ])
            rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

    # Deltas (bottom row for all scan contexts)
    rows.append([
        { "text": "Δ 5m", "callback_data": _cb(chat_id, msg_id, "DELTA_M5") },
        { "text": "Δ 1h", "callback_data": _cb(chat_id, msg_id, "DELTA_1H") },
        { "text": "Δ 6h", "callback_data": _cb(chat_id, msg_id, "DELTA_6H") },
        { "text": "Δ 24h", "callback_data": _cb(chat_id, msg_id, "DELTA_24H") },
    ])
    return {"inline_keyboard": rows}

    # ---- NAV (DEX / Scan) ----
    dex_url = links.get("dex") or None
    scan_url = links.get("scan") or None
    nav = []
    if dex_url:
        btn_text = "🟢 Open in DEX"
        if "dexscreener.com" in dex_url.lower():
            btn_text = "🟢 Open on DexScreener"
        nav.append({"text": btn_text, "url": dex_url})
    if scan_url: nav.append({"text": "🔎 Open in Scan", "url": scan_url})
    if nav: rows.append(nav)

    if ctx == "quick":
        rows.append([{ "text": "📄 More details", "callback_data": _cb(chat_id, msg_id, "DETAILS") }])
        rows.append([
            { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
            { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") },
        ])
        rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])
        rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])
        rows.append([
            { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
            { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
        ])
        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

    elif ctx == "details":
        rows.append([
            { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
            { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") }
        ])
        rows.append([{ "text": "🧪 On-chain", "callback_data": _cb(chat_id, msg_id, "ONCHAIN") }])
        rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])
        rows.append([
            { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
            { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
        ])
        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

    elif ctx == "onchain":
        rows.append([
            { "text": "❓ Why?", "callback_data": _cb(chat_id, msg_id, "WHY") },
            { "text": "ℹ️ Why++", "callback_data": _cb(chat_id, msg_id, "WHYPP") }
        ])
        rows.append([{ "text": "📋 Copy CA", "callback_data": _cb(chat_id, msg_id, "COPY_CA") }])
        rows.append([
            { "text": "🧾 Report (HTML)", "callback_data": _cb(chat_id, msg_id, "REPORT") },
            { "text": "📄 Report (PDF)", "callback_data": _cb(chat_id, msg_id, "REPORT_PDF") }
        ])
        rows.append([{ "text": "🔒 LP lock (lite)", "callback_data": _cb(chat_id, msg_id, "LP") }])

    # Deltas (bottom row for all scan contexts)
    rows.append([
        { "text": "Δ 5m", "callback_data": _cb(chat_id, msg_id, "DELTA_M5") },
        { "text": "Δ 1h", "callback_data": _cb(chat_id, msg_id, "DELTA_1H") },
        { "text": "Δ 6h", "callback_data": _cb(chat_id, msg_id, "DELTA_6H") },
        { "text": "Δ 24h", "callback_data": _cb(chat_id, msg_id, "DELTA_24H") },
    ])
    return {"inline_keyboard": rows}
