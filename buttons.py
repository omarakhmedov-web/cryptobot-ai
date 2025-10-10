from typing import Optional, Dict, Any

# Telegram inline keyboard builder.
# callback_data format must be short (<64 bytes). We use: v1:<ACTION>:<msgId>:<chatId>
# ACTION ∈ {DETAILS, WHY, WHYPP, LP, OPEN_DEX, OPEN_SCAN, UPGRADE}
def build_keyboard(chat_id: int, msg_id: int, links: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    links = links or {}
    dex_url = links.get("dex") or "https://dexscreener.com"
    scan_url = links.get("scan") or None  # may be None if chain unsupported

    def cb(action: str) -> str:
        # msg_id/chat_id can be None; guard to avoid "None" in callback
        mid = str(msg_id if msg_id is not None else 0)
        cid = str(chat_id if chat_id is not None else 0)
        return f"v1:{action}:{mid}:{cid}"

    keyboard = [
        [
            {"text": "More details", "callback_data": cb("DETAILS")},
            {"text": "Why?",         "callback_data": cb("WHY")},
            {"text": "Why++",        "callback_data": cb("WHYPP")},
            {"text": "LP lock",      "callback_data": cb("LP")},
        ],
        [
            {"text": "Open in DEX",  "url": dex_url},
            # Only include Scan button if we have a link (keeps UI clean)
            *([{"text": "Open in Scan", "url": scan_url}] if scan_url else []),
            {"text": "Upgrade",      "callback_data": cb("UPGRADE")},
        ]
    ]

    return {"inline_keyboard": keyboard}
