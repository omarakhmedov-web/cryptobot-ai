from typing import Dict, Any, List

# Fixed order: 1 More details, 2 Why?, 3 Why++, 4 LP lock, 5 Open in DEX, 6 Open in Scan, 7 Upgrade

def keyboard_main(version: str, msg_id: int, chat_id: int, links: Dict[str,str]) -> Dict[str, Any]:
    def cb(action: str) -> str:
        return f"{version}:{action}:{msg_id}:{chat_id}"
    rows: List[List[Dict[str,Any]]] = [
        [
            {"text": "More details", "callback_data": cb("DETAILS")},
            {"text": "Why?", "callback_data": cb("WHY")},
            {"text": "Why++", "callback_data": cb("WHYPP")},
        ],
        [
            {"text": "LP lock", "callback_data": cb("LP")},
            {"text": "Open in DEX", "url": links.get("dex") or "https://dexscreener.com"},
            {"text": "Open in Scan", "url": links.get("scan") or "https://etherscan.io"},
        ],
        [
            {"text": "Upgrade", "callback_data": cb("UPGRADE")}
        ]
    ]
    return {"inline_keyboard": rows}
