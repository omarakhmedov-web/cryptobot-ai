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
