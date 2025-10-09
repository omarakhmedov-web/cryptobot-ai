
# safe9e_replycanon.py — v1 (2025-10-09)
from typing import Dict, Any, List, Tuple

_SYNONYMS = {
    "why": "Why++",
    "why?": "Why++",
    "why ++": "Why++",
    "why++": "Why++",
    "why++ factors": "Why++",
    "why factors": "Why++",
    "why+": "Why++",
    "why plus": "Why++",
    "почему": "Why++",
    "зачем": "Why++",
}

_PRIORITY = [
    "Why++",
    "Signals",
    "Positives",
    "On-chain",
    "LP lock (lite)",
    "Open report",
    "Open in DEX",
    "Open in Scan",
]

def _canon_text(s: str) -> str:
    key = s.strip().lower().replace(" ", " ").replace("  ", " ")
    return _SYNONYMS.get(key, s.strip())

def _prio(s: str) -> int:
    try:
        return _PRIORITY.index(s)
    except ValueError:
        return len(_PRIORITY) + hash(s) % 1000

def canonicalize_reply_markup(markup: Any, max_per_row: int = 3) -> Any:
    if not isinstance(markup, dict):
        return markup
    ik = markup.get("inline_keyboard")
    if not isinstance(ik, list):
        return markup

    flat = []
    seen = set()

    for row in ik:
        if not isinstance(row, list):
            continue
        for btn in row:
            if not isinstance(btn, dict):
                continue
            txt = _canon_text(str(btn.get("text", "")))
            if len(txt) > 64:
                txt = txt[:61] + "…"
            btn["text"] = txt

            if "callback_data" in btn:
                cb = str(btn["callback_data"]).encode("utf-8")
                if len(cb) > 64:
                    btn["callback_data"] = cb[:64].decode("utf-8", "ignore")

            key = (btn.get("text", ""), btn.get("url", ""), btn.get("callback_data", ""))
            if key in seen:
                continue
            seen.add(key)
            flat.append(btn)

    flat.sort(key=lambda b: (_prio(b.get("text", "")), b.get("text", "")))

    flat_why = [b for b in flat if b.get("text") == "Why++"]
    flat_rest = [b for b in flat if b.get("text") != "Why++"]
    flat = (flat_why + flat_rest) if flat_why else flat

    new_ik = []
    row = []
    for b in flat:
        row.append(b)
        if len(row) >= max_per_row:
            new_ik.append(row)
            row = []
    if row:
        new_ik.append(row)

    markup["inline_keyboard"] = new_ik
    return markup
