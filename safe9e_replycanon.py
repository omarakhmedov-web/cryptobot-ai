# safe9e_replycanon.py — v2 LEGACY-friendly (2025-10-09)
# Restores original button order in LEGACY mode. Only unifies labels (e.g., Why? -> Why++)
# and trims oversized fields. In CANON mode, keeps deterministic priority packing.
#
# Env:
#   SAFE9E_MARKUP_MODE = "legacy" | "canon"   (default: legacy)
#   SAFE9E_MAX_PER_ROW = int (only used in canon mode; default: 3)

from typing import Dict, Any, List, Tuple
import os

_MODE = (os.getenv("SAFE9E_MARKUP_MODE", "legacy") or "legacy").strip().lower()
_MAX_PER_ROW = int(os.getenv("SAFE9E_MAX_PER_ROW", "3") or "3")

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
        return len(_PRIORITY) + (hash(s) % 1000)

def _trim_button(btn: Dict[str, Any]) -> Dict[str, Any]:
    # In-place safety trims
    txt = str(btn.get("text", ""))
    if len(txt) > 64:
        btn["text"] = txt[:61] + "…"
    if "callback_data" in btn:
        try:
            cb = str(btn["callback_data"]).encode("utf-8")
            if len(cb) > 64:
                btn["callback_data"] = cb[:64].decode("utf-8", "ignore")
        except Exception:
            pass
    return btn

def _legacy_preserve_layout(markup: Any) -> Any:
    """LEGACY: keep original rows & order. Only unify labels and trim oversized fields.
    Deduplicate exact duplicates by preserving the first occurrence in-place.
    """
    if not isinstance(markup, dict):
        return markup
    ik = markup.get("inline_keyboard")
    if not isinstance(ik, list):
        return markup
    seen = set()
    new_ik: List[List[Dict[str, Any]]] = []
    for row in ik:
        if not isinstance(row, list):
            continue
        new_row: List[Dict[str, Any]] = []
        for btn in row:
            if not isinstance(btn, dict):
                continue
            btn = dict(btn)  # shallow copy
            btn["text"] = _canon_text(str(btn.get("text", "")))
            btn = _trim_button(btn)
            key = (btn.get("text", ""), btn.get("url", ""), btn.get("callback_data", ""))
            if key in seen:
                continue
            seen.add(key)
            new_row.append(btn)
        if new_row:
            new_ik.append(new_row)
    markup["inline_keyboard"] = new_ik
    return markup

def _canon_pack(markup: Any, max_per_row: int) -> Any:
    """CANON: flatten + priority sort + pack into rows of max_per_row."""
    if not isinstance(markup, dict):
        return markup
    ik = markup.get("inline_keyboard")
    if not isinstance(ik, list):
        return markup
    flat: List[Dict[str, Any]] = []
    seen = set()
    for row in ik:
        if not isinstance(row, list):
            continue
        for btn in row:
            if not isinstance(btn, dict):
                continue
            btn = dict(btn)
            btn["text"] = _canon_text(str(btn.get("text", "")))
            btn = _trim_button(btn)
            key = (btn.get("text", ""), btn.get("url", ""), btn.get("callback_data", ""))
            if key in seen:
                continue
            seen.add(key)
            flat.append(btn)
    flat.sort(key=lambda b: (_prio(b.get("text", "")), b.get("text", "")))
    # Ensure Why++ first if present
    flat_why = [b for b in flat if b.get("text") == "Why++"]
    flat_rest = [b for b in flat if b.get("text") != "Why++"]
    flat = (flat_why + flat_rest) if flat_why else flat

    new_ik: List[List[Dict[str, Any]]] = []
    row: List[Dict[str, Any]] = []
    for b in flat:
        row.append(b)
        if len(row) >= max_per_row:
            new_ik.append(row)
            row = []
    if row:
        new_ik.append(row)
    markup["inline_keyboard"] = new_ik
    return markup

def canonicalize_reply_markup(markup: Any, max_per_row: int = None) -> Any:
    """Public entry.
    LEGACY (default): only label unification + trim + dedupe, keep order & rows.
    CANON: deterministic priority sort + pack (max_per_row).
    """
    mode = _MODE
    if max_per_row is None:
        max_per_row = _MAX_PER_ROW
    try:
        if mode == "canon":
            return _canon_pack(markup, max_per_row)
        # default: legacy
        return _legacy_preserve_layout(markup)
    except Exception:
        # Fail-quiet: never break message sending
        return markup
