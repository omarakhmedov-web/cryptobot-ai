
# safe9e_stateful.py — v1 (2025-10-09)
# Adds per-token consistency with a small in-memory TTL cache.
# Policy:
#  - If message contains "NOT TRADABLE"/"No pools" => force HIGH 80/100 for that token.
#  - Else prefer numeric risks if present; precedence: HIGH(>=60) > CAUTION(15-59) > LOW(0-14).
#  - "Insufficient data" before On-chain: no numeric risk; do not override stored numeric state.
#  - Trust / Risk / inline (score ...) are aligned to the chosen (bucket, score).
#  - Fix "nals:" -> "⚠️ Signals:" and "IInsufficient"/"nsufficient".
#  - Remove duplicated trailing "Insufficient data ..." snippets.

import re as _re
import time as _time
from typing import Any, Dict, Tuple

# Regexes
_RE_TOKEN_ADDR = _re.compile(r"0x[a-fA-F0-9]{40}")
_RE_SCORE = _re.compile(r"Risk score:\s*(?P<score>\d{1,3})/100", _re.I)
_RE_RISK_LINE = _re.compile(r"(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)\s*.*?•\s*Risk score:\s*(?P<score>\d{1,3})/100", _re.I)
_RE_TRUST_LINE = _re.compile(r"Trust verdict:\s*(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)[^\n]*", _re.I)
_RE_SCORE_INLINE = _re.compile(r"\(score\s*(?P<score>\d{1,3})/100\)", _re.I)
_RE_IINSUFF = _re.compile(r"\bIInsufficient|\bnsufficient", _re.I)
_RE_INSUFF = _re.compile(r"Insufficient data\s*\(run .*?On-chain\)", _re.I)
_RE_INSUFF_DUP = _re.compile(r"(Insufficient data\s*\(run .*?On-chain\))(\s*\1)+", _re.I)
_RE_NOTTRAD = _re.compile(r"NOT TRADABLE\s*\(no active pools/liquidity\)", _re.I)
_RE_NOPOOLS = _re.compile(r"No pools found", _re.I)
_RE_BROKEN_NALS = _re.compile(r"(?:^|\n)\s*nals:", _re.I)
_RE_LOW60 = _re.compile(r"LOW RISK\s*🟢?\s*•\s*Risk score:\s*60/100", _re.I)
_RE_ONCHAIN_HDR = _re.compile(r"(?m)^On-chain\b")

# state: token -> (timestamp, score, label)
_SAFE9E_CACHE: Dict[str, Tuple[float, int, str]] = {}
_TTL_SEC = int(float(os.getenv("SAFE9E_TTL_MIN", "30"))*60) if "os" in globals() else 1800

def _bucket(score: int) -> str:
    if score <= 14: return "LOW RISK"
    if score <= 59: return "CAUTION"
    return "HIGH RISK"

def _emoji(label: str) -> str:
    return {"LOW RISK":"🟢","CAUTION":"🟡","HIGH RISK":"🔴","MEDIUM RISK":"🟡"}.get(label,"🟡")

def _extract_token(text: str) -> str:
    # Prefer the token in "Scan token: https://.../token/<addr>" else first 0x...
    m = _re.search(r"/token/(0x[a-fA-F0-9]{40})", text)
    if m: return m.group(1).lower()
    m = _RE_TOKEN_ADDR.search(text)
    return m.group(0).lower() if m else ""

def _read_cache(tok: str):
    if not tok: return None
    v = _SAFE9E_CACHE.get(tok)
    if not v: return None
    ts, score, label = v
    if _time.time() - ts > _TTL_SEC:
        _SAFE9E_CACHE.pop(tok, None)
        return None
    return v

def _write_cache(tok: str, score: int):
    if not tok: return
    label = _bucket(score)
    _SAFE9E_CACHE[tok] = (_time.time(), score, label)

def _best_of(a: int, b: int) -> int:
    # choose more severe bucket: HIGH>CAUTION>LOW by score threshold precedence
    la, lb = _bucket(a), _bucket(b)
    order = {"HIGH RISK":3, "CAUTION":2, "LOW RISK":1}
    if order[lb] > order[la]:
        return b
    if order[lb] < order[la]:
        return a
    # equal bucket -> take max score magnitude
    return b if b > a else a

def _enforce(text: str, score: int) -> str:
    label = _bucket(score); em = _emoji(label)
    t = _RE_RISK_LINE.sub(f"{label} {em} • Risk score: {score}/100", text)
    t = _RE_TRUST_LINE.sub(f"Trust verdict: {label} {em} • Risk score: {score}/100 (lower = safer)", t)
    t = _RE_SCORE_INLINE.sub(f"(score {score}/100)", t)
    t = _RE_LOW60.sub("CAUTION 🟡 • Risk score: 60/100", t)
    return t

def normalize_consistent(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return text
    t = str(text)

    # cosmetics & typos
    t = _RE_IINSUFF.sub("Insufficient", t)
    t = _RE_INSUFF_DUP.sub(lambda m: m.group(1), t)
    t = _RE_BROKEN_NALS.sub("\n⚠️ Signals:", t)

    tok = _extract_token(t)
    seen = _read_cache(tok)

    # NOT TRADABLE / No pools -> force 80
    if _RE_NOTTRAD.search(t) or _RE_NOPOOLS.search(t):
        score = 80
        _write_cache(tok, score)
        return _enforce(t, score)

    # Pre on-chain "Insufficient data" message: do not introduce numbers; do not override cache
    if _RE_INSUFF.search(t) and not _RE_ONCHAIN_HDR.search(t):
        # if we already have a cached numeric state for this token, enforce it (so сообщения согласованы);
        if seen:
            _, sc, _ = seen
            return _enforce(t, sc)
        # else leave Insufficient-only lines: drop any numbers accidentally present
        t = _RE_RISK_LINE.sub("MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t)
        t = _RE_TRUST_LINE.sub("Trust verdict: MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t)
        t = _RE_SCORE_INLINE.sub("", t)
        return t

    # Extract numeric score if present in message
    m = _RE_SCORE.search(t)
    if m:
        try:
            score_here = int(m.group("score"))
        except Exception:
            score_here = 60
        # Merge with cached
        base = seen[1] if seen else None
        score_final = score_here if base is None else _best_of(base, score_here)
        _write_cache(tok, score_final)
        return _enforce(t, score_final)

    # No explicit score; if we have cached -> enforce
    if seen:
        return _enforce(t, seen[1])

    # Fallback: return cleaned text
    return t
