
# safe9e_text_normalizer.py
from typing import Any
import re as _re

_RE_RISK_LINE    = _re.compile(r"(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)\s*.*?•\s*Risk score:\s*(?P<score>\d{1,3})/100", _re.I)
_RE_TRUST_LINE   = _re.compile(r"Trust verdict:\s*(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)[^\n]*", _re.I)
_RE_SCORE_INLINE = _re.compile(r"\(score\s*(?P<score>\d{1,3})/100\)", _re.I)
_RE_NOTTRAD      = _re.compile(r"NOT TRADABLE\s*\(no active pools/liquidity\)", _re.I)
_RE_NOPools      = _re.compile(r"No pools found", _re.I)
_RE_INSUFF       = _re.compile(r"Insufficient data\s*\(run .*?On-chain\)", _re.I)
_RE_NSUFF_GLUE   = _re.compile(r"(Insufficient data\s*\(run .*?On-chain\))\1+", _re.I)
_RE_NOTR_GLUE    = _re.compile(r"(NOT TRADABLE\s*\(no active pools/liquidity\))\1+", _re.I)
_RE_BROKEN_NALS  = _re.compile(r"(?:^|\n)\s*nals:", _re.I)
_RE_LOW60        = _re.compile(r"LOW RISK\s*🟢?\s*•\s*Risk score:\s*60/100", _re.I)

def _bucket(score: int) -> str:
    if score <= 14: return "LOW RISK"
    if score <= 59: return "CAUTION"
    return "HIGH RISK"

def normalize(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return text
    t = text.replace("nsufficient data", "Insufficient data")
    t = _RE_NSUFF_GLUE.sub(lambda m: m.group(1), t)
    t = _RE_NOTR_GLUE.sub(lambda m: m.group(1), t)
    t = _RE_BROKEN_NALS.sub("\n⚠️ Signals:", t)
    if _RE_INSUFF.search(t):
        t = _RE_RISK_LINE.sub("MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t, count=1)
        t = _RE_SCORE_INLINE.sub("", t)
        t = _RE_TRUST_LINE.sub("Trust verdict: MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t)
        return t
    if _RE_NOTTRAD.search(t) or _RE_NOPools.search(t):
        score = 80; label="HIGH RISK"; emoji="🔴"
        t = _RE_RISK_LINE.sub(f"{label} {emoji} • Risk score: {score}/100", t)
        t = _RE_TRUST_LINE.sub(f"Trust verdict: {label} {emoji} • NOT TRADABLE (no active pools/liquidity)", t)
        t = _RE_SCORE_INLINE.sub(f"(score {score}/100)", t)
        return t
    m = _RE_RISK_LINE.search(t)
    score = int(m.group("score")) if m else 60
    label = _bucket(score); emoji = {"LOW RISK":"🟢","CAUTION":"🟡","HIGH RISK":"🔴"}.get(label,"🟡")
    t = _RE_RISK_LINE.sub(f"{label} {emoji} • Risk score: {score}/100", t)
    t = _RE_SCORE_INLINE.sub(f"(score {score}/100)", t)
    t = _RE_TRUST_LINE.sub(f"Trust verdict: {label} {emoji} • Risk score: {score}/100 (lower = safer)", t)
    t = _RE_LOW60.sub("CAUTION 🟡 • Risk score: 60/100", t)
    return t
