# safe9e_text_normalizer.py — v2 (2025-10-09)
# Deterministic text normalizer for Metridex bot messages & HTML exports.
# - Fixes duplicates: "IInsufficient", repeated NOT TRADABLE/Insufficient
# - Pre-onchain: only "Insufficient data" (no numeric scores) when "On-chain" block отсутствует
# - No pools/NOT TRADABLE: force HIGH 80/100 across all sections
# - Align Trust/Risk/inline (score .../100)
# - Fix LP-lite: EOA vs contract mismatch wording

import re as _re
from typing import Any

# Core regexes
_RE_RISK_LINE     = _re.compile(r"(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)\s*.*?•\s*Risk score:\s*(?P<score>\d{1,3})/100", _re.I)
_RE_TRUST_LINE    = _re.compile(r"Trust verdict:\s*(?P<label>LOW RISK|CAUTION|HIGH RISK|MEDIUM RISK)[^\\n]*", _re.I)
_RE_SCORE_INLINE  = _re.compile(r"\(score\s*(?P<score>\d{1,3})/100\)", _re.I)
_RE_NOTTRAD       = _re.compile(r"NOT TRADABLE\s*\(no active pools/liquidity\)", _re.I)
_RE_NOPOOLS       = _re.compile(r"No pools found", _re.I)
_RE_INSUFF        = _re.compile(r"\bInsufficient data\s*\(run .*?On-chain\)", _re.I)
_RE_IINSUFF       = _re.compile(r"\bIInsufficient", _re.I)  # double I glitch
_RE_NSUFF_GLUE    = _re.compile(r"(Insufficient data\s*\(run .*?On-chain\))\1+", _re.I)
_RE_NOTR_GLUE     = _re.compile(r"(NOT TRADABLE\s*\(no active pools/liquidity\))\1+", _re.I)
_RE_BROKEN_NALS   = _re.compile(r"(?:^|\\n)\\s*nals:", _re.I)
_RE_LOW60         = _re.compile(r"LOW RISK\\s*🟢?\\s*•\\s*Risk score:\\s*60/100", _re.I)
_RE_ONCHAIN_HDR   = _re.compile(r"(?m)^On-chain\\b")

# LP-lite mismatch: "Verdict: ... (EOA holds LP)" while later "Top holder type: contract"
_RE_LPLITE_EOA    = _re.compile(r"Verdict:\\s*[^\\n]*\\(EOA holds LP\\)", _re.I)
_RE_LPLITE_CONTRACT = _re.compile(r"Top holder type:\\s*contract", _re.I)

def _bucket(score: int) -> str:
    if score <= 14: return "LOW RISK"
    if score <= 59: return "CAUTION"
    return "HIGH RISK"

def _emoji(label: str) -> str:
    return {"LOW RISK":"🟢","CAUTION":"🟡","HIGH RISK":"🔴","MEDIUM RISK":"🟡"}.get(label,"🟡")

def _normalize_insuff_block(t: str) -> str:
    # Fix typos + collapse duplicates
    t = _RE_IINSUFF.sub("Insufficient", t)
    t = _RE_NSUFF_GLUE.sub(lambda m: m.group(1), t)
    # If no explicit On-chain block in the same message -> pure Insufficient mode everywhere
    if _RE_INSUFF.search(t) and not _RE_ONCHAIN_HDR.search(t):
        t = _RE_RISK_LINE.sub("MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t)
        t = _RE_TRUST_LINE.sub("Trust verdict: MEDIUM RISK 🟡 • Insufficient data (run 🧪 On-chain)", t)
        t = _RE_SCORE_INLINE.sub("", t)
    return t

def _force_not_tradable(t: str) -> str:
    if _RE_NOTTRAD.search(t) or _RE_NOPOOLS.search(t):
        score = 80; label="HIGH RISK"; em="🔴"
        t = _RE_RISK_LINE.sub(f"{label} {em} • Risk score: {score}/100", t)
        # Trust may occasionally carry a wrong "Risk score: 60/100" — replace trust line entirely:
        t = _RE_TRUST_LINE.sub(f"Trust verdict: {label} {em} • NOT TRADABLE (no active pools/liquidity)", t)
        t = _RE_SCORE_INLINE.sub(f"(score {score}/100)", t)
        # Cleanup duplicates
        t = _RE_NOTR_GLUE.sub(lambda m: m.group(1), t)
    return t

def _align_numeric_bucket(t: str) -> str:
    m = _RE_RISK_LINE.search(t)
    if not m:
        return t
    try:
        score = int(m.group("score"))
    except Exception:
        score = 60
    label = _bucket(score); em = _emoji(label)
    t = _RE_RISK_LINE.sub(f"{label} {em} • Risk score: {score}/100", t)
    t = _RE_SCORE_INLINE.sub(f"(score {score}/100)", t)
    if not _RE_INSUFF.search(t) or _RE_ONCHAIN_HDR.search(t):
        # Only align Trust when не в Insufficient-режиме без On-chain
        t = _RE_TRUST_LINE.sub(f"Trust verdict: {label} {em} • Risk score: {score}/100 (lower = safer)", t)
    # Classic bug LOW 60/100
    t = _RE_LOW60.sub("CAUTION 🟡 • Risk score: 60/100", t)
    return t

def _fix_broken_tokens(t: str) -> str:
    # "nals:" → "⚠️ Signals:"
    t = _RE_BROKEN_NALS.sub("\\n⚠️ Signals:", t)
    # LP-lite mismatch
    if _RE_LPLITE_EOA.search(t) and _RE_LPLITE_CONTRACT.search(t):
        t = _RE_LPLITE_EOA.sub("Verdict: 🟡 mixed (contract/custodian holds LP)", t)
    return t

def normalize(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return text
    t = str(text)

    # 1) Insufficient mode handling
    t = _normalize_insuff_block(t)

    # 2) NOT TRADABLE / No pools override
    t = _force_not_tradable(t)

    # 3) General bucket alignment
    t = _align_numeric_bucket(t)

    # 4) Token-level fixes & cosmetics
    t = _fix_broken_tokens(t)

    return t
