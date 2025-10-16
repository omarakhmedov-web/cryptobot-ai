
"""
webintel_country_fix_v1.py — SAFE9e helper
Infer country string ("United States", "Germany", etc.) from website intel dicts.
No network; pure extraction & normalization.

Public API:
    infer_country(meta: dict) -> str | None
        Expects meta with possible keys:
            - rdap (dict)
            - ssl (dict)
            - whois_text (str) or whois (dict-like)
    country_label(country: str | None) -> str
        Returns "Country: <Name>" or "Country: n/a"

Integration example (pseudo):
    from webintel_country_fix_v1 import infer_country, country_label
    country = infer_country(site_meta)
    line = country_label(country)
"""

from typing import Any, Dict, Iterable, Optional

# Minimal mapping for common ISO alpha-2 -> full names
_ISO2_MAP = {
    "US": "United States",
    "GB": "United Kingdom",
    "DE": "Germany",
    "FR": "France",
    "NL": "Netherlands",
    "SE": "Sweden",
    "NO": "Norway",
    "FI": "Finland",
    "DK": "Denmark",
    "IS": "Iceland",
    "CH": "Switzerland",
    "IT": "Italy",
    "ES": "Spain",
    "PT": "Portugal",
    "PL": "Poland",
    "EE": "Estonia",
    "LV": "Latvia",
    "LT": "Lithuania",
    "CZ": "Czechia",
    "SK": "Slovakia",
    "HU": "Hungary",
    "RO": "Romania",
    "BG": "Bulgaria",
    "IE": "Ireland",
    "CA": "Canada",
    "AU": "Australia",
    "NZ": "New Zealand",
    "AE": "United Arab Emirates",
    "SA": "Saudi Arabia",
    "TR": "Türkiye",
    "IN": "India",
    "SG": "Singapore",
    "HK": "Hong Kong",
    "JP": "Japan",
    "KR": "South Korea",
    "CN": "China",
    "TW": "Taiwan",
    "RU": "Russia",
    "UA": "Ukraine",
    "BY": "Belarus",
    "KZ": "Kazakhstan",
    "AZ": "Azerbaijan",
    "AM": "Armenia",
    "GE": "Georgia",
    "BR": "Brazil",
    "AR": "Argentina",
    "MX": "Mexico",
    "ZA": "South Africa"
}

def _coalesce(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str):
            v = v.strip()
        if v:
            return v
    return None

def _normalize_country(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    s = str(val).strip()
    if s in {"—", "-", "n/a", "N/A", "NA"}:
        return None
    # Allow alpha-2 code
    if len(s) == 2 and s.isalpha():
        s = s.upper()
        return _ISO2_MAP.get(s, s)
    # Title-case common names, keep acronyms
    if s.isupper() and len(s) <= 3:
        return s
    # Basic cleanup: collapse spaces
    s = " ".join(s.split())
    # Fix common vendor strings
    s = s.replace("United States of America", "United States")
    return s

def _extract_from_rdap(rdap: Dict[str, Any]) -> Optional[str]:
    if not isinstance(rdap, dict):
        return None
    # Direct fields
    country = _coalesce(rdap.get("country"), rdap.get("countryCode"))
    country = _normalize_country(country)
    if country:
        return country
    # Entities -> vcardArray
    entities = rdap.get("entities") or []
    for ent in entities:
        vcard = ent.get("vcardArray")
        if isinstance(vcard, (list, tuple)) and len(vcard) >= 2:
            props = vcard[1]
            for p in props:
                try:
                    if p[0] == "adr":
                        # vCard ADR is ["adr", {...}, ["", "", "locality", "region", "postcode", "country"]]
                        adr = p[3] if len(p) >= 4 else None
                        if isinstance(adr, (list, tuple)) and adr:
                            # Last slot is typically country name/code
                            c = adr[-1]
                            c = _normalize_country(c)
                            if c:
                                return c
                except Exception:
                    continue
    # notices -> description may contain CC
    notices = rdap.get("notices") or []
    for n in notices:
        desc = n.get("description")
        if isinstance(desc, list):
            for line in desc:
                m = re.search(r"\b([A-Z]{2})\b", str(line))
                if m:
                    c = _normalize_country(m.group(1))
                    if c:
                        return c
    return None

def _extract_from_ssl(ssl: Dict[str, Any]) -> Optional[str]:
    if not isinstance(ssl, dict):
        return None
    # Look into subject / issuer fields like "C=US, ST=..., O=..."
    def _scan_dn(dn: str) -> Optional[str]:
        m = re.search(r"(?:^|[,/])\s*C\s*=\s*([A-Za-z]{2})(?:[,/]|$)", dn)
        if m:
            return _normalize_country(m.group(1))
        return None
    subj = ssl.get("subject") or ssl.get("subject_dn")
    if isinstance(subj, str):
        c = _scan_dn(subj)
        if c: return c
    iss = ssl.get("issuer") or ssl.get("issuer_dn")
    if isinstance(iss, str):
        c = _scan_dn(iss)
        if c: return c
    return None

def _extract_from_whois(whois: Any) -> Optional[str]:
    if whois is None:
        return None
    text = None
    if isinstance(whois, str):
        text = whois
    elif isinstance(whois, dict):
        # common keys
        text = _coalesce(whois.get("raw"), whois.get("text"))
        if not text:
            # stitch some fields
            parts = []
            for k in ("registrant_country", "country", "Registrant Country", "Registrant Country Code"):
                v = whois.get(k)
                if v:
                    parts.append(f"{k}: {v}")
            text = "\n".join(parts) if parts else None
    if not text:
        return None
    # Try explicit fields first
    for pat in (
        r"(?i)\bRegistrant Country(?: Code)?:\s*([A-Za-z]{2,})",
        r"(?i)\bCountry:\s*([A-Za-z]{2,})"
    ):
        m = re.search(pat, text)
        if m:
            c = _normalize_country(m.group(1))
            if c:
                return c
    return None

def infer_country(meta: Dict[str, Any]) -> Optional[str]:
    if not isinstance(meta, dict):
        return None
    rdap = meta.get("rdap")
    ssl = meta.get("ssl")
    whois = meta.get("whois") or meta.get("whois_text")
    # Priority: RDAP -> SSL -> WHOIS
    return _coalesce(
        _extract_from_rdap(rdap),
        _extract_from_ssl(ssl),
        _extract_from_whois(whois),
    )

def country_label(country: Optional[str]) -> str:
    return f"Country: {country}" if country else "Country: n/a"
