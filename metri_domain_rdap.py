"""
metri_domain_rdap.py — RDAP/WHOIS hardening for Metridex QuickScan

Env (optional):
  RDAP_TIMEOUT_MS=2500
  RDAP_RETRIES=2
  RDAP_BASE=<override base RDAP endpoint>
  RDAP_BOOTSTRAP_TTL=86400
  RDAP_CACHE_TTL=900
  WHOIS_ENABLE=0  (reserved, port 43 not used by default)

Public API:
  _rdap(domain) -> (handle, created_iso, registrar)
  domain_meta(domain, ssl_fn=None, wayback_fn=None) -> dict
  render_domain_block(body_text, domain, ssl_fn=None, wayback_fn=None) -> new_text
"""

import os, time, json, re
from typing import Tuple, Optional

try:
    import idna as _idna
except Exception:
    _idna = None

try:
    import requests
except Exception:  # fallback shim
    requests = None  # type: ignore

# caches
_RDAP_BOOTSTRAP = {"t": 0, "data": {}}
_RDAP_BOOTSTRAP_TTL = int(os.environ.get("RDAP_BOOTSTRAP_TTL", "86400") or "86400")
_RDAP_CACHE = {}
_RDAP_CACHE_TTL = int(os.environ.get("RDAP_CACHE_TTL", "900") or "900")


def _now() -> int:
    try:
        return int(time.time())
    except Exception:
        return 0


def _punycode(d: str) -> str:
    d = (d or "").strip().lower()
    if not d:
        return d
    try:
        return _idna.encode(d).decode("ascii") if _idna else d.encode("idna").decode("ascii")
    except Exception:
        return d


def _rdap_bootstrap_server(tld: str) -> Optional[str]:
    """Get RDAP base for a TLD via IANA bootstrap."""
    try:
        if requests is None:
            return None
        tld = (tld or "").lower().lstrip(".")
        now = _now()
        ent = _RDAP_BOOTSTRAP
        if now - ent.get("t", 0) > _RDAP_BOOTSTRAP_TTL or not ent.get("data"):
            r = requests.get(
                "https://data.iana.org/rdap/dns.json",
                timeout=float(os.environ.get("RDAP_TIMEOUT_MS","2500"))/1000.0,
                headers={"User-Agent": os.getenv("USER_AGENT","MetridexBot/1.0")},
            )
            if r.status_code == 200:
                ent["data"] = r.json() or {}
                ent["t"] = now
        svc = ((ent.get("data") or {}).get("services") or [])
        for rec in svc:
            names, urls = rec[0], rec[1] if isinstance(rec, list) and len(rec) >= 2 else ([], [])
            if tld in (names or []):
                for u in urls or []:
                    if isinstance(u, str) and u.startswith("https://"):
                        return u.rstrip("/")
                if urls:
                    return str(urls[0]).rstrip("/")
        return None
    except Exception:
        return None


def _rdap_fetch_json(urls, domain, timeout_s, retries):
    reason = None
    if requests is None:
        return (None, "requests missing")
    for base in (urls or []):
        for _ in range(max(1, retries)):
            try:
                r = requests.get(f"{base}/domain/{domain}", timeout=timeout_s,
                                 headers={"User-Agent": os.getenv("USER_AGENT","MetridexBot/1.0")})
                if r.status_code == 200:
                    return (r.json() or {}, None)
                reason = f"RDAP {r.status_code}"
            except requests.Timeout:
                reason = "RDAP timeout"
            except Exception as e:
                reason = f"RDAP error: {e.__class__.__name__}"
        # next base
    return (None, reason or "RDAP error")


def _rdap(domain: str) -> Tuple[str, str, str]:
    """
    Hardened RDAP resolver.
    Returns (handle_or_reason, created_iso_or_—, registrar_or_—).
    """
    try:
        d = (domain or "").strip().lower()
        if not d or "." not in d:
            return ("N/A (invalid domain)", "—", "—")
        d_enc = _punycode(d)
        now = _now()
        ent = _RDAP_CACHE.get(d_enc)
        if ent and now - ent.get("t", 0) < _RDAP_CACHE_TTL:
            return ent["h"], ent["created"], ent["reg"]

        timeout_s = float(os.environ.get("RDAP_TIMEOUT_MS","2500"))/1000.0
        retries = int(os.environ.get("RDAP_RETRIES","2") or "2")

        bases = []
        env_base = (os.environ.get("RDAP_BASE","") or "").strip().rstrip("/")
        if env_base:
            bases.append(env_base)
        b = _rdap_bootstrap_server(d_enc.rsplit(".",1)[-1])
        if b and b not in bases:
            bases.append(b)
        if "https://rdap.org" not in bases:
            bases.append("https://rdap.org")

        js, reason = _rdap_fetch_json(bases, d_enc, timeout_s, retries)
        if not isinstance(js, dict):
            h = f"N/A ({reason})" if reason else "—"
            created = "—"; registrar = "—"
        else:
            h = js.get("handle") or "—"
            created = "—"
            for ev in (js.get("events") or []):
                if ev.get("eventAction") == "registration":
                    created = ev.get("eventDate", "—"); break
            registrar = "—"
            for ent in (js.get("entities") or []):
                roles = ent.get("roles") or []
                if "registrar" in roles:
                    v = ent.get("vcardArray")
                    if isinstance(v, list) and len(v) == 2:
                        for item in v[1]:
                            if item and item[0] == "fn":
                                registrar = item[3]; break
        _RDAP_CACHE[d_enc] = {"t": now, "h": h, "created": created, "reg": registrar}
        return (h, created, registrar)
    except Exception as e:
        return (f"N/A (RDAP error: {e.__class__.__name__})", "—", "—")


# Convenience layer compatible with existing formatting
def _normalize_date_iso(iso: str) -> str:
    if not iso or iso == "—":
        return "—"
    try:
        # Expect ISO, trim to date
        return str(iso).split("T",1)[0]
    except Exception:
        return str(iso)


def domain_meta(domain: str, ssl_fn=None, wayback_fn=None) -> dict:
    """Return meta dict for domain using RDAP + optional SSL/Wayback helpers."""
    h, created, reg = _rdap(domain)
    ssl_exp, ssl_issuer = ("—","—")
    if callable(ssl_fn):
        try:
            ssl_exp, ssl_issuer = ssl_fn(domain)
        except Exception:
            pass
    wb = None
    if callable(wayback_fn):
        try:
            wb = wayback_fn(domain)
        except Exception:
            wb = None
    return {
        "handle": h,
        "created": _normalize_date_iso(created),
        "registrar": reg,
        "ssl_expires": ssl_exp,
        "ssl_issuer": ssl_issuer,
        "wayback_first": wb or "—",
        "domain": domain,
    }


def render_domain_block(body_text: str, domain: str, ssl_fn=None, wayback_fn=None) -> str:
    """Replace/append Domain/WHOIS/RDAP/SSL/Wayback lines in a text report."""
    meta = domain_meta(domain, ssl_fn=ssl_fn, wayback_fn=wayback_fn)
    domain_line = f"Domain: {meta['domain']}"
    whois_line  = f"WHOIS/RDAP: {meta['handle']} | Created: {meta['created']} | Registrar: {meta['registrar']}"
    ssl_prefix  = "SSL: OK" if meta['ssl_expires'] and meta['ssl_expires'] != "—" else "SSL: —"
    ssl_line    = f"{ssl_prefix} | Expires: {meta['ssl_expires'] or '—'} | Issuer: {meta['ssl_issuer'] or '—'}"
    wayback_line= f"Wayback: first {meta['wayback_first']}"

    def _replace_or_append(body, label, newline):
        patt = re.compile(rf"(?m)^{re.escape(label)}[^\n]*$")
        if patt.search(body or ""):
            return patt.sub(newline, body)
        if body and not body.endswith("\n"):
            body += "\n"
        return body + newline

    t = body_text or ""
    t = _replace_or_append(t, "Domain:",     domain_line)
    t = _replace_or_append(t, "WHOIS/RDAP:", whois_line)
    t = _replace_or_append(t, "SSL:",        ssl_line)
    t = _replace_or_append(t, "Wayback:",    wayback_line)
    return t
