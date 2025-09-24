import importlib
import os
from datetime import datetime, timezone
from flask import redirect, jsonify

# Import existing server module (must be "server.py")
_base = importlib.import_module("server")
app = getattr(_base, "app")
_ready_links = getattr(_base, "_ready_links")

VERSION_PATCH = "0.3.96-p2-sharefix"

@app.get("/version_patch")
def _version_patch():
    return {"version_patch": VERSION_PATCH}

@app.get("/debug/selfshare_html")
def _debug_selfshare_html():
    """
    Smoketest self-share (safe):
    - generates small HTML stub
    - calls _ready_links(addr, html) defined in base server
    - 302 redirects to /r/<token>
    Never crashes to 502: returns 500 text with reason if something goes wrong.
    """
    try:
        addr = "0x831753DD7087Ca61aB5644b308642cc1c33Dc13"  # QUICK (Polygon), stable test address
        html = "<html><body><h1>selfshare smoketest</h1></body></html>"
        links = _ready_links(addr=addr, html=html)  # expected dict: share_url/pdf_url/sample_url
        share_url = links.get("share_url")
        if not share_url:
            raise RuntimeError("share_url is empty (check SITE_URL/SHARE_SECRET)")
        return redirect(share_url, code=302)
    except Exception as e:
        app.logger.exception("selfshare error")
        return (f"selfshare error: {type(e).__name__}: {e}", 500)

@app.get("/debug/share_diag")
def _share_diag():
    """Non-sensitive diagnostics for share settings (no secrets exposed)."""
    try:
        site_url = os.getenv("SITE_URL", "")
        secret_len = len(os.getenv("SHARE_SECRET", ""))
        ttl = os.getenv("SHARE_TTL_MIN", "default")
        skew = os.getenv("SHARE_CLOCK_SKEW_SEC", "default")
        now = datetime.now(timezone.utc).isoformat()
        return jsonify({
            "now_utc": now,
            "site_url_ok": bool(site_url) and not site_url.endswith("/"),
            "share_secret_len": secret_len,
            "share_ttl_min": ttl,
            "share_clock_skew_sec": skew,
            "hint": "site_url must be like https://cryptobot-ai-1.onrender.com (no trailing slash)"
        })
    except Exception as e:
        return (f"share_diag error: {type(e).__name__}: {e}", 500)
