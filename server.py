# server_0_3_85_anchor37_diag.py
import os, time, hmac, hashlib, base64, json, inspect
from flask import Flask, jsonify, make_response, abort, request

def _b64(x: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(x).decode('ascii').rstrip('=')

def _ub64(s: str) -> bytes:
    import base64
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _sign(secret: str, msg: bytes) -> str:
    import hmac, hashlib
    return _b64(hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest())

def _token_for(addr: str, ttl_min: int, secret: str) -> str:
    import time, json
    exp = int(time.time()) + ttl_min * 60
    payload = json.dumps({'a': addr, 'e': exp, 'n': int(time.time()*1000)}).encode('utf-8')
    sig = _sign(secret, payload)
    return f"{_b64(payload)}.{sig}"

STATE = {}

app = Flask(__name__)

@app.route("/")
def root():
    return f"Metridex server OK :: {time.ctime()} :: ver=0.3.85-anchor37", 200

@app.route("/healthz")
def healthz():
    return jsonify(status="ok", version="0.3.85-anchor37")

@app.route("/debug/env")
def debug_env():
    keys = [
        "SITE_URL", "SHARE_SECRET", "SHARE_TTL_MIN",
        "RENDER_SERVICE_NAME", "PORT"
    ]
    env = {k: ("<set>" if os.getenv(k) else "<unset>") for k in keys}
    return jsonify(env=env, cwd=os.getcwd())

@app.route("/debug/routes")
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(dict(rule=str(rule), methods=sorted(rule.methods)))
    return jsonify(routes=sorted(routes, key=lambda r: r['rule']))

@app.route("/debug/selfshare")
def debug_selfshare():
    addr = request.args.get('addr', '0x831753DD7087CaC61aB5644b308642cc1c33Dc13')
    STATE[addr.lower()] = {
        'html': f"<html><body style='font-family:Arial,sans-serif'><h2>Metridex — sample report</h2><p>Address: {addr}</p><p>Generated: {time.ctime()}</p></body></html>"
    }
    site = os.getenv('SITE_URL', '').rstrip('/')
    ttl = int(os.getenv('SHARE_TTL_MIN', '60'))
    secret = os.getenv('SHARE_SECRET', 'dev-secret-change-me')
    token = _token_for(addr, ttl, secret)
    share_url = f"{site}/r/{token}" if site else f"/r/{token}"
    pdf_url = f"{site}/export/pdf/{addr}" if site else f"/export/pdf/{addr}"
    return jsonify(ok=True, version="0.3.85-anchor37", share_url=share_url, pdf_url=pdf_url,
                   hint="Open these URLs directly. If 404, you're not running this server file or routes missing.")

@app.route("/r/<token>")
def share_render(token):
    secret = os.getenv('SHARE_SECRET', 'dev-secret-change-me')
    try:
        p64, sig = token.split('.', 1)
        payload = _ub64(p64)
    except Exception:
        abort(404)
    if _sign(secret, payload) != sig:
        abort(404)
    try:
        data = json.loads(payload.decode('utf-8'))
    except Exception:
        abort(404)
    if int(data.get('e', 0)) < int(time.time()):
        abort(404)
    addr = str(data.get('a', '')).lower()
    blob = STATE.get(addr)
    if not blob:
        abort(404)
    html = blob.get('html') or f"<html><body><h2>Metridex — report</h2><p>{addr}</p></body></html>"
    resp = make_response(html, 200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route("/export/pdf/<addr>")
def export_pdf(addr):
    blob = STATE.get(addr.lower()) or {}
    html = blob.get('html') or f"<html><body><h2>Metridex — report</h2><p>{addr}</p></body></html>"
    resp = make_response(html, 200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-store'
    return resp

# expose app for gunicorn: gunicorn server:app
