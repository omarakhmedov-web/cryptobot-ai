# server_feedback_patched_httpmail.py
# Feedback API with dual delivery:
#  - SMTP (if reachable)  OR
#  - HTTP Email API providers (SendGrid, Brevo, Mailgun, Postmark)
# Includes diagnostics for quick testing.
import os, time, smtplib, socket, json as _json, base64, urllib.request
from email.message import EmailMessage
from flask import Flask, request, jsonify, Response

try:
    app  # type: ignore
except NameError:
    app = Flask(__name__)

# Try to reuse an existing tg_send_message(token, chat_id, text, logger=None)
try:
    _tg_send = tg_send_message  # type: ignore
except Exception:
    _tg_send = None

# CORS / ENV
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "https://metridex.com,https://www.metridex.com").split(",") if o.strip()]
_FEEDBACK_TO    = os.getenv("FEEDBACK_TO", os.getenv("CONTACT_EMAIL", "contact@metridex.com")).strip()
_FEEDBACK_SUBJ  = os.getenv("FEEDBACK_SUBJECT_PREFIX","[Metridex.Help] ").strip()
_RATE_TTL       = int(os.getenv("FEEDBACK_RATE_LIMIT_SEC","60") or "60")
_TG_CHAT        = os.getenv("TELEGRAM_FEEDBACK_CHAT_ID", os.getenv("ADMIN_CHAT_ID","")).strip()
_TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN","").strip()
_DEBUG_TOKEN    = os.getenv("DEBUG_FEEDBACK_TOKEN","").strip()

# SMTP (may be blocked by hosting)
_SMTP_HOST      = os.getenv("SMTP_HOST","").strip()
_SMTP_PORT      = int(os.getenv("SMTP_PORT","587") or "587")
_SMTP_USER      = os.getenv("SMTP_USER","").strip()
_SMTP_PASS      = os.getenv("SMTP_PASS","").strip()
_SMTP_FROM      = os.getenv("SMTP_FROM", _SMTP_USER or "no-reply@metridex.com").strip()
_SMTP_STARTTLS  = (os.getenv("SMTP_STARTTLS","1") or "1").lower() not in ("0","false","no")
_SMTP_SSL_FALLBACK = (os.getenv("SMTP_SSL_FALLBACK","1") or "1").lower() not in ("0","false","no")

# HTTP Email APIs (any one is enough)
SENDGRID_API_KEY   = os.getenv("SENDGRID_API_KEY","").strip()
BREVO_API_KEY      = os.getenv("BREVO_API_KEY","").strip()           # formerly Sendinblue
MAILGUN_API_KEY    = os.getenv("MAILGUN_API_KEY","").strip()
MAILGUN_DOMAIN     = os.getenv("MAILGUN_DOMAIN","").strip()
POSTMARK_API_TOKEN = os.getenv("POSTMARK_API_TOKEN","").strip()

_FEED_RL = {}  # ip->ts
_last_mail_path = None
_last_mail_err  = None

def _origin_ok(req):
    o = (req.headers.get("Origin") or "").strip()
    if not o:
        return True
    for a in _ALLOWED_ORIGINS:
        if a == "*" or o.startswith(a):
            return True
    return False

def _with_cors(resp):
    try:
        o = request.headers.get("Origin") or "*"
        if _origin_ok(request):
            resp.headers["Access-Control-Allow-Origin"] = o
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS, GET"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    except Exception:
        pass
    return resp

# ---------- Mail senders ----------
def _smtp_reachable(host: str, port: int, timeout=5) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try: sock.close()
        except Exception: pass
        return True
    except Exception:
        return False

def _send_via_smtp(to_addr: str, subject: str, body: str) -> bool:
    global _last_mail_path, _last_mail_err
    _last_mail_path = "smtp"
    _last_mail_err  = None
    if not (_SMTP_HOST and to_addr):
        _last_mail_err = "smtp_not_configured"
        return False
    # Try 587 then 465
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _SMTP_FROM
    msg["To"] = to_addr
    msg.set_content(body)
    try:
        if _smtp_reachable(_SMTP_HOST, _SMTP_PORT):
            s = smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=15)
            try:
                if _SMTP_STARTTLS:
                    s.starttls()
                if _SMTP_USER:
                    s.login(_SMTP_USER, _SMTP_PASS)
                s.send_message(msg)
                return True
            finally:
                try: s.quit()
                except Exception: pass
        if _SMTP_SSL_FALLBACK and _smtp_reachable(_SMTP_HOST, 465):
            s2 = smtplib.SMTP_SSL(_SMTP_HOST, 465, timeout=15)
            try:
                if _SMTP_USER:
                    s2.login(_SMTP_USER, _SMTP_PASS)
                s2.send_message(msg)
                return True
            finally:
                try: s2.quit()
                except Exception: pass
        _last_mail_err = "smtp_unreachable"
        return False
    except smtplib.SMTPResponseException as e:
        _last_mail_err = f"smtp_code={getattr(e,'smtp_code',None)} msg={(getattr(e,'smtp_error',b'') or b'').decode('utf-8','ignore')}"
        try: app.logger.error(f"feedback: {_last_mail_err}")
        except Exception: pass
        return False
    except Exception as e:
        _last_mail_err = f"smtp_exception:{e}"
        try: app.logger.exception("feedback: SMTP failed")
        except Exception: pass
        return False

def _http_post(url: str, headers: dict, data: dict) -> (bool, str):
    req = urllib.request.Request(url, data=_json.dumps(data).encode("utf-8"),
                                 headers={"Content-Type":"application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            body   = resp.read().decode("utf-8","ignore")
            return (200 <= status < 300), f"{status}:{body}"
    except Exception as e:
        return False, f"error:{e}"

def _send_via_sendgrid(to_addr: str, subject: str, body: str) -> bool:
    global _last_mail_path, _last_mail_err
    _last_mail_path = "sendgrid"
    if not SENDGRID_API_KEY: 
        _last_mail_err = "sendgrid_key_missing"; return False
    payload = {
        "personalizations":[{"to":[{"email": to_addr}]}],
        "from":{"email": _SMTP_FROM},
        "subject": subject,
        "content":[{"type":"text/plain","value": body}]
    }
    ok, info = _http_post("https://api.sendgrid.com/v3/mail/send",
                          {"Authorization": f"Bearer {SENDGRID_API_KEY}"}, payload)
    _last_mail_err = None if ok else info
    return ok

def _send_via_brevo(to_addr: str, subject: str, body: str) -> bool:
    global _last_mail_path, _last_mail_err
    _last_mail_path = "brevo"
    if not BREVO_API_KEY: 
        _last_mail_err = "brevo_key_missing"; return False
    payload = {
        "sender": {"email": _SMTP_FROM},
        "to": [{"email": to_addr}],
        "subject": subject,
        "textContent": body
    }
    ok, info = _http_post("https://api.brevo.com/v3/smtp/email",
                          {"api-key": BREVO_API_KEY}, payload)
    _last_mail_err = None if ok else info
    return ok

def _send_via_mailgun(to_addr: str, subject: str, body: str) -> bool:
    global _last_mail_path, _last_mail_err
    _last_mail_path = "mailgun"
    if not (MAILGUN_API_KEY and MAILGUN_DOMAIN):
        _last_mail_err = "mailgun_key_or_domain_missing"; return False
    # Mailgun uses form-encoded or basic auth; we will use JSON via API v3/messages with basic auth
    # Build basic auth header
    token = base64.b64encode(f"api:{MAILGUN_API_KEY}".encode()).decode()
    payload = {
        "from": _SMTP_FROM,
        "to": [to_addr],
        "subject": subject,
        "text": body
    }
    # Mailgun JSON endpoint (may require form-encoded on some regions; this works on many)
    ok, info = _http_post(f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                          {"Authorization": f"Basic {token}"}, payload)
    _last_mail_err = None if ok else info
    return ok

def _send_via_postmark(to_addr: str, subject: str, body: str) -> bool:
    global _last_mail_path, _last_mail_err
    _last_mail_path = "postmark"
    if not POSTMARK_API_TOKEN:
        _last_mail_err = "postmark_token_missing"; return False
    payload = {
        "From": _SMTP_FROM,
        "To": to_addr,
        "Subject": subject,
        "TextBody": body
    }
    ok, info = _http_post("https://api.postmarkapp.com/email",
                          {"X-Postmark-Token": POSTMARK_API_TOKEN}, payload)
    _last_mail_err = None if ok else info
    return ok

def _send_email(to_addr: str, subject: str, body: str) -> (bool, str):
    """Try SMTP first (if reachable), else fall back to HTTP Email APIs (SendGrid, Brevo, Mailgun, Postmark)."""
    # 1) SMTP if ports open
    if _SMTP_HOST:
        if _send_via_smtp(to_addr, subject, body):
            return True, "smtp"
    # 2) HTTP APIs in order (whichever is configured)
    for fn in (_send_via_sendgrid, _send_via_brevo, _send_via_mailgun, _send_via_postmark):
        ok = fn(to_addr, subject, body)
        if ok: 
            return True, _last_mail_path or "api"
    return False, _last_mail_err or "no_email_provider_configured"

# ---------- Telegram ----------
def _send_telegram(text: str) -> bool:
    try:
        if not (_tg_send and _TG_CHAT and _TELEGRAM_TOKEN):
            return False
        _tg_send(_TELEGRAM_TOKEN, _TG_CHAT, text, logger=app.logger)
        return True
    except Exception:
        try: app.logger.exception("feedback: telegram failed")
        except Exception: pass
        return False

# ---------- Routes ----------
@app.route("/api/feedback", methods=["POST","OPTIONS"])
def feedback_api():
    if request.method == "OPTIONS":
        return _with_cors(Response(status=204))

    if not _origin_ok(request):
        return _with_cors(jsonify(ok=False, error="origin_forbidden")), 403

    # rate limit
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0"
    now = time.time()
    if now - _FEED_RL.get(ip, 0) < _RATE_TTL:
        return _with_cors(jsonify(ok=False, error="rate_limited")), 429
    _FEED_RL[ip] = now

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()[:200]
    subj  = (data.get("subject") or "").strip()[:200]
    msg   = (data.get("message") or "").strip()[:4000]
    if not msg:
        return _with_cors(jsonify(ok=False, error="message_required")), 400

    site = request.headers.get("Origin") or request.headers.get("Referer") or ""
    ua = request.headers.get("User-Agent") or ""
    subject = f"{_FEEDBACK_SUBJ}{subj or 'New message'}"
    body    = f"From: {email or 'anonymous'}\nIP: {ip}\nSite: {site}\nUA: {ua}\n\n{msg}"

    ok_email, path = _send_email(_FEEDBACK_TO, subject, body)
    ok_tg    = _send_telegram(f"✉️ Feedback\n{subj or 'New message'}\nfrom: {email or 'anonymous'}\nIP: {ip}\n\n{msg[:1800]}")

    resp = {"ok": True, "email": bool(ok_email), "email_path": path, "telegram": bool(ok_tg)}
    if not ok_email:
        resp["email_error"] = _last_mail_err
    return _with_cors(jsonify(resp))

@app.get("/api/feedback/ping")
def feedback_ping():
    return jsonify(ok=True, ts=int(time.time()))

# Diagnostics
@app.get("/api/feedback/_mail_api_diag")
def feedback_mail_api_diag():
    if not _DEBUG_TOKEN or request.args.get("token") != _DEBUG_TOKEN:
        return _with_cors(jsonify(ok=False, error="forbidden")), 403
    ok, path = _send_email(_FEEDBACK_TO, f"{_FEEDBACK_SUBJ}[API Diag]", "Diagnostic test via API/SMTP")
    return _with_cors(jsonify(ok=bool(ok), path=path, error=_last_mail_err,
                              have={"sendgrid": bool(SENDGRID_API_KEY),
                                    "brevo": bool(BREVO_API_KEY),
                                    "mailgun": bool(MAILGUN_API_KEY and MAILGUN_DOMAIN),
                                    "postmark": bool(POSTMARK_API_TOKEN)}))
