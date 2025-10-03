# server_feedback_patched_diag.py
# Same feedback API, plus:
#  - richer SMTP logging (codes & messages)
#  - protected diag endpoint /api/feedback/_smtp_diag?token=... for one-off tests
import os, time, smtplib, json as _json
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

_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "https://metridex.com,https://www.metridex.com").split(",") if o.strip()]
_SMTP_HOST      = os.getenv("SMTP_HOST","").strip()
_SMTP_PORT      = int(os.getenv("SMTP_PORT","587") or "587")
_SMTP_USER      = os.getenv("SMTP_USER","").strip()
_SMTP_PASS      = os.getenv("SMTP_PASS","").strip()
_SMTP_FROM      = os.getenv("SMTP_FROM", _SMTP_USER or "no-reply@metridex.com").strip()
_SMTP_STARTTLS  = (os.getenv("SMTP_STARTTLS","1") or "1").lower() not in ("0","false","no")
_FEEDBACK_TO    = os.getenv("FEEDBACK_TO", os.getenv("CONTACT_EMAIL", "contact@metridex.com")).strip()
_FEEDBACK_SUBJ  = os.getenv("FEEDBACK_SUBJECT_PREFIX","[Metridex.Help] ").strip()
_RATE_TTL       = int(os.getenv("FEEDBACK_RATE_LIMIT_SEC","60") or "60")
_TG_CHAT        = os.getenv("TELEGRAM_FEEDBACK_CHAT_ID", os.getenv("ADMIN_CHAT_ID","")).strip()
_TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN","").strip()
_DEBUG_TOKEN    = os.getenv("DEBUG_FEEDBACK_TOKEN","").strip()

_FEED_RL = {}  # ip->ts

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

_last_smtp_err = None  # (code:int|None, msg:str|None)

def _send_email(to_addr: str, subject: str, body: str) -> bool:
    global _last_smtp_err
    _last_smtp_err = None
    if not (_SMTP_HOST and to_addr):
        _last_smtp_err = (None, "smtp_not_configured")
        return False
    try:
        s = smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=15)
        try:
            if _SMTP_STARTTLS:
                s.starttls()
            if _SMTP_USER:
                s.login(_SMTP_USER, _SMTP_PASS)
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = _SMTP_FROM
            msg["To"] = to_addr
            msg.set_content(body)
            s.send_message(msg)
            return True
        finally:
            try: s.quit()
            except Exception: pass
    except smtplib.SMTPResponseException as e:
        _last_smtp_err = (int(getattr(e, "smtp_code", 0) or 0), (getattr(e, "smtp_error", b"") or b"").decode("utf-8","ignore"))
        try: app.logger.error(f"feedback: SMTP failed code={_last_smtp_err[0]} msg={_last_smtp_err[1]}")
        except Exception: pass
        return False
    except Exception as e:
        _last_smtp_err = (None, str(e))
        try: app.logger.exception("feedback: SMTP failed (generic)")
        except Exception: pass
        return False

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

    ok_email = _send_email(_FEEDBACK_TO, subject, body)
    ok_tg    = _send_telegram(f"✉️ Feedback\n{subj or 'New message'}\nfrom: {email or 'anonymous'}\nIP: {ip}\n\n{msg[:1800]}")

    return _with_cors(jsonify(ok=True, email=bool(ok_email), telegram=bool(ok_tg)))

@app.get("/api/feedback/ping")
def feedback_ping():
    return jsonify(ok=True, ts=int(time.time()))

# Protected SMTP diag (on-demand). Use only with a token you set in env DEBUG_FEEDBACK_TOKEN.
@app.get("/api/feedback/_smtp_diag")
def feedback_smtp_diag():
    if not _DEBUG_TOKEN or request.args.get("token") != _DEBUG_TOKEN:
        return _with_cors(jsonify(ok=False, error="forbidden")), 403
    subject = f"{_FEEDBACK_SUBJ}[Diag]"
    body    = "Diagnostic test"
    ok = _send_email(_FEEDBACK_TO, subject, body)
    code, msg = (None, None)
    if not ok and isinstance(globals().get("_last_smtp_err"), tuple):
        code, msg = _last_smtp_err
    return _with_cors(jsonify(ok=bool(ok), smtp_code=code, smtp_err=msg,
                              host=_SMTP_HOST, user=_SMTP_USER, from_addr=_SMTP_FROM, to=_FEEDBACK_TO))
