#!/usr/bin/env python3
"""
tg_webhook_tools_secure.py — Webhook helper with Telegram secret_token support.
ENV (all read at runtime):
  BOT_TOKEN (required)
  PUBLIC_URL (required)
  BOT_WEBHOOK_SECRET (required) — used in URL path
  WEBHOOK_HEADER_SECRET (optional) — if set, will be used as Telegram secret_token;
                                     otherwise we use BOT_WEBHOOK_SECRET as secret_token.
Usage:
  python tg_webhook_tools_secure.py getme
  python tg_webhook_tools_secure.py info
  python tg_webhook_tools_secure.py set      # sets url + secret_token
  python tg_webhook_tools_secure.py delete
"""
import os, sys, json, urllib.request as _r

def _env(k, required=False):
    v = (os.getenv(k, "") or "").strip()
    if required and not v:
        print(f"[ERR] Missing env: {k}", file=sys.stderr)
        sys.exit(2)
    return v

def _api_call(token, method, params=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = None
    if params is not None:
        data = json.dumps(params).encode("utf-8")
    req = _r.Request(url, data=data, headers={"Content-Type":"application/json"})
    with _r.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode("utf-8","ignore")
        try:
            return json.loads(raw)
        except Exception:
            return {"ok": False, "raw": raw}

def cmd_getme():
    token = _env("BOT_TOKEN", True)
    print(json.dumps(_api_call(token, "getMe"), ensure_ascii=False, indent=2))

def cmd_info():
    token = _env("BOT_TOKEN", True)
    print(json.dumps(_api_call(token, "getWebhookInfo"), ensure_ascii=False, indent=2))

def cmd_set():
    token = _env("BOT_TOKEN", True)
    base  = _env("PUBLIC_URL", True).rstrip("/")
    sec   = _env("BOT_WEBHOOK_SECRET", True)
    header = (os.getenv("WEBHOOK_HEADER_SECRET","") or sec).strip()
    url = f"{base}/webhook/{sec}"
    params = {"url": url, "secret_token": header, "max_connections": 40, "drop_pending_updates": False}
    resp = _api_call(token, "setWebhook", params)
    out = {"request": {"url": url[:-len(sec)] + "***", "secret_token": "***"}, "response": resp}
    print(json.dumps(out, ensure_ascii=False, indent=2))

def cmd_delete():
    token = _env("BOT_TOKEN", True)
    print(json.dumps(_api_call(token, "deleteWebhook", {"drop_pending_updates": False}), ensure_ascii=False, indent=2))

def main():
    if len(sys.argv) < 2:
        print("Usage: python tg_webhook_tools_secure.py [getme|info|set|delete]")
        sys.exit(2)
    cmd = sys.argv[1].lower()
    if cmd == "getme": return cmd_getme()
    if cmd == "info": return cmd_info()
    if cmd == "set": return cmd_set()
    if cmd == "delete": return cmd_delete()
    print("Unknown command", cmd, file=sys.stderr); sys.exit(2)

if __name__ == "__main__":
    main()
