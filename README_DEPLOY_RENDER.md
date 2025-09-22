# MetridexBot — Render Deploy Guide (Server 2025-09-22T16:44:10Z)

## 1) Create a Web Service on Render
- **Runtime:** Python 3.11+
- **Build Command:** *empty* (Render will install from `requirements.txt` if present)
- **Start Command:** `gunicorn server:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`

> If your app file is not `server.py`, adjust the module path accordingly (e.g. `app:app`).

## 2) Required Environment Variables
Set these in **Render → Environment** _(Names must match exactly)_:
```
TELEGRAM_TOKEN=***your bot token***
WEBHOOK_SECRET=***random strong string***
WEBHOOK_HEADER_SECRET=***another strong string***
ADMIN_CHAT_ID=***your numeric Telegram chat id***
ADMIN_SECRET=***admin key to access admin endpoints***
BOT_USERNAME=MetridexBot
```

### Networking & Data
```
USAGE_PATH=./usage.json
CACHE_TTL_SECONDS=600
HTTP_TIMEOUT=6.0
KNOWN_AUTORELOAD_SEC=300
```

### Price & Limits (defaults shown)
```
FREE_LIFETIME=2
SLOW_LANE_MS_FREE=3000
PRO_MONTHLY=29
TEAMS_MONTHLY=99
DAY_PASS=9
DEEP_REPORT=3
PRO_OVERAGE_PER_100=5
```

### On‑chain / Data Sources
```
# A) Preferred: single JSON defining per‑chain RPCs
RPC_URLS={"eth":"https://eth.llamarpc.com","bsc":"https://bsc-dataseed.binance.org","polygon":"https://polygon-rpc.com"}

# B) Or explicit per‑chain legacy keys (server supports both)
ETH_RPC_URL=https://eth.llamarpc.com
BSC_RPC_URL=https://bsc-dataseed.binance.org
BNB_RPC_URL=https://bsc-dataseed.binance.org
POLYGON_RPC_URL=https://polygon-rpc.com
ETH_RPC_URLS=
```

### DexScreener / Candles (optional; keep blank unless using a proxy/worker)
```
DEX_BASE=
DEX_CANDLES_BASE=
USER_AGENT=MetridexBot/1.0
```

### Domain Meta (Wayback/SSL/RDAP caches)
```
DOMAIN_META_TTL=2592000
DOMAIN_META_TTL_NEG=120
KNOWN_DOMAINS_FILE_PATH=/opt/render/project/src/known_domains.json
```

### Risk Thresholds (optional overrides)
```
RISK_THRESH_HIGH=85
RISK_THRESH_CAUTION=55
RISK_VOL_LOW=50000
RISK_POSITIVE_LIQ=1000000
RISK_POSITIVE_AGE_Y=3
TOPH_TTL=21600
TEAMFINANCE_LOCKERS_JSON=
```

## 3) Deploy & Health Check
- Deploy the service and open **/healthz**. You should see:
  ```json
  {"ok": true, "version": "..."}
  ```

## 4) Set Telegram Webhook
Replace placeholders and run from any terminal:
```bash
TOKEN="***"
BASE="https://<your-render-service>.onrender.com"
HDR="***WEBHOOK_HEADER_SECRET***"
WH="***WEBHOOK_SECRET***"

curl -s "https://api.telegram.org/bot$TOKEN/setWebhook"   -d "url=$BASE/webhook/$WH"   -d "allowed_updates[]=message"   -d "allowed_updates[]=callback_query"   -H "X-Webhook-Header-Secret: $HDR"
# Expect: {"ok":true,"result":true,"description":"Webhook was set"}
```

## 5) Optional Admin Endpoints
- `GET /version` – shows app version and basic env sanity.
- `GET /limits_preview` – preview of current free/limit settings.
- `POST /reload_meta` or `GET /admin/reload_meta` – refresh domain caches.
- `GET /admin/clear_meta` – clear domain caches.
- `GET /admin/diag` – diagnostic info.

> Protect admin endpoints at the ingress (e.g., with Render Team IP allowlists) and never leak secrets.

## 6) Common Pitfalls
- **Missing RPCs →** on-chain section shows “Contract code: absent”. Ensure `RPC_URLS` or per‑chain RPC vars are set and reachable.
- **Old callbacks →** Telegram doesn’t guarantee old inline buttons after restarts. New messages will contain valid callbacks.
- **DexScreener 403 →** set a Cloudflare Worker proxy and put its URL in `DEX_BASE`.
- **Double reports →** the server de‑duplicates reports within short time windows by chat+file; don’t spam the button.