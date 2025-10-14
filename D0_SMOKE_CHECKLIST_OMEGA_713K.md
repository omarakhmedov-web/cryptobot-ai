# Metridex — D0 Smoke Checklist (OMEGA-713K)

**Goal:** Verify clean ENV + basic liveness + 3-token smoke before D1/D2/D3.

## 0) Preconditions
- Runtime: Python 3.11.9
- Start: `gunicorn -w 1 -t 120 server:app`
- ENV allowlist only:
  - Required: `PYTHON_VERSION`, `PUBLIC_URL`, `BOT_TOKEN`, `BOT_WEBHOOK_SECRET`
  - Optional (if used): `PRO_URL`, `TEAMS_URL`, `DAY_PASS_URL`, `JUDGE_*`, `REDIS_URL` (valid URL, **no spaces**)
- Restart the Render service after ENV changes.

## 1) Healthcheck
Run:
```
curl -i https://cryptobot-ai-1.onrender.com/healthz
```
**Pass criteria:** HTTP/1.1 200 OK.

## 2) Telegram Webhook
Set or re-set webhook to the new PUBLIC_URL:
```
# Replace with your real values (do NOT paste secrets into chat)
curl -G "https://api.telegram.org/bot$BOT_TOKEN/setWebhook"   --data-urlencode "url=$PUBLIC_URL/webhook/$BOT_WEBHOOK_SECRET"
```
Check:
```
curl -s "https://api.telegram.org/bot$BOT_TOKEN/getWebhookInfo"
```
**Pass criteria:**
- `url` = `https://cryptobot-ai-1.onrender.com/webhook/<secret>`
- `pending_update_count` small (ideally 0 after a few seconds).

## 3) Chat Smoke (3 addresses)
In your Telegram chat with the bot:

### A) PEPE (ETH): `0x6982508145454Ce325dDbE47a25d4ec3d2311933`
**Pass criteria:**
- Snapshot shows Price/FDV/MC/Liq/Vol/Δ-метрики (не `—`)
- Кнопки **Open in DEX** и **Open in Scan** кликабельны.
- “Why/Why++” не залипают в одном ризке, отвечают корректно.

### B) QUICK (Polygon): `0x831753DD7087CaC61aB5644b308642cc1c33Dc13`
**Pass criteria:**
- Риск = жёлтый (≈20), без «foreign» Website intel.

### C) CAKE (BSC): `0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82`
**Pass criteria:**
- **Age** заполнен (из pairCreatedAt).
- **LP-lite** показывает проценты и ссылку провайдера.

## 4) If something fails
- Healthz ≠ 200 → приложите последние 80 строк Render logs (app).
- Webhook mismatch → приведите вывод `getWebhookInfo`.
- Token smoke → скрин ответа + 20 строк лога вокруг запроса.
- Не добавляйте новые ENV: фикс идёт через код.