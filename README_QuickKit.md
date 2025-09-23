# METRI-ANCHOR-28 QuickKit (2025-09-23)

This kit helps you verify the **anchor28** build without breaking other features.
Works on Windows (PowerShell) and Linux/macOS (bash).

## Files
- `test_api.sh` — bash script to sanity-check webhook/version
- `test_api.bat` — Windows batch to run the same checks
- `test_ipn.json` — sample IPN payload for crypto payments webhook
- `README_QuickKit.md` — this file
- `server_0_3_46_anchor28_fixed.py` — server file (included)

## Environment (Render)
Set/confirm the following **ENV vars** on Render:
- `TELEGRAM_TOKEN`
- `WEBHOOK_SECRET` (random string used in `/webhook/<WEBHOOK_SECRET>` path)
- `WEBHOOK_HEADER_SECRET` (optional hardening)
- `CRYPTO_LINK_DEEP`, `CRYPTO_LINK_DAYPASS`, `CRYPTO_LINK_PRO`, `CRYPTO_LINK_TEAMS`
- `CRYPTO_WEBHOOK_SECRET` (path segment for crypto IPN endpoint)
- `CRYPTO_WEBHOOK_HMAC` (optional shared secret for HMAC signature)
- `UPSALE_CALLBACKS_ENABLED=1` (optional feature flag)

> Deploy command (Render uses Gunicorn automatically)
```
gunicorn server:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120
```

## Health / Version
After deploy, test:
- `GET https://<YOUR_HOST>/healthz` → `ok`
- `GET https://<YOUR_HOST>/version` → should contain `0.3.46-anchor-28`

## Telegram webhook info
Replace `TELEGRAM_TOKEN` below and run one of the commands.

**bash:**
```
curl -s "https://api.telegram.org/bot$TELEGRAM_TOKEN/getWebhookInfo" | python3 -m json.tool
```

**PowerShell:**
```
$Env:TELEGRAM_TOKEN="<PASTE_TOKEN>"
curl "https://api.telegram.org/bot$Env:TELEGRAM_TOKEN/getWebhookInfo"
```

Expected: `ok:true` and a `url` like `https://<YOUR_HOST>/webhook/<WEBHOOK_SECRET>`.

## Test crypto IPN (NOWPayments-style)
Endpoint:
```
POST https://<YOUR_HOST>/crypto_webhook/<CRYPTO_WEBHOOK_SECRET>
Content-Type: application/json
```

Example minimal payload (see `test_ipn.json` in this kit):
```json
{
  "payment_status": "finished",
  "pay_address": "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEeF",
  "price_amount": 9.10,
  "price_currency": "USD",
  "actually_paid": 9.10,
  "order_id": "TEST-ORDER-001",
  "payment_id": 123456789,
  "purchase_id": "mdx-2025-09-23-001",
  "pay_currency": "USDT",
  "ipn_type": "payment",
  "invoice_id": "INV-001"
}
```

**bash:**
```
curl -s -X POST "https://<YOUR_HOST>/crypto_webhook/<CRYPTO_WEBHOOK_SECRET>"   -H "Content-Type: application/json"   --data @test_ipn.json
```

**PowerShell:**
```
$hostUrl = "https://<YOUR_HOST>/crypto_webhook/<CRYPTO_WEBHOOK_SECRET>"
$body = Get-Content -Raw -Path .\test_ipn.json
Invoke-WebRequest -Uri $hostUrl -Method POST -ContentType "application/json" -Body $body
```

Expected result: `200 OK` on test. On live callbacks your build should grant entitlements.

## Functional smoke-test
1. `/start` — welcome + keyboard.
2. `/version` — returns `0.3.46-anchor-28`.
3. `/buy deep|day|pro|teams` — returns `CRYPTO_LINK_*` direct link.
4. Tap link → provider page opens; small amounts (<$1) may be rejected by provider.
5. POST `test_ipn.json` to your webhook → 200 OK; entitlement recorded (check logs/DB if enabled).

---
**Note:** Keep secrets out of commits. If you change `WEBHOOK_SECRET`/`CRYPTO_WEBHOOK_SECRET`, re-set Telegram webhook accordingly.
