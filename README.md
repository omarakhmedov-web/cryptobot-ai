# Metridex MVP+ (Telegram QuickScan Bot)

Production-ready minimal MVP that runs as a Flask webhook receiving Telegram updates,
fetches market data (DexScreener or proxy), computes a deterministic risk verdict,
and renders consistent outputs (Quick / More details / Why? / Why++ / LP lock)
with a **fixed** inline keyboard order.

- **Language**: Python 3.11
- **Web**: Flask + Gunicorn
- **Cache/Limits**: Redis (with in-memory fallback)
- **CI**: GitHub Actions (lint, unit smoke test)
- **Start**: `gunicorn -w 1 -t 120 server:app`

## Features
- Fixed button order (no mixing): `More details`, `Why?`, `Why++`, `LP lock`, `Open in DEX`, `Open in Scan`, `Upgrade`
- Single callback handler with versioned `callback_data` (`v1:<ACTION>:<msgId>:<chatId>`)
- Consistent risk verdict across all views; no per-handler recompute
- Free/Pro/Teams limits + **Judge-Pass** (code, expiry, max 5 concurrent activations)
- Partial-response strategy with strict timeouts
- `/healthz` endpoint and structured logs

## Quick start

1) Python 3.11 + Redis available.
2) Create `.env` from `.env.example`, fill required values (BOT_TOKEN, PUBLIC_BASE_URL, etc.).
3) Deploy to Render (or similar), set start command:
   ```
   gunicorn -w 1 -t 120 server:app
   ```
4) Set Telegram webhook to `https://<your-app>.onrender.com/webhook/<BOT_WEBHOOK_SECRET>`

## ENV
See `.env.example` for a full list.

## Tests
```
pytest -q
```

## Notes
- Deep on-chain checks are stubbed with safe fallbacks; extend `chain_client.py` as needed.
- For DexScreener, you may set `DS_PROXY_URL` (Cloudflare Worker) to avoid rate limits.
- LP-lock info is rendered as *lite* (placeholder) unless you wire a locker provider.
