# MetridexBot

AI risk-metrics & quick due diligence for DeFi/Telegram.

## What’s inside
- Stable webhook (`/webhook/<SECRET>`), health check (`/healthz`)
- i18n EN/RU: `/lang en|ru`
- Commands: `/start`, `/help`, `/license <KEY>`, `/quota`
- Inline callbacks (24h/7d/30d)
- Clean Gunicorn setup, no proxies

## Deploy (Render)
1) Env: `TELEGRAM_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `APP_BASE_URL`
2) `pip install -r requirements.txt`
3) Start: `gunicorn server:app --preload --workers=2 --threads=4 --timeout=30`
4) Set webhook to `https://<app>.onrender.com/webhook/<SECRET>`
