[README_DEPLOY (2).md](https://github.com/user-attachments/files/22198623/README_DEPLOY.2.md)
# MetridexBot Skeleton

Minimal, production-oriented Flask webhook for Telegram:
- Stable `/webhook/<SECRET>`
- `/healthz` for Render
- i18n EN/RU, `/lang`
- `/license` + feature flags (stub)
- Inline callbacks (24h/7d/30d)
- No proxies anywhere

## Quick start (Render)

1) Set env vars in Render → Environment:
- `TELEGRAM_TOKEN` = token from @BotFather for **@MetridexBot**
- `TELEGRAM_WEBHOOK_SECRET` = `python -c "import secrets; print(secrets.token_hex(32))"`
- `APP_BASE_URL` = `https://<your-app>.onrender.com`

2) Deploy (it will bind Gunicorn).

3) Set webhook (from your terminal):
```bash
export TELEGRAM_BOT_TOKEN="<TOKEN>"
export WEBHOOK_SECRET="<SECRET>"
export APP_BASE_URL="https://<your-app>.onrender.com"

curl -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
  -d "url=$APP_BASE_URL/webhook/$WEBHOOK_SECRET" \
  -d "max_connections=40" \
  -d "drop_pending_updates=true" \
  -d "allowed_updates[]=message" \
  -d "allowed_updates[]=edited_message" \
  -d "allowed_updates[]=callback_query" \
  -d "allowed_updates[]=my_chat_member" \
  -d "allowed_updates[]=chat_member"
```

4) Smoke test:
- Open `/healthz` → 200 OK
- DM `/start` to @MetridexBot
- Add to a test group (privacy disabled), send a normal message → webhook receives it

## Notes
- This is a skeleton to get the bot reliably online. Replace in-memory dicts with DB (Postgres) and implement QuickScan/DeepReport modules next.
- Keep tokens and secrets out of logs and git.
