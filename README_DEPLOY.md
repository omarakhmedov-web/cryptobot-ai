# Metridex QuickScan (MVP)

Flask + Gunicorn webhook that implements **QuickScan**:
- Pools & price/volume/FDV via **DexScreener** API.
- Domain signals (WHOIS/RDAP via `rdap.net`, SSL cert check, Wayback first capture).
- Caching, timeouts, and inline buttons for Δ 24h/7d/30d.

## Deploy (Render)

1. Create a new **Web Service** from this folder.
2. Set env vars (Render → *Environment*):
   - `TELEGRAM_TOKEN`
   - `WEBHOOK_SECRET` (random, used in URL path)
   - `WEBHOOK_HEADER_SECRET` (random, used as Telegram `secret_token` header)
   - optional: `BOT_USERNAME`, `REQUEST_TIMEOUT`, `CACHE_TTL_SECONDS`

3. After deploy, set Telegram webhook (replace vars):
```bash
curl -s "https://api.telegram.org/bot$TELEGRAM_TOKEN/setWebhook" \
  -d "url=$RENDER_EXTERNAL_URL/webhook/$WEBHOOK_SECRET" \
  -d "secret_token=$WEBHOOK_HEADER_SECRET"
```
4. Check:
   - `GET $RENDER_EXTERNAL_URL/healthz` → `{status:ok}`
   - `GET $RENDER_EXTERNAL_URL/` → meta

## Usage

- `/quickscan <address|url>` — accepts raw EVM address, DexScreener token/pair URL, or explorer URL.
- Just send a message with an address or URL to trigger an implicit scan.

Outputs:
- Best pool summary (by liquidity then 24h volume).
- Δ 24h/7d/30d buttons.
- Domain: WHOIS/RDAP created date & registrar, SSL validity + issuer, Wayback first snapshot date.

## Notes

- DexScreener API used:
  - `/latest/dex/pairs/{chainId}/{pairId}`
  - `/token-pairs/v1/{chainId}/{tokenAddress}`
  - `/latest/dex/search?q=` (fallback, works across chains for address queries)
- WHOIS → RDAP via `https://www.rdap.net/domain/<domain>`
- Wayback availability API: `https://archive.org/wayback/available?url=<domain>`

No proxies. Keep timeouts small.