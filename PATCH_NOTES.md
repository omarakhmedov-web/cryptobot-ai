
# Metridex Superbot Patch — 2025-10-10

**Что нового**
- Богаче карточка QuickScan: цена, FDV/MC/Liq, Vol24h, Δ5m/1h/24h, возраст пары, ссылки (DEX/Scan/Site).
- Markdown-оформление, читабельные USD/%.
- Стабильные попапы Why?/Why++/LP: bundle хранится в Redis (есть fallback в памяти процесса).
- Строгий роутинг callback'ов: v1:<ACTION>:<msgId>:<chatId>.

**Как установить**
1. Распаковать архив и заменить файлы в репо: `dex_client.py`, `renderers.py`, `server.py`, `state.py`.
2. Убедиться в ENV: есть `REDIS_URL`, `BOT_WEBHOOK_SECRET` совпадает с URL вебхука.
3. Деплой → новый скан → нажать Why?/Why++/LP.

**Примечания**
- Кнопки должны строиться функцией `build_keyboard(chat_id, msg_id, links)` из вашего `buttons.py`. Порядок:
  More details → Why? → Why++ → LP lock → Open in DEX → Open in Scan → Upgrade.
- Этот патч не требует ключей Web3. Реальный on-chain/WHOIS/SSL/Wayback добавим отдельным пакетом.
