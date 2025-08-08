import os
from flask import Flask, request
import telegram
from openai import OpenAI

app = Flask(__name__)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
PORT = int(os.environ.get("PORT", 10000))

bot = telegram.Bot(token=TELEGRAM_TOKEN)
client = OpenAI(api_key=OPENAI_API_KEY)

@app.route("/")
def root():
    return "Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or {}

    chat = (msg.get("chat") or {}).get("id")
    text = msg.get("text")

    if not (chat and text):
        return "ok"

    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": text}],
            temperature=0.7,
        )
        reply = resp.choices[0].message.content.strip()
    except Exception as e:
        reply = f"Error: {e}"

    bot.send_message(chat_id=chat, text=reply)
    return "ok"

if __name__ == "__main__":
    # Локальный запуск / Render (без gunicorn) — ок.
    app.run(host="0.0.0.0", port=PORT)
Rename app.py to server.py
