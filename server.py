import os
from flask import Flask, request
import requests
from openai import OpenAI

app = Flask(__name__)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

client = OpenAI(api_key=OPENAI_API_KEY)

def tg_send_message(chat_id: int, text: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": chat_id, "text": text})

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

    tg_send_message(chat, reply)
    return "ok"
