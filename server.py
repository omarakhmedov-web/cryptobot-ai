import os
from flask import Flask, request
import requests

app = Flask(__name__)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
GROQ_API_KEY = os.environ["GROQ_API_KEY"]

def tg_send_message(chat_id: int, text: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": chat_id, "text": text})

def generate_reply(user_text: str) -> str:
    """Бесплатная генерация через Groq (OpenAI-совместимый endpoint)."""
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.1-8b-instant",  # можно "llama-3.1-70b-versatile"
                "messages": [
                    {"role": "system", "content": "Отвечай кратко и по делу."},
                    {"role": "user", "content": user_text},
                ],
                "temperature": 0.7,
            },
            timeout=30,
        )
        data = r.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Error (Groq): {e}"

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
    reply = generate_reply(text)
    tg_send_message(chat, reply)
    return "ok"
