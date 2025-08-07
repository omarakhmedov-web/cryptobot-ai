from flask import Flask, request
import telegram
import openai
import os

TELEGRAM_TOKEN = os.environ['TELEGRAM_TOKEN']
OPENAI_API_KEY = os.environ['OPENAI_API_KEY']

bot = telegram.Bot(token=TELEGRAM_TOKEN)
app = Flask(__name__)
openai.api_key = OPENAI_API_KEY

@app.route('/')
def hello():
    return 'Bot is running!'

@app.route('/webhook', methods=['POST'])
def webhook():
    update = telegram.Update.de_json(request.get_json(force=True), bot)
    chat_id = update.message.chat.id
    user_message = update.message.text

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": user_message}]
        )
        reply = response.choices[0].message['content']
        bot.send_message(chat_id=chat_id, text=reply)
    except Exception as e:
        bot.send_message(chat_id=chat_id, text="Error: " + str(e))

    return 'ok'
