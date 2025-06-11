import random
import requests
from django.conf import settings

BOT_TOKEN=settings.BOT_TOKEN

def generate_otp(length=6):
    return ''.join(random.choices('0123456789', k=length))


def send_telegram_message(telegram_id, message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage?chat_id={telegram_id}&text={message}"
    requests.get(url)
