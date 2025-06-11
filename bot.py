import os
from dotenv import load_dotenv
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram import Update

load_dotenv()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    telegram_id = update.effective_user.id
    link = f"http://127.0.0.1:8000/auth/bind-telegram/?telegram_id={telegram_id}"
    await update.message.reply_text(
        "Чтобы привязать Telegram к своему аккаунту, нажмите на ссылку ниже:\n" + link
    )

def main():
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise ValueError("BOT_TOKEN не найден в .env")

    application = ApplicationBuilder().token(token).build()
    application.add_handler(CommandHandler("start", start))

    application.run_polling()  # <-- автоматически всё запустит и корректно завершит

if __name__ == "__main__":
    main()
