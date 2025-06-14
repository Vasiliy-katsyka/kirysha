# -*- coding: utf-8 -*-
import telebot
import time
import threading
import logging
from telebot import apihelper, types
import requests
from bs4 import BeautifulSoup # Requires: pip install beautifulsoup4 requests
import re
import schedule # Requires: pip install schedule
import pytz # Requires: pip install pytz
from datetime import datetime, timedelta, date as date_obj # Import date separately
import os
import math
import calendar
import asyncio
import inspect # For checking coroutine functions
import json # For loading holidays data
import sqlite3

# Import Flask for the webhook server
from flask import Flask, request, abort

# --- Fix for curl_cffi on Windows ---
if os.name == 'nt': # Check if running on Windows
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception as e_policy:
        logging.warning(f"Could not set WindowsSelectorEventLoopPolicy: {e_policy}. curl_cffi might have issues.")
# --- End of fix ---


# --- Telethon Imports ---
from telethon import TelegramClient, events
from telethon.errors import UserNotParticipantError, ChatAdminRequiredError, UsernameNotOccupiedError, UsernameInvalidError
from telethon.errors.rpcerrorlist import UserIdInvalidError, PeerIdInvalidError
from telethon.tl.types import User as TelethonUser, PeerUser, PeerChat, PeerChannel


# --- Tonnel Gifting Imports ---
import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from curl_cffi.requests import AsyncSession, RequestsError

# --- Configuration ---
# Variables are kept in code as requested, not as environment variables.
BOT_TOKEN = "8173822520:AAE4RuWlOl6yHeSUIf0e8ZewDez03Aud2MY"
TARGET_CHANNEL_ID = -1002433007679
NFT_MONITOR_CHANNEL_ID = -1002485605769
LOW_SUPPLY_CHANNEL_ID = -1002291646801
CHECK_INTERVAL_SECONDS = 0.6
FALLBACK_CHECK_KEYWORD = "new gifts"
UPGRADE_KEYWORD = "nft upgrade"
UPGRADE_COUNT_PHRASE = "upgrade for"
LOW_SUPPLY_KEYWORD = "low supply alert"
MOSCOW_TZ = pytz.timezone('Europe/Moscow')

MAX_COLLECTION_NAME_WORDS = 3
FLOOR_COMMAND_REGEX_PATTERN = rf"^\s*(?:флор|floor)\s+([^\s]+(?:\s+[^\s]+){{0,{MAX_COLLECTION_NAME_WORDS-1}}})(?:\s+(.+))?\s*$"
FLOOR_COMMAND_REGEX = re.compile(FLOOR_COMMAND_REGEX_PATTERN, re.IGNORECASE)

# Regex to parse lines from @Gift_Alerts response
# Group 1: Model Name (e.g., "Midas Pepe")
# Group 2: Market Floor Price (e.g., "22000")
GIFT_ALERTS_MODEL_LINE_REGEX = re.compile(r"•\s*(.+?)\s*\(.*?:\s*([\d\.]+)\s*/")

# Configuration for @Gift_Alerts interaction
GIFT_ALERTS_BOT_USERNAME = "PriceNFTBot"
GIFT_ALERTS_CONVERSATION_TIMEOUT_SECONDS = 25 # Increased slightly

TARGET_REPLY_GROUP_ID = -1002356508255
TARGET_REPLY_USER_ID = 1234509506 # This user ID will be checked alongside NOW_COMMAND_ALLOWED_USER_ID
TARGET_REPLY_TEXT = "денис блять ты заебал чо ты блять пишешь хуйню всякую, лучше дикпик скинь блять"

# Main allowed user ID for all *specific bot commands* and sensitive Telethon operations
NOW_COMMAND_ALLOWED_USER_ID = 5146625949

CURRENCY_API_PRIMARY_BASE = "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@{date}/v1/currencies/{currencyCode}.min.json"
CURRENCY_API_FALLBACK_BASE = "https://{date}.currency-api.pages.dev/v1/currencies/{currencyCode}.min.json"
TONCOIN_CMC_URL = "https://coinmarketcap.com/currencies/toncoin/"
BITCOIN_CMC_URL = "https://coinmarketcap.com/currencies/bitcoin/"
ETHEREUM_CMC_URL = "https://coinmarketcap.com/currencies/ethereum/"
PETERHOF_LAT = 59.88
PETERHOF_LON = 29.91
SPB_LAT = 59.93
SPB_LON = 30.31
WEATHER_API_URL = "https://api.open-meteo.com/v1/forecast"

# Updated Event Targets
ED_CONCERT_TARGET = MOSCOW_TZ.localize(datetime(2025, 8, 3, 17, 0, 0))
ED_ALBUM_TARGET = MOSCOW_TZ.localize(datetime(2025, 9, 12, 10, 0, 0))
SQUID_GAME_TARGET = MOSCOW_TZ.localize(datetime(2025, 6, 27, 12, 0, 0)) # Date remains for "Squid Game 3"
SUMMER_END_TARGET = MOSCOW_TZ.localize(datetime(2025, 9, 1, 0, 0, 0))
MY_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2026, 5, 13, 10, 0, 0))
NIKITA_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2025, 7, 21, 10, 0, 0))
KIRILL_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2026, 3, 29, 10, 0, 0))
LISA_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2025, 10, 31, 10, 0, 0))
ALICE_BORDERLAND_TARGET = MOSCOW_TZ.localize(datetime(2025, 9, 19, 10, 0, 0))
GRISHA_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2026, 1, 28, 10, 0, 0))
POLINA_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2025, 9, 19, 10, 0, 0))
PLATON_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2025, 9, 15, 10, 0, 0))
CAMP_END_TARGET = MOSCOW_TZ.localize(datetime(2025, 6, 15, 0, 0, 0)) # New target for "пенис" message
YAROSLAV_BDAY_TARGET = MOSCOW_TZ.localize(datetime(2025, 7, 17, 10, 0, 0)) # Added Yaroslav's Birthday

TELETHON_API_ID = 17181071
TELETHON_API_HASH = "422d63fefdaa0144dc94e9f9bf4261f7"
TELETHON_SESSION_NAME = "my_gift_monitor_bot_telethon_session"
# These are the *two private chats* where specific Telethon commands like "пенис" and conversions work.
COUNTDOWN_TARGET_USERS_TELETHON = [1187759793, 7245223987]
COUNTDOWN_TARGET_DATE_TELETHON = MOSCOW_TZ.localize(datetime(2025, 8, 15, 0, 0, 0))
TELETHON_HEART_EMOJI = "❤️"
STAR_TO_RUB_RATE = 1.65

# Tonnel Gifting Configuration (placeholders should be replaced with actual values)
TONNEL_SENDER_INIT_DATA = "user=%7B%22id%22%3A5146625949%2C%22first_name%22%3A%22%F0%9D%99%91%F0%9D%98%BC%F0%9D%99%8E%F0%9D%99%84%F0%9D%99%87%F0%9D%99%84%F0%9D%99%94%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22Vasiliy939%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FXkLMSNnNOFwEiPSG-pvw0rtZyZpxl3Mabrm0ORyPo3zb6TTkLCiOwxIJ-gIV6o0K.svg%22%7D&chat_instance=9152189631026101607&chat_type=sender&start_param=4725037&auth_date=1747423191&signature=iX22zf0TMxVv_YaSF60awKK_oY6RY4NPMLFCTADU5Lhx77N0nldHltqnYOISYh5UuilYzgcCo_CnGrWsuMDA&hash=b6747e35feedca5349e2be2fdf052c91cd797dbfbbd3ad64f7d774a47a77f100"
TONNEL_GIFT_SECRET = "yowtfisthispieceofshitiiit"

HUG_EMOJI = "🤗" # Or any hug emoji you prefer
STAR_TO_USD_RATE = 0.01
USD_PER_HUG_UNIT = 3  # For the 3 USD part of the rate
HUG_MINUTES_PER_UNIT = 5  # For the 5 minutes part of the rate

DB_NAME = "bot_data.sqlite" # Or your preferred database file name

# Regex for the new "+время" command
# Handles: +время 10$, +время 10 usd, +время 10 долларов,
#          +время 10 евро, +время 10 eur, +время 10 рублей, +время 10 rub,
#          +время 10 тон, +время 10 ton, +время 10 звезд, +время 10 stars
PLUS_VREMYA_REGEX = re.compile(
    r"^\s*\+время\s+(\d+\.?\d*)\s*(доллар(?:ов)?|usd|\$|евро|eur|€|руб(?:лей|ля|лю)?|rub|₽|тон|ton|звезд|зв[её]зд|stars)\s*$",
    re.IGNORECASE
)

# Telethon Regex Patterns
SKOLKO_OSTALOS_REGEX = re.compile(r"^\s*сколько осталось\s*$", re.IGNORECASE)
PENIS_REGEX = re.compile(r"^\s*пенис\s*$", re.IGNORECASE)
CALCULATOR_REGEX = re.compile(r"^\s*(-?\d+\.?\d*)\s*([+\-*/%]|//|\*\*)\s*(-?\d+\.?\d*)\s*$")
TON_RUB_SEARCH_REGEX = re.compile(r"(\d+\.?\d*)\s*(?:тон|ton)(?![a-zA-Z])", re.IGNORECASE)
STARS_TO_RUB_REGEX = re.compile(r"(\d+\.?\d*)\s*(?:звезд|зв[её]зд|stars)(?![a-zA-Z])", re.IGNORECASE)
CURRENCY_TO_RUB_REGEX = re.compile(r"(\d+\.?\d*)\s*(?:(\$|€)|(usd|eur)(?![a-zA-Z]))", re.IGNORECASE)
GIFT_COMMAND_REGEX = re.compile(r"^\s*подарить\s+(.+?)\s+(\d{6,12})\s*$", re.IGNORECASE)
CONFIRM_GIFT_REGEX = re.compile(r"^\s*(да|нет)\s*$", re.IGNORECASE)


# --- Webhook Configuration ---
# Render.com provides the PORT environment variable.
# You MUST replace <YOUR_RENDER_APP_NAME> with your actual Render app name.
# Example: If your app is named 'my-telegram-bot', it would be "https://my-telegram-bot.onrender.com"
WEBHOOK_HOST = '0.0.0.0'
WEBHOOK_PORT = int(os.environ.get('PORT', 5000)) # Default to 5000 if not set by Render
WEBHOOK_URL_BASE = "https://kirysha.onrender.com" # !!! REPLACE THIS WITH YOUR RENDER APP URL !!!
WEBHOOK_URL_PATH = "/botwebhook/" + BOT_TOKEN # A secret path using the bot token

# --- Globals ---
known_gift_ids = set()
user_id_to_notify = None
monitoring_active = False
gifts_api_failing = False
monitor_thread = None
scheduler_thread = None
telethon_thread = None
bot = None
bot_info = None
bot_username = None
telethon_client = None
telethon_loop = None
MY_ID_TELETHON = None
pending_gift_purchases = {}
PENDING_GIFT_TIMEOUT_SECONDS = 300
lock = threading.Lock() # Ensure lock is defined before use

# _newline_char for f-string fix
_newline_char = '\n'

# --- Holidays Data ---
# Holidays data array removed as requested.
# Please paste your HOLIDAYS_DATA dictionary here if you want it to be included.
HOLIDAYS_DATA = {} # Placeholder as requested.

MONTH_NAMES_RU = {
    1: "Январь", 2: "Февраль", 3: "Март", 4: "Апрель", 5: "Май", 6: "Июнь",
    7: "Июль", 8: "Август", 9: "Сентябрь", 10: "Октябрь", 11: "Ноябрь", 12: "Декабрь"
}

# --- Logging ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger('telethon').setLevel(logging.WARNING)
logging.getLogger('curl_cffi').setLevel(logging.WARNING)
logging.getLogger('flask').setLevel(logging.WARNING) # Silence Flask access logs
logging.getLogger('werkzeug').setLevel(logging.WARNING) # Silence Werkzeug access logs

if "YOUR_TONNEL" in TONNEL_SENDER_INIT_DATA or "YOUR_TONNEL" in TONNEL_GIFT_SECRET:
    logger.critical("CRITICAL: Tonnel Sender InitData or Secret is not configured properly. Gifting feature WILL FAIL.")
if "<YOUR_RENDER_APP_NAME>" in WEBHOOK_URL_BASE:
    logger.critical("CRITICAL: WEBHOOK_URL_BASE is not configured. Please replace <YOUR_RENDER_APP_NAME> with your actual Render app name for webhook to function.")

# --- Bot Initialization (Telebot) ---
try:
    logger.info("Initializing Telebot Bot...")
    bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
    bot_info = bot.get_me()
    bot_username = bot_info.username
    if not bot_username or not bot_info.id:
        raise ValueError("Failed to get bot username or ID for Telebot")
    logger.info(f"Telebot Bot initialized: {bot_username} (ID: {bot_info.id})")
except Exception as e:
    logger.error(f"Telebot Bot initialization failed: {e}", exc_info=True)
    exit(1)

# --- Flask App Initialization ---
app = Flask(__name__)

# --- TonnelGifting: Crypto Helpers ---
SALT_SIZE = 8
KEY_SIZE = 32
IV_SIZE = 16
def derive_key_and_iv(passphrase: str, salt: bytes, key_length: int, iv_length: int) -> tuple[bytes, bytes]:
    derived = b''
    hasher = hashlib.md5()
    hasher.update(passphrase.encode('utf-8'))
    hasher.update(salt)
    derived_block = hasher.digest()
    derived += derived_block
    while len(derived) < key_length + iv_length:
        hasher = hashlib.md5()
        hasher.update(derived_block)
        hasher.update(passphrase.encode('utf-8'))
        hasher.update(salt)
        derived_block = hasher.digest()
        derived += derived_block
    return derived[:key_length], derived[key_length : key_length + iv_length]

def encrypt_aes_cryptojs_compat(plain_text: str, secret_passphrase: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key, iv = derive_key_and_iv(secret_passphrase, salt, KEY_SIZE, IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plain_text = pad(plain_text.encode('utf-8'), AES.block_size, style='pkcs7')
    ciphertext = cipher.encrypt(padded_plain_text)
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode('utf-8')

# --- TonnelGifting: TonnelGiftSender Class ---
class TonnelGiftSender:
    def __init__(self, sender_auth_data: str, gift_secret_passphrase: str):
        self.passphrase_secret = gift_secret_passphrase
        self.authdata = sender_auth_data
        self._session_instance: AsyncSession | None = None

    async def _get_session(self) -> AsyncSession:
        if self._session_instance is None:
            logger.debug("TonnelGiftSender: Creating new AsyncSession.")
            self._session_instance = AsyncSession(impersonate="chrome110")
        return self._session_instance

    async def _close_session_if_open(self):
        session_to_close = self._session_instance
        logger.debug(f"_close_session_if_open: Initial self._session_instance is type {type(self._session_instance)}")

        if session_to_close:
            logger.debug(f"_close_session_if_open: session_to_close (type: {type(session_to_close)}) is truthy.")

            try:
                if hasattr(session_to_close, 'aclose'):
                    if inspect.iscoroutinefunction(session_to_close.aclose):
                        logger.debug("Attempting to close Tonnel AsyncSession using async 'aclose()'.")
                        await session_to_close.aclose()
                    else: # Fallback for older curl_cffi where aclose might not be truly async
                        logger.warning("Tonnel AsyncSession 'aclose()' is not a coroutine, calling 'close()' directly.")
                        session_to_close.close() # type: ignore
                elif hasattr(session_to_close, 'close'):
                    if inspect.iscoroutinefunction(session_to_close.close):
                        logger.debug("Attempting to close Tonnel AsyncSession using async 'close()'.")
                        await session_to_close.close()
                    else:
                        logger.warning("Tonnel AsyncSession 'close()' method is synchronous. Calling it directly.")
                        session_to_close.close() # type: ignore
                else:
                    logger.error("Tonnel AsyncSession instance has no recognizable callable 'close' or 'aclose' method.")
                logger.debug("Tonnel AsyncSession close attempt finished.")
            except Exception as e:
                logger.error(f"Error during actual closing of Tonnel AsyncSession: {e}", exc_info=True)
            finally:
                self._session_instance = None
        else:
            logger.debug("_close_session_if_open: self._session_instance was already None. No action taken.")


    async def _make_request(self, method: str, url: str, headers: dict | None = None, json_payload: dict | None = None, timeout: int = 30, is_initial_get: bool = False):
        session = await self._get_session()
        response_obj = None
        try:
            req_kwargs = {"headers": headers, "timeout": timeout}
            if json_payload is not None and method.upper() == "POST":
                req_kwargs["json"] = json_payload

            if method.upper() == "GET":
                response_obj = await session.get(url, **req_kwargs)
            elif method.upper() == "POST":
                response_obj = await session.post(url, **req_kwargs)
            elif method.upper() == "OPTIONS":
                response_obj = await session.options(url, **req_kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            if method.upper() == "OPTIONS":
                if 200 <= response_obj.status_code < 300:
                    return {"status": "options_ok"}
                else:
                    err_txt = await response_obj.text()
                    logger.error(f"Tonnel OPTIONS {url} fail: {response_obj.status_code}. {err_txt[:200]}")
                    response_obj.raise_for_status()
                    return {"status": "error", "message": f"OPTIONS fail {response_obj.status_code}"}

            response_obj.raise_for_status()
            if response_obj.status_code == 204:
                return None

            ct = response_obj.headers.get("Content-Type", "").lower()
            if "application/json" in ct:
                try:
                    return response_obj.json()
                except json.JSONDecodeError as je:
                    err_txt = await response_obj.text()
                    logger.error(f"Tonnel JSONDecodeError {method} {url}: {je}. Body: {err_txt[:200]}")
                    return {"status": "error", "message": "Invalid JSON", "raw_text": err_txt[:200]}
            else:
                if is_initial_get:
                    return {"status": "get_ok_non_json"}
                else:
                    resp_txt = await response_obj.text()
                    logger.warning(f"Tonnel {method} {url} - Non-JSON ({ct}). Text: {resp_txt[:200]}")
                    return {"status": "error", "message": "Response not JSON", "content_type": ct, "text_preview": resp_txt[:200]}
        except RequestsError as re:
            logger.error(f"Tonnel RequestsError ({method} {url}): {re}")
            raise
        except json.JSONDecodeError as je:
            logger.error(f"Tonnel JSONDecodeError (outer) ({method} {url}): {je}")
            raise ValueError(f"Failed to decode JSON from {url}") from je
        except Exception as e:
            logger.error(f"Tonnel general request error ({method} {url}): {type(e).__name__} - {e}")
            raise

    async def search_gifts_on_marketplace(self, gift_filter_criteria_user: dict):
        if not self.authdata or "YOUR_TONNEL" in self.authdata:
            logger.error("TonnelGiftSender: search_gifts_on_marketplace called but sender auth data is not configured.")
            return {"status": "error", "message": "Tonnel sender not configured."}
        try:
            logger.debug("TonnelGiftSender: Attempting initial GET to marketplace.tonnel.network")
            initial_get_resp = await self._make_request(method="GET", url="https://marketplace.tonnel.network/", is_initial_get=True)
            if isinstance(initial_get_resp, dict) and initial_get_resp.get("status") == "error":
                logger.warning(f"TonnelGiftSender: Initial GET to marketplace failed: {initial_get_resp.get('message')}. Full response: {str(initial_get_resp)[:200]}")
            else:
                logger.debug(f"TonnelGiftSender: Initial GET response status: {initial_get_resp.get('status') if isinstance(initial_get_resp, dict) else 'OK'}")

            # Base filter criteria (always applied)
            final_filter = {
                "price": {"$exists": True},
                "refunded": {"$ne": True},
                "buyer": {"$exists": False},
                "export_at": {"$exists": True},
                "asset": "TON"
            }
            # Merge user-provided filter criteria
            # gift_filter_criteria_user can contain 'gift_id', 'gift_name', 'model', 'backdrop'
            final_filter.update(gift_filter_criteria_user)

            filter_str = json.dumps(final_filter)

            # If gift_id is in filter, it means we are searching by specific ID. Limit to 1.
            limit = 1 if "gift_id" in gift_filter_criteria_user else 10

            payload = {"filter": filter_str, "limit": limit, "page": 1, "sort": '{"price":1,"gift_id":-1}'}
            opt_h = {"Access-Control-Request-Method":"POST","Access-Control-Request-Headers":"content-type","Origin":"https://tonnel-gift.vercel.app","Referer":"https://tonnel-gift.vercel.app/"}
            post_h = {"Content-Type":"application/json","Origin":"https://marketplace.tonnel.network","Referer":"https://marketplace.tonnel.network/"}

            logger.debug("TonnelGiftSender: Attempting OPTIONS to gifts2.tonnel.network/api/pageGifts")
            options_resp = await self._make_request(method="OPTIONS", url="https://gifts2.tonnel.network/api/pageGifts", headers=opt_h)
            if isinstance(options_resp, dict) and options_resp.get("status") == "error":
                 logger.warning(f"TonnelGiftSender: OPTIONS request to pageGifts failed: {options_resp.get('message')}. Full response: {str(options_resp)[:200]}")
            else:
                logger.debug(f"TonnelGiftSender: OPTIONS response status: {options_resp.get('status') if isinstance(options_resp, dict) else 'OK'}")

            logger.debug(f"TonnelGiftSender: Attempting POST to gifts2.tonnel.network/api/pageGifts with payload: {payload}")
            resp = await self._make_request(method="POST", url="https://gifts2.tonnel.network/api/pageGifts", headers=post_h, json_payload=payload)
            logger.debug(f"TonnelGiftSender: POST response type: {type(resp)}, content snippet: {str(resp)[:300]}")

            if not isinstance(resp, list):
                msg = resp.get('message','API error') if isinstance(resp,dict) else 'Format error or non-dict non-list response'
                final_message = f"Could not fetch gift list: {msg}"
                logger.error(f"TonnelGiftSender: Failed to get a valid gift list from pageGifts. API response was not a list. Full Response: {str(resp)}. Derived message: {final_message}")
                return {"status": "error", "message": final_message, "raw_response": resp}

            if not resp:
                search_type = "by ID" if "gift_id" in gift_filter_criteria_user else "by name/criteria"
                logger.info(f"TonnelGiftSender: No gifts found {search_type}: {gift_filter_criteria_user}. API returned an empty list.")
                return {"status": "error", "message": f"No gifts found matching your {search_type}.", "gifts": []}

            return {"status": "success", "gifts": resp}
        except RequestsError as re:
            logger.error(f"TonnelGiftSender: Network error during gift search for {gift_filter_criteria_user}: {re}", exc_info=True)
            return {"status": "error", "message": f"Network error during gift search: {str(re)}"}
        except ValueError as ve:
            logger.error(f"TonnelGiftSender: Value error (e.g. JSON decode) during gift search for {gift_filter_criteria_user}: {ve}", exc_info=True)
            return {"status": "error", "message": f"Data error during gift search: {str(ve)}"}
        except Exception as e:
            logger.error(f"TonnelGiftSender: General error searching gifts {gift_filter_criteria_user}: {e}", exc_info=True)
            return {"status": "error", "message": f"Error during gift search: {str(e)}"}
        finally:
            await self._close_session_if_open()


    async def execute_purchase(self, gift_to_buy: dict, receiver_telegram_id: int):
        if not self.authdata or "YOUR_TONNEL" in self.authdata:
            logger.error("TonnelGiftSender: execute_purchase called but sender auth data is not configured.")
            return {"status": "error", "message": "Tonnel sender not configured."}
        if not self.passphrase_secret or "YOUR_TONNEL" in self.passphrase_secret:
            logger.error("TonnelGiftSender: execute_purchase called but gift secret not configured.")
            return {"status": "error", "message": "Tonnel gift secret not configured."}
        try:
            gift_id, gift_price = gift_to_buy.get('gift_id'), gift_to_buy.get('price')
            if not gift_id or gift_price is None:
                logger.error(f"TonnelGiftSender: Invalid gift object for purchase: {gift_to_buy}")
                return {"status": "error", "message": "Invalid gift object."}

            user_payload = {"authData": self.authdata, "user": receiver_telegram_id}
            ui_comm_h = {"Origin":"https://marketplace.tonnel.network","Referer":"https://marketplace.tonnel.network/"}
            ui_opt_h = {**ui_comm_h, "Access-Control-Request-Method":"POST", "Access-Control-Request-Headers":"content-type"}
            ui_post_h = {**ui_comm_h, "Content-Type":"application/json"}

            logger.debug(f"TonnelGiftSender: Checking user info for receiver ID {receiver_telegram_id}")
            await self._make_request(method="OPTIONS", url="https://gifts2.tonnel.network/api/userInfo", headers=ui_opt_h)
            user_chk = await self._make_request(method="POST", url="https://gifts2.tonnel.network/api/userInfo", headers=ui_post_h, json_payload=user_payload)
            logger.debug(f"TonnelGiftSender: User check response: {str(user_chk)[:300]}")

            if not isinstance(user_chk, dict) or user_chk.get("status") != "success":
                msg = user_chk.get('message','User error') if isinstance(user_chk,dict) else 'Unknown user check error'
                logger.error(f"TonnelGiftSender: User check failed for {receiver_telegram_id}. Response: {str(user_chk)}. Message: {msg}")
                return {"status": "error", "message": f"Tonnel user check failed for {receiver_telegram_id}: {msg}"}

            enc_ts = encrypt_aes_cryptojs_compat(f"{int(time.time())}", self.passphrase_secret)
            buy_url = f"https://gifts.coffin.meme/api/buyGift/{gift_id}"
            buy_payload = {"anonymously":True, "asset":"TON", "authData":self.authdata, "price":gift_price, "receiver":receiver_telegram_id, "showPrice":False, "timestamp":enc_ts}
            buy_comm_h = {"Origin":"https://marketplace.tonnel.network","Referer":"https://marketplace.tonnel.network/","Host":"gifts.coffin.meme"}
            buy_opt_h = {**buy_comm_h, "Access-Control-Request-Method":"POST", "Access-Control-Request-Headers":"content-type"}
            buy_post_h = {**buy_comm_h, "Content-Type":"application/json"}

            logger.debug(f"TonnelGiftSender: Attempting purchase for gift ID {gift_id} to {receiver_telegram_id}. Payload: {buy_payload}")
            await self._make_request(method="OPTIONS", url=buy_url, headers=buy_opt_h)
            purchase_resp = await self._make_request(method="POST", url=buy_url, headers=buy_post_h, json_payload=buy_payload, timeout=90)
            logger.debug(f"TonnelGiftSender: Purchase response: {str(purchase_resp)[:300]}")

            if isinstance(purchase_resp, dict) and purchase_resp.get("status") == "success":
                return {"status": "success", "message": f"Gift (ID: {gift_id}) sent!", "details": purchase_resp}
            else:
                msg = purchase_resp.get('message','Purchase error') if isinstance(purchase_resp,dict) else 'Unknown purchase error'
                logger.error(f"TonnelGiftSender: Tonnel transfer failed. Response: {str(purchase_resp)}. Message: {msg}")
                return {"status": "error", "message": f"Tonnel transfer failed: {msg}"}
        except RequestsError as re:
            logger.error(f"TonnelGiftSender: Network error during purchase for gift ID {gift_id} to {receiver_telegram_id}: {re}", exc_info=True)
            return {"status": "error", "message": f"Network error during Tonnel purchase: {str(re)}"}
        except ValueError as ve:
             logger.error(f"TonnelGiftSender: Value error (e.g. JSON decode) during purchase for gift ID {gift_id} to {receiver_telegram_id}: {ve}", exc_info=True)
             return {"status": "error", "message": f"Data error during Tonnel purchase: {str(ve)}"}
        except Exception as e:
            logger.error(f"TonnelGiftSender: General error purchasing gift ID {gift_id} to {receiver_telegram_id}: {e}", exc_info=True)
            return {"status": "error", "message": f"Error during Tonnel purchase: {str(e)}"}
        finally:
            await self._close_session_if_open()

# --- TonnelGifting: Gift Name Parsing Function ---
def parse_gift_details_from_string(full_name_str: str) -> dict:
    parsed = {"name": None, "model": None, "backdrop": None}
    temp_str = full_name_str.strip()

    # Regex to find a component at the end of a string:
    # Captures an optional "name part" (any word chars or spaces that are not parenthesis or space)
    # before a percentage.
    # Group 1: The name part within the component (e.g., "Red Grape", "Intergalactic")
    # Group 2: The raw percentage string (e.g., "1.2%" or "(1.5%)")
    # `\s*`: optional leading spaces for the component (which will be stripped)
    # `([^\(\)\s]+(?:\s+[^\(\)\s]+)*?)?`: This is the crucial name_part.
    #   `[^\(\)\s]+`: matches one or more characters that are not parenthesis or space.
    #   `(?:\s+[^\(\)\s]+)*?`: optionally followed by space then more non-parenthesis chars (non-greedy).
    #   The outer `?` makes the entire name_part optional.
    # `\s*`: optional space before percentage
    # `(\(\d+\.?\d*%\)|\d+\.?\d*%)`: the percentage part (with or without parentheses).
    # `$` : anchors to the end of the string.
    component_end_regex = re.compile(
        r"\s*([^\(\)\s]+(?:\s+[^\(\)\s]+)*?)?\s*(\(\d+\.?\d*%\)|\d+\.?\d*%)$",
        re.IGNORECASE
    )

    # Helper to normalize percentage string to "(X%)" format for API consistency
    def normalize_perc_format(perc_str):
        if perc_str and not (perc_str.startswith('(') and perc_str.endswith(')')):
            return f"({perc_str})"
        return perc_str

    extracted_components = [] # Will store (component_name_for_api_filter, original_match_start_index)

    # First, try to find the backdrop (rightmost component)
    backdrop_match = component_end_regex.search(temp_str)
    if backdrop_match:
        component_name_part = backdrop_match.group(1).strip() if backdrop_match.group(1) else ""
        component_perc_part = backdrop_match.group(2)

        # Build the component string for the API filter (e.g., "Red Grape (1.2%)")
        api_filter_value = f"{component_name_part} {normalize_perc_format(component_perc_part)}".strip()
        extracted_components.append((api_filter_value, backdrop_match.start()))

        # Remove this component from the temp_str for further processing
        temp_str = temp_str[:backdrop_match.start()].strip()
        logger.debug(f"Parser: Found a component (potential backdrop): '{api_filter_value}', remaining: '{temp_str}'")


    # Second, try to find the model (next rightmost component)
    model_match = component_end_regex.search(temp_str)
    if model_match:
        component_name_part = model_match.group(1).strip() if model_match.group(1) else ""
        component_perc_part = model_match.group(2)

        api_filter_value = f"{component_name_part} {normalize_perc_format(component_perc_part)}".strip()
        extracted_components.append((api_filter_value, model_match.start()))

        # Remove this component from temp_str
        temp_str = temp_str[:model_match.start()].strip()
        logger.debug(f"Parser: Found another component (potential model): '{api_filter_value}', remaining: '{temp_str}'")

    # Sort components by their original position in the string (left to right).
    # This is important for assigning the first found component to 'model' and the second to 'backdrop'.
    extracted_components.sort(key=lambda x: x[1])

    if len(extracted_components) >= 1:
        parsed["model"] = extracted_components[0][0] # The first component found (leftmost) is the model
    if len(extracted_components) >= 2:
        parsed["backdrop"] = extracted_components[1][0] # The second component found is the backdrop

    # The remaining text is the main gift name
    parsed["name"] = temp_str if temp_str else None

    # Edge case: If the input string was ONLY a single component (e.g., "Rare Starship (1.0%)")
    # and we parsed it as a model, but no main name was left. Then it should be the main name.
    # This means if `parsed["name"]` is empty after parsing, and only one component was found
    # (i.e., `parsed["model"]` is set and `parsed["backdrop"]` is not),
    # that component is actually the `name`.
    if not parsed["name"] and parsed["model"] and not parsed["backdrop"]:
        logger.debug(f"Parser: Single component input '{full_name_str}', reassigning model as name.")
        parsed["name"] = parsed["model"]
        parsed["model"] = None
    elif not parsed["name"] and not parsed["model"] and not parsed["backdrop"] and full_name_str.strip():
        # Fallback if nothing was parsed but input existed (e.g., "Plain Text")
        parsed["name"] = full_name_str.strip()


    logger.debug(f"Parser final result for '{full_name_str}': name='{parsed['name']}', model='{parsed['model']}', backdrop='{parsed['backdrop']}'")
    return parsed


# --- Utility Functions ---
def format_timedelta(td):
    if td.total_seconds() <= 0:
        return "уже прошло!"
    days = td.days
    hours, rem_s = divmod(td.seconds, 3600)
    minutes, _ = divmod(rem_s, 60)
    parts = []
    if days > 0:
        parts.append(f"{days} дн")
    if hours > 0:
        parts.append(f"{hours} ч")
    if minutes > 0:
        parts.append(f"{minutes} мин")
    if not parts:
        return "меньше минуты"
    return ", ".join(parts)

def format_gift_count_string(count):
    if count % 10 == 1 and count % 100 != 11:
        return f"{count} новый подарок"
    elif 2 <= count % 10 <= 4 and (count % 100 < 10 or count % 100 >= 20):
        return f"{count} новых подарка"
    else:
        return f"{count} новых подарков"

def format_upgrade_count_string(count):
    if count % 10 == 1 and count % 100 != 11:
        return f"{count} новое улучшение"
    elif 2 <= count % 10 <= 4 and (count % 100 < 10 or count % 100 >= 20):
        return f"{count} новых улучшения"
    else:
        return f"{count} новых улучшений"

def notify_generic(target_chat_id, message_text, description="notification", parse_mode=None, reply_to_message_id=None, reply_markup=None):
    if not bot:
        logger.error("Telebot Bot not initialized.")
        return None
    try:
        sent = bot.send_message(target_chat_id, message_text, parse_mode=parse_mode, reply_to_message_id=reply_to_message_id, reply_markup=reply_markup, disable_web_page_preview=True)
        logger.info(f"Telebot: Sent {description} to {target_chat_id} (MsgID: {sent.message_id}).")
        return sent
    except apihelper.ApiException as e:
        logger.error(f"Telebot: Fail send {description} to {target_chat_id}: API Exc {e.error_code} - {e.description}", exc_info=False)
        return None
    except Exception as e:
        logger.error(f"Telebot: Unexp error send {description} to {target_chat_id}: {e}", exc_info=True)
        return None

# --- Gift Monitoring Logic (Telebot) ---
def get_current_gifts():
    global gifts_api_failing
    if not bot:
        return None
    try:
        resp = bot.get_available_gifts()
        if resp and hasattr(resp, 'gifts') and resp.gifts is not None:
            with lock:
                gifts_api_failing = False
            logger.debug(f"Fetched {len(resp.gifts)} gifts.")
            return resp.gifts
        else:
            logger.warning(f"get_available_gifts unexpected: {resp}")
            with lock:
                gifts_api_failing = False
            return []
    except apihelper.ApiException as e:
        logger.error(f"API Error gifts: {e.error_code} - {e.description}")
        with lock:
            gifts_api_failing = True
        return None
    except Exception as e:
        logger.error(f"Unexp error gifts: {e}", exc_info=True)
        with lock:
            gifts_api_failing = True
        return None

def initialize_known_gifts():
    global known_gift_ids
    logger.info("Fetching initial gifts baseline...")
    initial = get_current_gifts()
    with lock:
        known_gift_ids.clear()
        if initial is not None:
            known_gift_ids = {g.id for g in initial}
            logger.info(f"Initialized {len(known_gift_ids)} known gifts.")
            return True
        else:
            logger.error("Failed to fetch initial gifts.")
            return False

def check_for_new_gifts_loop():
    global known_gift_ids, monitoring_active, gifts_api_failing
    if not initialize_known_gifts():
        with lock:
            notify_user = user_id_to_notify
        if notify_user and bot:
            notify_generic(notify_user, "⚠️ Gift fetch failed on init.", "init warning")

    logger.info("Starting gift monitor loop...")
    while True:
        with lock:
            stop = not monitoring_active
        if stop:
            logger.info("Gift monitor loop stopping.")
            break

        current_list = get_current_gifts()
        if current_list is not None:
            current_ids = {g.id for g in current_list}
            new_ids = set()
            with lock:
                new_ids = current_ids - known_gift_ids
                if new_ids:
                    known_gift_ids.update(new_ids)
            if new_ids:
                logger.info(f"New gifts detected: IDs={new_ids}")
                msg = f"🎁✨ Новые подарки! Обнаружено: {format_gift_count_string(len(new_ids))}"
                notify_generic(TARGET_CHANNEL_ID, msg, "new gift API")
                with lock:
                    notify_user = user_id_to_notify
                if notify_user:
                    notify_generic(notify_user, msg, "new gift API to user")

        with lock:
            is_failing = gifts_api_failing

        time.sleep(5 if is_failing else CHECK_INTERVAL_SECONDS)
    logger.info("Gift monitor loop finished.")

# --- Data Fetching Helpers ---
def _fetch_currency_data(url):
    try:
        resp = requests.get(url, headers={'User-Agent': 'TelegramBot/1.0'}, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"Error fetch currency {url}: {e}")
        return None

def get_currency_rate_with_change(base, target):
    base_lower, target_lower = base.lower(), target.lower()
    latest_r, yest_r, r_date = None, None, "latest"

    latest_d = _fetch_currency_data(CURRENCY_API_PRIMARY_BASE.format(date="latest", currencyCode=base_lower))
    if latest_d is None:
        latest_d = _fetch_currency_data(CURRENCY_API_FALLBACK_BASE.format(date="latest", currencyCode=base_lower))

    if latest_d and isinstance(latest_d, dict):
        r_date_str, latest_r_d = latest_d.get("date"), latest_d.get(base_lower)
        if isinstance(latest_r_d, dict):
            latest_r = latest_r_d.get(target_lower)
        if latest_r is not None and r_date_str:
            try:
                date_obj.fromisoformat(r_date_str)
                r_date = r_date_str
            except ValueError:
                pass

    if latest_r is None:
        return "N/A", "N/A"

    if r_date != "latest":
        try:
            yest_d_obj = date_obj.fromisoformat(r_date) - timedelta(days=1)
            yest_d_str = yest_d_obj.isoformat()
            yest_data = _fetch_currency_data(CURRENCY_API_PRIMARY_BASE.format(date=yest_d_str, currencyCode=base_lower))
            if yest_data is None:
                yest_data = _fetch_currency_data(CURRENCY_API_FALLBACK_BASE.format(date=yest_d_str, currencyCode=base_lower))
            if yest_data and isinstance(yest_data, dict):
                yest_r_d = yest_data.get(base_lower)
                if isinstance(yest_r_d, dict):
                    yest_r = yest_r_d.get(target_lower)
        except Exception:
            yest_r = None

    rate_s = f"{latest_r:.4f}" if isinstance(latest_r, (int, float)) else str(latest_r)
    change_s = "N/A"
    if yest_r is not None and isinstance(latest_r,(int,float)) and isinstance(yest_r,(int,float)) and yest_r != 0:
        try:
            change_s = f"{((latest_r - yest_r) / yest_r) * 100:+.2f}% 1d"
        except Exception:
            change_s = "Calc Err"
    return rate_s, change_s

def get_usd_rub_rate():
    r, c = get_currency_rate_with_change("usd", "rub")
    return f"{r} ₽", c

def get_eur_rub_rate():
    r, c = get_currency_rate_with_change("eur", "rub")
    return f"{r} ₽", c

def get_cmc_crypto_price(url):
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 Chrome/91','Accept-Language':'en-US,en'}, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        price_s, price_f = "N/A", "N/A"
        sels = ['span[data-test="text-cdp-price-display"]','div.priceValue span','span.sc-f70bb44c-0']
        for sel in sels:
            span = soup.select_one(sel)
            if span and span.text.strip():
                price_s = span.text.strip()
                break
        if price_s != "N/A":
            price_f = f"{float(price_s.replace('$', '').replace(',', '')):,.2f}" if price_s.startswith('$') else price_s

        change_s = "N/A"
        ch_p_sels = [f'div[data-p="{url.split("/")[-2]}-price-changepercentage-24h"] p', 'p.priceChange']
        for sel in ch_p_sels:
            ch_el = soup.select_one(sel)
            if ch_el and '%' in ch_el.text:
                match = re.search(r"([+-]?[\d\.,]+%)", ch_el.text)
                change_s = match.group(1) if match else ch_el.text.strip()
                break
        return price_f, change_s
    except Exception as e:
        logger.error(f"Error CMC price {url}: {e}")
        return "N/A", "N/A"

def get_ton_price(): return get_cmc_crypto_price(TONCOIN_CMC_URL)
def get_btc_price(): return get_cmc_crypto_price(BITCOIN_CMC_URL)
def get_eth_price(): return get_cmc_crypto_price(ETHEREUM_CMC_URL)

WMO_CODES_SIMPLE = {0:"☀️",1:"🌤️",2:"🌥️",3:"☁️",45:"🌫️",61:"🌧️",63:"🌧️",65:"🌧️",71:"🌨️",73:"🌨️",75:"🌨️",95:"⛈️"}
def get_weather(lat, lon, name):
    try:
        resp = requests.get(WEATHER_API_URL, params={"latitude":lat,"longitude":lon,"current":"temperature_2m,apparent_temperature,weather_code","timezone":"Europe/Moscow"}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        curr = data.get('current', {})
        t, app_t, code = curr.get('temperature_2m'), curr.get('apparent_temperature'), curr.get('weather_code')
        return f"{t}°(ощ.{app_t}°), {WMO_CODES_SIMPLE.get(code, f'Код {code}')}" if t is not None else "N/A"
    except Exception as e:
        logger.error(f"Error weather {name}: {e}")
        return "N/A"

def get_peterhof_weather_str(): return get_weather(PETERHOF_LAT, PETERHOF_LON, "Peterhof")
def get_spb_weather_str(): return get_weather(SPB_LAT, SPB_LON, "SPb")

def get_today_holidays(now: datetime):
    month_name = MONTH_NAMES_RU.get(now.month)
    day = now.day
    if month_name and month_name in HOLIDAYS_DATA:
        month_data = HOLIDAYS_DATA[month_name]
        for day_data in month_data:
            if day_data["day"] == day:
                holidays_list = [h["name"] for h in day_data["holidays"] if h["name"] != "Нет широко признанных праздников"]
                return holidays_list
    return []

# --- Scheduled Task & Message Generation (Telebot) ---
def send_timed_message_telebot(message_text_header):
    logger.info(f"Telebot: Generating summary: '{message_text_header}'")
    now = datetime.now(MOSCOW_TZ)
    year = now.year

    # Extract week and day in year info first
    week_day_stats_str = (
        f"🗓️ Неделя: {now.isocalendar()[1]}{_newline_char}"
        f"⏳ Дней в году: {(366 if calendar.isleap(year) else 365) - now.timetuple().tm_yday}"
    )

    # Holidays section
    today_holidays = get_today_holidays(now)
    holidays_str = ""
    if today_holidays:
        if len(today_holidays) == 1:
            holidays_str = f"<b>Праздник сегодня:</b> {today_holidays[0]}"
        else:
            holidays_str = "<b>Праздники сегодня:</b>" + _newline_char + _newline_char.join(f"• {h}" for h in today_holidays)
    else:
        holidays_str = "<b>Праздник сегодня:</b> нет широко признанных праздников"

    # Remaining countdowns for the quote block
    countdown_items_for_quote = [
        f"🎸 Ed Concert - {format_timedelta(ED_CONCERT_TARGET-now)}",
        f"💿 Ed Album - {format_timedelta(ED_ALBUM_TARGET-now)}",
        f"🦑 Squid Game 3 - {format_timedelta(SQUID_GAME_TARGET-now)}", # Updated title
        f"☀️ До конца лета - {format_timedelta(SUMMER_END_TARGET-now)}",
        f"🎂 Мой ДР - {format_timedelta(MY_BDAY_TARGET-now)}",
        f"🎉 ДР Никиты - {format_timedelta(NIKITA_BDAY_TARGET-now)}",
        f"🥳 ДР Кирюши - {format_timedelta(KIRILL_BDAY_TARGET-now)}",
        f"🎈 ДР Лизы - {format_timedelta(LISA_BDAY_TARGET-now)}",
        f"🎀 ДР Полины - {format_timedelta(POLINA_BDAY_TARGET-now)}",
        f"🧸 ДР Платона - {format_timedelta(PLATON_BDAY_TARGET-now)}",
        f"🎬 Алиса в пограничье 3 - {format_timedelta(ALICE_BORDERLAND_TARGET-now)}", # Updated title
        f"🍰 ДР Гриши - {format_timedelta(GRISHA_BDAY_TARGET-now)}",
        f"🎂 ДР Ярослава - {format_timedelta(YAROSLAV_BDAY_TARGET-now)}" # Added Yaroslav's Birthday
    ]
    # Filter out any empty strings that might have been placeholder newlines
    countdown_items_for_quote = [item for item in countdown_items_for_quote if item.strip()]

    # Construct the quote block. No leading _newline_char needed inside the f-string after `<blockquote>`
    # as the join will handle newlines between items.
    time_info_str = f"<blockquote expandable>{_newline_char.join(countdown_items_for_quote)}{_newline_char}</blockquote>"

    ton_p, ton_c = get_ton_price()
    btc_p, btc_c = get_btc_price()
    eth_p, eth_c = get_eth_price()
    usd_r, usd_c = get_usd_rub_rate()
    eur_r, eur_c = get_eur_rub_rate()

    fin_info = (f"💎 TON: ${ton_p} ({ton_c}){_newline_char}💰 BTC: ${btc_p} ({btc_c}){_newline_char}"
                f"💎 ETH: ${eth_p} ({eth_c}){_newline_char}💵 USD: {usd_r} ({usd_c}){_newline_char}💶 EUR: {eur_r} ({eur_c})")

    weather_info = (f"📍 Петергоф: {get_peterhof_weather_str()}{_newline_char}📍 СПб: {get_spb_weather_str()}")

    # Assemble the full message in the new order
    full_message = (
        f"<b>{message_text_header}</b>{_newline_char}{_newline_char}"
        f"{week_day_stats_str}{_newline_char}{_newline_char}" # Week and Day in Year
        f"{holidays_str}{_newline_char}{_newline_char}"      # Celebration
        f"{time_info_str}{_newline_char}{_newline_char}"     # Quote with countdowns
        f"{fin_info}{_newline_char}{_newline_char}"          # Currencies
        f"{weather_info}"                                    # Weather
    )
    notify_generic(TARGET_CHANNEL_ID, full_message, description=f"Telebot timed msg '{message_text_header}'", parse_mode="HTML")

# --- Telethon Base Functions ---
async def _is_allowed_two_private_chats(event):
    """
    Checks if the event is a private message from one of the allowed Telethon users.
    Used for commands like "сколько осталось", "пенис", calc, conversions, gifting.
    """
    if not event.is_private:
        # Silently ignore messages not in private chats for these commands
        return False
    if event.chat_id not in COUNTDOWN_TARGET_USERS_TELETHON:
        logger.warning(f"Telethon: Unauthorized private chat access attempt by {event.chat_id} for command '{event.text}'.")
        # Optionally, reply with a generic unauthorized message to the private chat
        # await event.reply("❌ У вас нет прав для выполнения этой команды в этом чате.")
        return False
    return True


async def get_telethon_countdown_message_text_generic():
    td = COUNTDOWN_TARGET_DATE_TELETHON - datetime.now(MOSCOW_TZ)
    if td.total_seconds() <= 0:
        return f"Наша встреча уже должна была состояться! {TELETHON_HEART_EMOJI}"
    else:
        return f"До нашей встречи осталось {format_timedelta(td)} {TELETHON_HEART_EMOJI}"

def send_daily_telethon_countdown_sync():
    if telethon_client and telethon_client.is_connected() and telethon_loop:
        async def _task():
            for uid in COUNTDOWN_TARGET_USERS_TELETHON:
                try:
                    # Daily countdown is sent to a specific list of users, not restricted by NOW_COMMAND_ALLOWED_USER_ID
                    # as it's a scheduled notification, not an interactive command.
                    await telethon_client.send_message(int(uid), await get_telethon_countdown_message_text_generic())
                except Exception as e:
                    logger.error(f"Telethon daily countdown fail to {uid}: {e}")
        asyncio.run_coroutine_threadsafe(_task(), telethon_loop)

# --- Telethon Event Handlers ---
# Handlers are now regular async functions and will be added via client.add_event_handler inside run_telethon_client_main_logic
async def telethon_penis_handler(event):
    """
    Handles the specific 'пенис' message for private chats in COUNTDOWN_TARGET_USERS_TELETHON.
    This is intentionally *not* restricted by NOW_COMMAND_ALLOWED_USER_ID to match the specific request.
    """
    td = CAMP_END_TARGET - datetime.now(MOSCOW_TZ)
    if td.total_seconds() <= 0:
        countdown_text = "вы уже свалили из этого ебанного лагеря!"
    else:
        countdown_text = f"до того как вы наконец-то свалите из этого ебанного лагеря осталось {format_timedelta(td)}"
    await event.reply(countdown_text)

async def telethon_skolko_ostalos_handler(event):
    await event.reply(await get_telethon_countdown_message_text_generic())

async def telethon_calculator_handler(event):
    m = event.pattern_match.groups()
    n1, op, n2 = float(m[0]), m[1], float(m[2])
    res = None
    try:
        if op == '+': res=n1+n2
        elif op == '-': res=n1-n2
        elif op == '*': res=n1*n2
        elif op == '/': res=n1/n2 if n2!=0 else "Деление на ноль!"
        elif op == '**': res=n1**n2
        elif op == '//': res=n1//n2 if n2!=0 else "Деление на ноль!"
        elif op == '%': res=n1%n2 if n2!=0 else "Деление на ноль!"

        if isinstance(res,(int,float)) and res==int(res):
            await event.reply(str(int(res)))
        elif isinstance(res,(int,float)):
            await event.reply(f"{res:.10g}")
        else:
            await event.reply(str(res))

    except Exception as e:
        await event.reply(f"Calc error: {e}")

async def generic_conversion_handler(event, regex_search_func, conversion_logic_func, error_msg_base):
    if not event.text:
        return
    # _is_allowed_two_private_chats check is handled by add_event_handler's func param now.

    match = regex_search_func(event.text)
    if not match:
        return

    amount_str = match.group(1)
    logger.info(f"Telethon: {error_msg_base} triggered for '{amount_str}' by {event.sender_id}")
    try:
        result_message = await conversion_logic_func(amount_str)
        await event.reply(result_message)
    except ValueError:
        await event.reply(f"Ошибка: Неверный формат для {error_msg_base}.")
    except Exception as e:
        logger.error(f"Telethon: {error_msg_base} error: {e}", exc_info=True)
        await event.reply(f"Ошибка конвертации {error_msg_base}.")

async def convert_ton_to_rub(amount_str):
    ton_p, _ = get_ton_price()
    usd_r, _ = get_usd_rub_rate()
    if "N/A" in ton_p or "N/A" in usd_r:
        return "Не удалось получить курсы TON/RUB."
    return f"{float(amount_str) * float(ton_p.replace('$', '').replace(',', '')) * float(usd_r.split(' ')[0].replace('₽', '').strip()):,.2f} ₽"

async def convert_stars_to_rub(amount_str):
    return f"{float(amount_str) * STAR_TO_RUB_RATE:,.2f} ₽"

async def convert_usd_to_rub(amount_str):
    rate_str, _ = get_usd_rub_rate()
    if "N/A" in rate_str:
        return "Не удалось получить курс USD/RUB."
    return f"{float(amount_str) * float(rate_str.split(' ')[0].replace('₽', '').strip()):,.2f} ₽"

async def convert_eur_to_rub(amount_str):
    rate_str, _ = get_eur_rub_rate()
    if "N/A" in rate_str:
        return "Не удалось получить курс EUR/RUB."
    return f"{float(amount_str) * float(rate_str.split(' ')[0].replace('₽', '').strip()):,.2f} ₽"

async def telethon_ton_to_rub_handler(event):
    await generic_conversion_handler(event, TON_RUB_SEARCH_REGEX.search, convert_ton_to_rub, "TON в RUB")

async def telethon_stars_to_rub_handler(event):
    await generic_conversion_handler(event, STARS_TO_RUB_REGEX.search, convert_stars_to_rub, "Stars в RUB")

async def telethon_currency_to_rub_handler(event):
    if not event.text: return
    # _is_allowed_two_private_chats check is handled by add_event_handler's func param now.

    match = CURRENCY_TO_RUB_REGEX.search(event.text)
    if not match: return

    amount_str = match.group(1)
    symbol, code = match.group(2), match.group(3)
    conversion_func, name = (None, None)

    if symbol == '$' or (code and code.lower() == 'usd'):
        conversion_func, name = convert_usd_to_rub, "USD"
    elif symbol == '€' or (code and code.lower() == 'eur'):
        conversion_func, name = convert_eur_to_rub, "EUR"

    if conversion_func:
        await generic_conversion_handler(event, CURRENCY_TO_RUB_REGEX.search, conversion_func, f"{name} в RUB")


def get_db_connection():
    """Gets a new SQLite connection."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Access columns by name
    return conn

def init_hug_db():
    """Initializes the hug_tracker table and populates initial hug times."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hug_tracker (
                user_id INTEGER PRIMARY KEY,
                total_hug_seconds INTEGER NOT NULL DEFAULT 0,
                pinned_message_id INTEGER DEFAULT NULL
            )
        """)
        # Initial hug times in seconds for the two specific users
        # User 7245223987: 2 hours 8 minutes 38 seconds = 7718 seconds
        # User 1187759793: 6 hours 26 minutes 5 seconds = 23165 seconds
        initial_users_hugs = {
            7245223987: 7718,
            1187759793: 23165,
        }
        for user_id, seconds in initial_users_hugs.items():
            # Insert if not exists, or ignore if already there (e.g. from previous run)
            # This doesn't update existing values, it sets them if the user_id is new to the table.
            # If you want to RESET to these values on every startup, use INSERT OR REPLACE.
            # For accumulation, INSERT OR IGNORE is fine for first-time setup.
            cursor.execute(
                "INSERT OR IGNORE INTO hug_tracker (user_id, total_hug_seconds) VALUES (?, ?)",
                (user_id, seconds)
            )
        conn.commit()
    logger.info("Hug tracker database initialized/verified with initial times.")

def get_user_hug_data(user_id: int):
    """Retrieves hug data for a user. Creates a new record if an allowed user is missing."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT total_hug_seconds, pinned_message_id FROM hug_tracker WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return {"total_hug_seconds": row["total_hug_seconds"], "pinned_message_id": row["pinned_message_id"]}
        elif user_id in COUNTDOWN_TARGET_USERS_TELETHON:
            # This user is allowed but not in DB, create a default record.
            # This might happen if COUNTDOWN_TARGET_USERS_TELETHON is updated after init_hug_db ran.
            logger.warning(f"User {user_id} (allowed) not found in hug_tracker. Initializing with 0 seconds.")
            cursor.execute(
                "INSERT INTO hug_tracker (user_id, total_hug_seconds, pinned_message_id) VALUES (?, 0, NULL)",
                (user_id,)
            )
            conn.commit()
            return {"total_hug_seconds": 0, "pinned_message_id": None}
        return None # User not found and not in the special list

def update_user_hug_data(user_id: int, new_total_seconds: float, pinned_id: int = None):
    """Updates a user's total hug seconds and optionally their pinned message ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Use INSERT OR REPLACE to handle cases where the user might not exist yet,
        # or to update existing ones.
        # If pinned_id is not provided by the call, we want to keep the existing one if present.
        if pinned_id is not None:
             cursor.execute(
                """INSERT OR REPLACE INTO hug_tracker (user_id, total_hug_seconds, pinned_message_id)
                   VALUES (?, ?, ?)""",
                (user_id, int(round(new_total_seconds)), pinned_id)
            )
        else:
            # If pinned_id is None, we only update total_hug_seconds, keeping the existing pinned_message_id.
            # This requires a slightly different approach: UPDATE existing, or INSERT if not.
            cursor.execute(
                "UPDATE hug_tracker SET total_hug_seconds = ? WHERE user_id = ?",
                (int(round(new_total_seconds)), user_id)
            )
            if cursor.rowcount == 0: # User was not in the table
                 cursor.execute(
                    """INSERT INTO hug_tracker (user_id, total_hug_seconds, pinned_message_id)
                       VALUES (?, ?, NULL)""", # Pinned ID is unknown if user is new here
                    (user_id, int(round(new_total_seconds)))
                )
        conn.commit()

def format_duration_russian(total_seconds_val: float) -> str:
    """Formats a duration in seconds into a human-readable Russian string."""
    if not isinstance(total_seconds_val, (int, float)) or total_seconds_val < 0:
        logger.warning(f"format_duration_russian received invalid input: {total_seconds_val}. Defaulting to 0 seconds.")
        total_seconds_val = 0

    total_seconds_int = int(round(total_seconds_val))

    days = total_seconds_int // (24 * 3600)
    remaining_seconds = total_seconds_int % (24 * 3600)
    hours = remaining_seconds // 3600
    remaining_seconds %= 3600
    minutes = remaining_seconds // 60
    seconds_part = remaining_seconds % 60

    parts = []

    def pluralize(n_val, one_str, few_str, many_str) -> str:
        n_abs = abs(n_val)
        if n_abs % 10 == 1 and n_abs % 100 != 11:
            return f"{n_val} {one_str}"
        elif 2 <= n_abs % 10 <= 4 and (n_abs % 100 < 10 or n_abs % 100 >= 20):
            return f"{n_val} {few_str}"
        else:
            return f"{n_val} {many_str}"

    if days > 0:
        parts.append(pluralize(days, 'день', 'дня', 'дней'))
    if hours > 0:
        parts.append(pluralize(hours, 'час', 'часа', 'часов'))
    if minutes > 0:
        parts.append(pluralize(minutes, 'минута', 'минуты', 'минут'))

    if seconds_part > 0 or not parts: # Always show seconds if it's the only unit or non-zero
        parts.append(pluralize(seconds_part, 'секунда', 'секунды', 'секунд'))

    return ", ".join(parts) if parts else "0 секунд"


async def convert_amount_to_usd(amount: float, currency_symbol_or_code: str, loop) -> float:
    """Converts a given amount of a currency to USD."""
    currency_lower = currency_symbol_or_code.lower()

    # Existing currency functions (get_currency_rate_with_change, get_ton_price)
    # are blocking (use requests). We must run them in an executor.

    if currency_lower in ("доллар", "долларов", "usd", "$"):
        return amount
    elif currency_lower in ("евро", "eur", "€"):
        # Assuming get_currency_rate_with_change returns (rate_str, change_str)
        # We need EUR to USD rate.
        rate_str, _ = await loop.run_in_executor(None, get_currency_rate_with_change, "eur", "usd")
        if rate_str != "N/A" and rate_str is not None: # Ensure rate_str is not None
            return amount * float(rate_str)
        else:
            raise ValueError("Не удалось получить курс EUR/USD.")
    elif currency_lower in ("руб", "рублей", "рубля", "рублю", "rub", "₽"):
        # We need RUB to USD rate.
        rate_str, _ = await loop.run_in_executor(None, get_currency_rate_with_change, "rub", "usd")
        if rate_str != "N/A" and rate_str is not None: # Ensure rate_str is not None
            return amount * float(rate_str)
        else:
            raise ValueError("Не удалось получить курс RUB/USD.")
    elif currency_lower in ("тон", "ton"):
        ton_price_usd_str, _ = await loop.run_in_executor(None, get_ton_price) # get_ton_price returns (price_str_usd, change_str)
        if ton_price_usd_str != "N/A" and ton_price_usd_str is not None: # Ensure price_str is not None
            # Price string is like "$6.50", need to parse it
            return amount * float(ton_price_usd_str.replace('$', '').replace(',', ''))
        else:
            raise ValueError("Не удалось получить курс TON/USD.")
    elif currency_lower in ("звезд", "звёзд", "звезд", "stars"): # Corrected typo "звзд" to "звезд"
        return amount * STAR_TO_USD_RATE
    else:
        raise ValueError(f"Неизвестная или неподдерживаемая валюта: {currency_symbol_or_code}")

def calculate_hug_seconds_from_usd(usd_amount: float) -> float:
    """Calculates hug time in seconds based on USD amount (3 USD = 5 minutes)."""
    # total_minutes = usd_amount * (HUG_MINUTES_PER_UNIT / USD_PER_HUG_UNIT)
    total_minutes = usd_amount * (5 / 3)
    return total_minutes * 60  # convert minutes to seconds

async def telethon_plus_vremya_handler(event: events.NewMessage.Event):
    # Permission check (private chat with one of the two users)
    # is handled by `func=_is_allowed_two_private_chats` when adding the handler.
    user_id = event.chat_id # This is the ID of the target user

    match = PLUS_VREMYA_REGEX.match(event.text)
    # This check is redundant if pattern is used in add_event_handler, but good for safety
    if not match:
        return

    amount_str, currency_str = match.group(1), match.group(2)

    try:
        amount_val = float(amount_str)
        if amount_val <= 0:
            await event.reply("⚠️ Количество должно быть положительным числом.")
            return

        # Use the global `telethon_loop` (event loop for Telethon)
        usd_equivalent = await convert_amount_to_usd(amount_val, currency_str, telethon_loop)

        added_hug_seconds = calculate_hug_seconds_from_usd(usd_equivalent)

        if added_hug_seconds < 1: # If it's less than a second (e.g., very small amount)
            await event.reply(
                f"ℹ️ Сумма {amount_val} {currency_str} (${usd_equivalent:.2f}) слишком мала "
                f"для значимого добавления времени обнимашек (меньше 1 секунды)."
            )
            return

        user_data = get_user_hug_data(user_id)
        if not user_data:
            # This should ideally not happen if init_hug_db and get_user_hug_data are robust
            logger.error(f"Hug tracker: CRITICAL - No data for allowed user {user_id}. Command aborted.")
            await event.reply("❌ Внутренняя ошибка: не найдены данные для вашего пользователя. Обратитесь к администратору.")
            return

        current_total_seconds = user_data.get("total_hug_seconds", 0)
        pinned_message_id = user_data.get("pinned_message_id")

        new_total_hug_seconds = current_total_seconds + added_hug_seconds

        formatted_added_time = format_duration_russian(added_hug_seconds)
        formatted_new_total_time = format_duration_russian(new_total_hug_seconds)

        main_message_text = f"Ты мне должен {formatted_new_total_time} обнимашек {HUG_EMOJI}"

        new_pinned_id_to_store = pinned_message_id

        if pinned_message_id:
            try:
                await telethon_client.edit_message(user_id, pinned_message_id, main_message_text)
                logger.info(f"Hug tracker: Edited pinned message {pinned_message_id} for user {user_id}.")
            except Exception as e_edit: # Catch generic error, could be MessageNotModified, MessageIdInvalid, etc.
                logger.warning(f"Hug tracker: Failed to edit pinned_msg {pinned_message_id} for user {user_id}: {e_edit}. Will send new.")
                # Message might have been deleted by user or other issue. Try sending and pinning a new one.
                try:
                    sent_message = await telethon_client.send_message(user_id, main_message_text)
                    await telethon_client.pin_message(user_id, sent_message.id, notify=False)
                    new_pinned_id_to_store = sent_message.id
                    logger.info(f"Hug tracker: Sent and pinned new msg {new_pinned_id_to_store} for {user_id} after edit fail.")
                except Exception as e_send_pin_new:
                    logger.error(f"Hug tracker: Failed to send/pin new msg for {user_id} after edit fail: {e_send_pin_new}")
                    new_pinned_id_to_store = None # Failed to get a new pinned message
        else: # No existing pinned message
            try:
                sent_message = await telethon_client.send_message(user_id, main_message_text)
                await telethon_client.pin_message(user_id, sent_message.id, notify=False)
                new_pinned_id_to_store = sent_message.id
                logger.info(f"Hug tracker: Sent and pinned new message {new_pinned_id_to_store} for user {user_id}.")
            except ChatAdminRequiredError: # Should not happen in PMs if bot can send messages
                 logger.warning(f"Hug tracker: Could not pin message for user {user_id}. Bot might lack pin permission.")
                 new_pinned_id_to_store = None # Store sent_message.id if you want to try editing it next time
            except Exception as e_pin:
                logger.error(f"Hug tracker: Error pinning message for user {user_id}: {e_pin}")
                new_pinned_id_to_store = None

        # Update database with the new total seconds and the ID of the message that is currently pinned (or None)
        update_user_hug_data(user_id, new_total_hug_seconds, new_pinned_id_to_store)

        await event.reply(
            f"✅ Готово! К твоему долгу добавлено: {formatted_added_time}.\n"
            f"Теперь ты мне должен {formatted_new_total_time} обнимашек {HUG_EMOJI}"
        )

    except ValueError as ve: # Handles errors from float() or convert_amount_to_usd
        await event.reply(f"⚠️ Ошибка обработки: {ve}")
    except Exception as e:
        logger.error(f"Hug tracker: Unhandled error in +время handler for user {user_id}: {e}", exc_info=True)
        await event.reply("❌ Произошла непредвиденная внутренняя ошибка. Свяжитесь с разработчиком.")

EMOJI_SEARCH = "🔎"
EMOJI_PRICE_TAG = "🏷️"
EMOJI_INFO = "ℹ️"
EMOJI_WARNING = "⚠️"
EMOJI_ERROR = "❌"
EMOJI_COLLECTION = "🎨" # Or any other suitable emoji for collection
EMOJI_MODEL = "🧩"    # Or any other suitable emoji for model

async def telethon_floor_price_handler(event: events.NewMessage.Event):
    # Permission check is handled by `func=_is_allowed_two_private_chats`

    match = FLOOR_COMMAND_REGEX.match(event.text)
    if not match: # Should not happen if regex is correct in add_event_handler
        return

    collection_name_input = match.group(1).strip()
    model_name_input = match.group(2).strip() if match.group(2) else None

    logger.info(
        f"Telethon: Floor price cmd from {event.sender_id}. Collection: '{collection_name_input}', Model: '{model_name_input}'"
    )

    if not telethon_client or not telethon_client.is_connected():
        logger.warning("Telethon: Floor price cmd received but client not connected.")
        # Cannot reply via telethon_client if not connected.
        return

    # Send initial "Searching..." message to the user, this will be edited or followed by a new reply.
    # For simplicity, we'll send a new reply at the end.
    # intermediate_message = await event.reply(f"{EMOJI_SEARCH} Ищу флор для '{collection_name_input}'...")

    try:
        async with telethon_client.conversation(
            GIFT_ALERTS_BOT_USERNAME, timeout=GIFT_ALERTS_CONVERSATION_TIMEOUT_SECONDS
        ) as conv:
            # IMPORTANT CHANGE: Always send only the collection_name_input to @Gift_Alerts
            await conv.send_message(collection_name_input)

            try:
                response_message = await conv.get_response()
            except asyncio.TimeoutError:
                logger.warning(
                    f"Telethon: Timeout waiting for response from {GIFT_ALERTS_BOT_USERNAME} "
                    f"for collection '{collection_name_input}'."
                )
                await event.reply(
                    f"{EMOJI_WARNING} {GIFT_ALERTS_BOT_USERNAME} не ответил вовремя для запроса по '{collection_name_input}'."
                )
                return

            if not response_message or not response_message.text:
                logger.warning(
                    f"Telethon: Empty response from {GIFT_ALERTS_BOT_USERNAME} "
                    f"for collection '{collection_name_input}'."
                )
                await event.reply(
                    f"{EMOJI_WARNING} {GIFT_ALERTS_BOT_USERNAME} прислал пустой ответ для '{collection_name_input}'."
                )
                return

            response_text = response_message.text
            logger.debug(
                f"Telethon: Response from {GIFT_ALERTS_BOT_USERNAME} for '{collection_name_input}':\n{response_text[:500]}"
            )

            lines = response_text.splitlines()

            if not lines or not lines[0].startswith("Information about"):
                if "no results found" in response_text.lower() or \
                   "не найдено" in response_text.lower() or \
                   "not found" in response_text.lower():
                    logger.info(
                        f"Telethon: {GIFT_ALERTS_BOT_USERNAME} found no results for '{collection_name_input}'."
                    )
                    await event.reply(
                        f"{EMOJI_INFO} {GIFT_ALERTS_BOT_USERNAME} не нашел информацию по коллекции {EMOJI_COLLECTION} '{collection_name_input}'."
                    )
                else:
                    logger.warning(
                        f"Telethon: Unexpected response header from {GIFT_ALERTS_BOT_USERNAME} "
                        f"for '{collection_name_input}'. Response: {response_text[:200]}"
                    )
                    await event.reply(
                        f"{EMOJI_WARNING} {GIFT_ALERTS_BOT_USERNAME} дал неожиданный ответ для '{collection_name_input}'. "
                        "Не удалось обработать."
                    )
                return

            floor_prices_found = []

            for line in lines:
                model_line_match = GIFT_ALERTS_MODEL_LINE_REGEX.search(line)
                if model_line_match:
                    model_name_from_bot = model_line_match.group(1).strip()
                    floor_price_str = model_line_match.group(2)
                    try:
                        floor_price_float = float(floor_price_str)
                        floor_prices_found.append((model_name_from_bot, floor_price_float))
                    except ValueError:
                        logger.warning(
                            f"Telethon: Could not parse floor price '{floor_price_str}' "
                            f"for model '{model_name_from_bot}' from {GIFT_ALERTS_BOT_USERNAME} response."
                        )

            if not floor_prices_found:
                logger.info(
                    f"Telethon: No valid floor price lines found in {GIFT_ALERTS_BOT_USERNAME} "
                    f"response for '{collection_name_input}', though header was ok."
                )
                await event.reply(
                    f"{EMOJI_WARNING} Не удалось извлечь данные о флор ценах из ответа {GIFT_ALERTS_BOT_USERNAME} "
                    f"для '{collection_name_input}'."
                )
                return

            final_floor_price = None
            result_display_name = f"{EMOJI_COLLECTION} {collection_name_input}" # Default display name

            if model_name_input: # User specified a model
                found_specific_model = False
                for bot_model_name, price in floor_prices_found:
                    # Case-insensitive comparison for model names
                    if model_name_input.lower() == bot_model_name.lower():
                        final_floor_price = price
                        result_display_name = f"{EMOJI_COLLECTION} {collection_name_input} ({EMOJI_MODEL} {bot_model_name})"
                        found_specific_model = True
                        break
                if not found_specific_model:
                    logger.info(
                        f"Telethon: Model '{model_name_input}' not found in {GIFT_ALERTS_BOT_USERNAME} response "
                        f"for collection '{collection_name_input}'. Available models: {[m[0] for m in floor_prices_found]}"
                    )
                    await event.reply(
                        f"{EMOJI_WARNING} Модель {EMOJI_MODEL} '{model_name_input}' не найдена в списке для коллекции "
                        f"{EMOJI_COLLECTION} '{collection_name_input}' от {GIFT_ALERTS_BOT_USERNAME}."
                    )
                    return
            else: # User did not specify a model, find minimum (non-zero if possible) floor for the collection
                if floor_prices_found:
                    absolute_min_price_tuple = min(floor_prices_found, key=lambda item: item[1])

                    if absolute_min_price_tuple[1] == 0:
                        non_zero_floors = [item for item in floor_prices_found if item[1] > 0]
                        if non_zero_floors:
                            min_non_zero_price_tuple = min(non_zero_floors, key=lambda item: item[1])
                            final_floor_price = min_non_zero_price_tuple[1]
                            logger.info(f"Telethon: Absolute min floor was 0 for '{collection_name_input}'. Found smallest non-zero floor: {final_floor_price} TON for model '{min_non_zero_price_tuple[0]}'.")
                        else:
                            final_floor_price = 0
                            logger.info(f"Telethon: All floors are 0 or no non-zero floors found for '{collection_name_input}'. Reporting 0 TON.")
                    else:
                        final_floor_price = absolute_min_price_tuple[1]
                        logger.info(f"Telethon: Found min floor {final_floor_price} TON for model '{absolute_min_price_tuple[0]}' in collection '{collection_name_input}'.")
                # result_display_name remains the collection name (with emoji)

            if final_floor_price is not None:
                price_display_str = f"{int(final_floor_price)}" if final_floor_price == int(final_floor_price) else f"{final_floor_price:.2f}"
                reply_text = f"{result_display_name} {EMOJI_PRICE_TAG} флор: {price_display_str} TON"
                await event.reply(reply_text)
                logger.info(f"Telethon: Replied with floor price: \"{reply_text}\"")
            else:
                # This path should ideally be covered by earlier specific error messages
                # (e.g., model not found, no floor data extracted).
                logger.warning(
                    "Telethon: Logic error or no valid price determined, final_floor_price is None. "
                    f"Collection: '{collection_name_input}', Model: '{model_name_input}'"
                )
                # Avoid sending a generic error if a specific one was already sent.
                # This could happen if `floor_prices_found` was empty and `model_name_input` was None.
                if not model_name_input and not floor_prices_found: # Should have been caught by "No valid floor price lines"
                    await event.reply(f"{EMOJI_WARNING} Не удалось определить флор цену для '{collection_name_input}'.")


    except UserNotParticipantError:
        logger.error(f"Telethon: Bot is not a participant in conversation with {GIFT_ALERTS_BOT_USERNAME} or user blocked it.")
        await event.reply(f"{EMOJI_ERROR} Ошибка: не удается начать диалог с {GIFT_ALERTS_BOT_USERNAME}. Возможно, бот заблокирован или вы не его участник.")
    except ChatAdminRequiredError:
        logger.error(f"Telethon: Chat admin rights error with {GIFT_ALERTS_BOT_USERNAME}.")
        await event.reply(f"{EMOJI_ERROR} Ошибка прав администратора при общении с {GIFT_ALERTS_BOT_USERNAME}.")
    except (UsernameNotOccupiedError, UsernameInvalidError):
        logger.error(f"Telethon: Username {GIFT_ALERTS_BOT_USERNAME} is not occupied or invalid.")
        await event.reply(f"{EMOJI_ERROR} Бот {GIFT_ALERTS_BOT_USERNAME} не найден.")
    except Exception as e:
        logger.error(
            f"Telethon: General error in floor_price_handler for '{collection_name_input}': {type(e).__name__} - {e}",
            exc_info=True
        )
        await event.reply(f"{EMOJI_ERROR} Произошла непредвиденная ошибка при запросе флор цены: {type(e).__name__}.")

async def telethon_channel_monitor_handler(event):
    """
    This handler is for monitoring channels, not for user commands, so it doesn't
    need any user-based permission check.
    """
    global gifts_api_failing, user_id_to_notify
    if not event.text:
        return

    text_lower, ch_id, msg_id = event.text.lower(), event.chat_id, event.id
    link = f"https://t.me/c/{str(ch_id).replace('-100','')}/{msg_id}" if str(ch_id).startswith("-100") else f"(Link {ch_id}/{msg_id})"
    notif_txt, notif_desc = None, None

    with lock:
        api_fail, user_notify = gifts_api_failing, user_id_to_notify

    if ch_id == NFT_MONITOR_CHANNEL_ID:
        if UPGRADE_KEYWORD in text_lower:
            count = len(re.findall(re.escape(UPGRADE_COUNT_PHRASE), event.text, re.IGNORECASE))
            notif_txt = f"💎 Улучшения! {format_upgrade_count_string(count) if count > 0 else '(кол-во?)'}\n🔗 <a href='{link}'>Источник</a>"
            notif_desc="Telethon:NFTup"
        elif api_fail and FALLBACK_CHECK_KEYWORD in text_lower:
            notif_txt = f"⚠️🎁 Резерв: Новые подарки?\n<i>(API Подарков ?, Telethon канал)</i>\n🔗 <a href='{link}'>Сообщение</a>"
            notif_desc="Telethon:FallbackGift"
    elif ch_id == LOW_SUPPLY_CHANNEL_ID and LOW_SUPPLY_KEYWORD in text_lower:
        notif_txt = f"🚨 Скоро будет sold out! ЗАКУПАЙТЕСЬ\n🔗 <a href='{link}'>Ссылка на инфо</a>"
        notif_desc="Telethon:LowSupply"

    if notif_txt and telethon_client:
        try:
            # Using telethon_client.send_message directly from an async handler
            await telethon_client.send_message(TARGET_CHANNEL_ID, notif_txt, parse_mode='html', link_preview=False)
        except Exception as e:
            logger.error(f"Telethon send '{notif_desc}' to TARGET_CHANNEL_ID fail: {e}")
        if user_notify:
            try:
                await telethon_client.send_message(int(user_notify), notif_txt, parse_mode='html', link_preview=False)
            except Exception as e:
                logger.error(f"Telethon send '{notif_desc}' to user {user_notify} fail: {e}")

async def telethon_gift_command_handler(event):
    # _is_allowed_two_private_chats check is handled by add_event_handler func param
    m = GIFT_COMMAND_REGEX.match(event.text)
    if not m:
        return

    gift_identifier_str, receiver_id_str = m.group(1).strip(), m.group(2).strip()
    initiator_key = (event.chat_id, event.sender_id)

    logger.info(f"Telethon: Gift cmd '{event.text}' from {event.sender_id} for User ID {receiver_id_str}, identifier: '{gift_identifier_str}'")

    if "YOUR_TONNEL" in TONNEL_SENDER_INIT_DATA or "YOUR_TONNEL" in TONNEL_GIFT_SECRET:
        await event.reply("⚠️ Сервис подарков временно недоступен (неверная конфигурация).")
        return

    try:
        receiver_id_int = int(receiver_id_str)
    except ValueError:
        await event.reply("⚠️ Неверный формат ID пользователя. Укажите числовой ID.")
        return

    user_filters = {} # This will be passed to search_gifts_on_marketplace
    is_search_by_id = False
    try:
        potential_gift_id = int(gift_identifier_str)
        # Check if it looks like a gift_id (e.g., 7 digits or so)
        # This range is a guess, adjust if needed.
        if 100000 <= potential_gift_id <= 99999999: # Example plausible range
            user_filters = {"gift_id": potential_gift_id}
            is_search_by_id = True
            logger.info(f"Telethon: Gift search is by gift_id: {potential_gift_id}")
        else: # Numeric but doesn't look like a gift_id, treat as part of a name.
             raise ValueError("Number not in typical gift_id format/range")
    except ValueError:
        # Not a simple integer or not in gift_id range, so treat as name/attribute search
        logger.info(f"Telethon: Gift search is by name/attributes: '{gift_identifier_str}'")
        parsed_details = parse_gift_details_from_string(gift_identifier_str)

        if not parsed_details["name"]: # If parsing yields no primary name
            await event.reply(f"⚠️ Не удалось распознать имя подарка из '{gift_identifier_str}'. Попробуйте указать только основное имя.")
            return

        user_filters["gift_name"] = parsed_details["name"]
        if parsed_details["model"]:
            user_filters["model"] = parsed_details["model"]
        if parsed_details["backdrop"]:
            user_filters["backdrop"] = parsed_details["backdrop"]


    receiver_username_for_display = f"User ID {receiver_id_int}" # Default
    try:
        receiver_entity = await telethon_client.get_entity(receiver_id_int)
        if not isinstance(receiver_entity, TelethonUser):
             await event.reply(f"⚠️ Не удалось найти пользователя с ID {receiver_id_int} или это не пользователь.")
             return
        receiver_username_for_display = f"@{receiver_entity.username}" if receiver_entity.username else f"User ID {receiver_id_int}"

    except UserIdInvalidError:
        await event.reply(f"⚠️ Пользователь с ID {receiver_id_int} не найден (UserIdInvalidError).")
        return
    except PeerIdInvalidError:
        await event.reply(f"⚠️ Недействительный ID: {receiver_id_int} (PeerIdInvalidError).")
        return
    except ValueError:
        await event.reply(f"⚠️ Неверный формат ID пользователя для поиска: {receiver_id_int}")
        return
    except Exception as e_user:
        logger.error(f"Telethon: Error resolving user ID {receiver_id_int}: {type(e_user).__name__} - {e_user}", exc_info=True)
        await event.reply(f"⚠️ Ошибка при поиске пользователя с ID {receiver_id_int}.")
        return

    try:
        search_term_display = f"ID {user_filters['gift_id']}" if is_search_by_id else f"'{gift_identifier_str}'"
        await event.reply(f"🔎 Ищу подарок {search_term_display} для {receiver_username_for_display}...")
        sender_instance = TonnelGiftSender(TONNEL_SENDER_INIT_DATA, TONNEL_GIFT_SECRET)
        res = await sender_instance.search_gifts_on_marketplace(user_filters) # Pass user_filters here

        logger.info(f"Telethon: Tonnel search result for identifier '{gift_identifier_str}' (filters: {user_filters}) by {event.sender_id}: {str(res)[:1000]}")

        if res.get("status") != "success" or not res.get("gifts"):
            user_message = res.get('message', 'Произошла неизвестная ошибка API при поиске.')
            logger.warning(f"Telethon: Gift search failed for identifier '{gift_identifier_str}'. API responded with: '{user_message}'. Full response from search_gifts_on_marketplace: {str(res)[:1000]}")
            await event.reply(f"⚠️ Не удалось найти подарок {search_term_display}. {user_message}")
            return

        gifts_found = res["gifts"]
        if is_search_by_id:
            if len(gifts_found) == 1 and gifts_found[0].get("gift_id") == user_filters["gift_id"]:
                cheap_gift = gifts_found[0]
            else:
                logger.warning(f"Telethon: Search by ID {user_filters['gift_id']} returned {len(gifts_found)} gifts or mismatched ID. Response: {str(gifts_found)[:500]}")
                await event.reply(f"⚠️ Не удалось найти подарок с ID {user_filters['gift_id']} или он уже продан/недоступен.")
                return
        else:
            cheap_gift = gifts_found[0]


        disp_name_parts = []
        if cheap_gift.get('gift_name'): disp_name_parts.append(cheap_gift['gift_name'])
        if cheap_gift.get('model'): disp_name_parts.append(cheap_gift['model'])
        if cheap_gift.get('backdrop'): disp_name_parts.append(cheap_gift['backdrop'])

        full_gift_display_name = " ".join(disp_name_parts).strip()
        if not full_gift_display_name: # Fallback if all parts are empty
            full_gift_display_name = gift_identifier_str if not is_search_by_id else f"Подарок ID {cheap_gift.get('gift_id')}"


        tonnel_gift_deep_link = f"https://t.me/tonnel_network_bot/gift?startapp={cheap_gift.get('gift_id','000')}"

        confirm_msg = (f"Найден подарок: <b>{full_gift_display_name}</b> (ID: {cheap_gift.get('gift_id','N/A')}){_newline_char}"
                       f"<a href='{tonnel_gift_deep_link}'>Открыть подарок в Tonnel Network</a>{_newline_char}"
                       f"Цена: <b>{cheap_gift['price']:.2f} TON</b>{_newline_char}{_newline_char}"
                       f"Получатель: {receiver_username_for_display}{_newline_char}Напишите \"<b>да</b>\" или \"<b>нет</b>\" ({PENDING_GIFT_TIMEOUT_SECONDS//60} мин).")

        pending_gift_purchases[initiator_key] = {
            "gift": cheap_gift,
            "recv_id": receiver_id_int,
            "recv_user_display": receiver_username_for_display,
            "req_identifier": gift_identifier_str,
            "ts": time.time()
        }
        await event.reply(confirm_msg, parse_mode='html', link_preview=False)
    except Exception as e:
        logger.error(f"Telethon: Critical error in Tonnel gift command flow for identifier '{gift_identifier_str}': {e}", exc_info=True)
        await event.reply(f"⚠️ Произошла критическая ошибка при обработке команды подарка: {str(e)}")

async def telethon_confirm_gift_handler(event):
    # _is_allowed_two_private_chats check is handled by add_event_handler func param
    initiator_key = (event.chat_id, event.sender_id)

    for k,d in list(pending_gift_purchases.items()):
        if time.time()-d["ts"] > PENDING_GIFT_TIMEOUT_SECONDS:
            del pending_gift_purchases[k]
            logger.info(f"Telethon: Removed expired pending gift for key {k}")

    pending = pending_gift_purchases.get(initiator_key)
    if not pending:
        return

    user_response = event.text.lower().strip()

    if user_response == "нет":
        del pending_gift_purchases[initiator_key]
        await event.reply("ℹ️ Покупка подарка отменена.")
        logger.info(f"Telethon: Gift purchase cancelled by user {event.sender_id} for key {initiator_key}.")
        return

    if user_response != "да":
        return


    logger.info(f"Telethon: Gift confirm 'да' from {event.sender_id} for pending purchase.")
    gift, recv_id, recv_user_display, req_identifier = pending["gift"], pending["recv_id"], pending["recv_user_display"], pending["req_identifier"]
    del pending_gift_purchases[initiator_key]

    sender_instance = TonnelGiftSender(TONNEL_SENDER_INIT_DATA, TONNEL_GIFT_SECRET)
    try:
        await event.reply(f"⏳ Покупаю подарок (был запрошен как '{req_identifier}') для {recv_user_display}...")
        res = await sender_instance.execute_purchase(gift, recv_id)
        if res.get("status") == "success":
            await event.reply(f"✅ {res.get('message', f'Подарок (был запрошен как ''{req_identifier}'') отправлен {recv_user_display}!')}")
        else:
            user_message = res.get('message', 'Не удалось совершить покупку.')
            await event.reply(f"❌ Ошибка покупки: {user_message}")
            logger.error(f"Tonnel purchase fail response: {res}")
    except Exception as e:
        logger.error(f"Telethon: Err Tonnel purchase exec: {e}", exc_info=True)
        await event.reply(f"⚠️ Критическая ошибка покупки: {e}")

# --- Telethon Main Logic ---
async def run_telethon_client_main_logic():
    global telethon_client, telethon_loop, MY_ID_TELETHON
    telethon_loop = asyncio.get_event_loop()
    telethon_client = TelegramClient(TELETHON_SESSION_NAME, TELETHON_API_ID, TELETHON_API_HASH, loop=telethon_loop)
    logger.info("Telethon: Starting client...")
    try:
        await telethon_client.start()
    except Exception as e:
        logger.error(f"Telethon: Client start fail: {e}", exc_info=True)
        return

    if await telethon_client.is_user_authorized():
        me = await telethon_client.get_me()
        if me:
            MY_ID_TELETHON = me.id
            logger.info(f"Telethon: Client authorized as: {me.first_name} (ID: {MY_ID_TELETHON})")
            init_hug_db()
        else:
            logger.error("Telethon: client.get_me() returned None after authorization.")
            if telethon_client.is_connected(): await telethon_client.disconnect()
            return

        # --- TELETHON EVENT HANDLERS REGISTRATION ---
        # ALL handlers must be added here after telethon_client is initialized
        logger.info("Telethon: Registering event handlers...")


        telethon_client.add_event_handler(
            telethon_plus_vremya_handler,
            events.NewMessage(
                pattern=PLUS_VREMYA_REGEX,
                func=_is_allowed_two_private_chats # This function checks if it's a private message from one of the allowed users
            )
        )
        telethon_client.add_event_handler(
            telethon_floor_price_handler,
            events.NewMessage(
                pattern=FLOOR_COMMAND_REGEX,
                func=_is_allowed_two_private_chats # Ensures it's from allowed users in PM
            )
        )

        logger.info("Telethon: All event handlers registered.")
        # Commands for the two specific private chats
        telethon_client.add_event_handler(
            telethon_penis_handler,
            events.NewMessage(
                pattern=PENIS_REGEX,
                func=_is_allowed_two_private_chats # Use the new specific check
            )
        )
        telethon_client.add_event_handler(
            telethon_skolko_ostalos_handler,
            events.NewMessage(
                pattern=SKOLKO_OSTALOS_REGEX,
                func=_is_allowed_two_private_chats # Use the new specific check
            )
        )
        telethon_client.add_event_handler(
            telethon_calculator_handler,
            events.NewMessage(
                pattern=CALCULATOR_REGEX,
                func=_is_allowed_two_private_chats # Use the new specific check
            )
        )

        # Helper function for currency checks with permission
        async def ton_rub_check_func(event):
            return event.text and TON_RUB_SEARCH_REGEX.search(event.text) and await _is_allowed_two_private_chats(event)
        telethon_client.add_event_handler(telethon_ton_to_rub_handler, events.NewMessage(func=ton_rub_check_func))

        async def stars_rub_check_func(event):
            return event.text and STARS_TO_RUB_REGEX.search(event.text) and await _is_allowed_two_private_chats(event)
        telethon_client.add_event_handler(telethon_stars_to_rub_handler, events.NewMessage(func=stars_rub_check_func))

        async def currency_rub_check_func(event):
            return event.text and CURRENCY_TO_RUB_REGEX.search(event.text) and await _is_allowed_two_private_chats(event)
        telethon_client.add_event_handler(telethon_currency_to_rub_handler, events.NewMessage(func=currency_rub_check_func))

        # Gift commands
        telethon_client.add_event_handler(
            telethon_gift_command_handler,
            events.NewMessage(
                pattern=GIFT_COMMAND_REGEX,
                func=_is_allowed_two_private_chats # Use the new specific check
            )
        )
        telethon_client.add_event_handler(
            telethon_confirm_gift_handler,
            events.NewMessage(
                pattern=CONFIRM_GIFT_REGEX,
                func=_is_allowed_two_private_chats # Use the new specific check
            )
        )

        # Channel monitor handler (not restricted by user ID, monitors channels)
        telethon_client.add_event_handler(
            telethon_channel_monitor_handler,
            events.NewMessage(chats=[NFT_MONITOR_CHANNEL_ID, LOW_SUPPLY_CHANNEL_ID])
        )

        logger.info("Telethon: All event handlers registered.")
        await telethon_client.run_until_disconnected()
    else:
        logger.error("Telethon: Client authorization failed.")

    if telethon_client.is_connected():
        await telethon_client.disconnect()
    logger.info("Telethon: Client stopped.")

def telethon_thread_runner():
    logger.info("Telethon: Client thread starting.")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_telethon_client_main_logic())
    except Exception as e:
        logger.error(f"Telethon: Critical error in client thread: {e}", exc_info=True)
    finally:
        if 'loop' in locals() and loop.is_running():
            loop.close()
    logger.info("Telethon: Client thread finished.")

# --- Scheduler Setup ---
def run_scheduler():
    logger.info("Scheduler thread started.")
    try:
        schedule.every().day.at("11:11", MOSCOW_TZ).do(send_timed_message_telebot, message_text_header="✨ 11:11 МСК ✨")
        schedule.every().day.at("22:22", MOSCOW_TZ).do(send_timed_message_telebot, message_text_header="✨ 22:22 МСК ✨")
        schedule.every().day.at("00:00", MOSCOW_TZ).do(send_daily_telethon_countdown_sync)
        logger.info("Scheduled jobs initialized.")
    except Exception as e:
        logger.error(f"Scheduler setup fail: {e}", exc_info=True)
        return

    while True:
        try:
            schedule.run_pending()
            time.sleep(30)
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}", exc_info=True)
            time.sleep(10)

# --- Telebot Command Handlers ---
def check_allowed_main_commands_user(message):
    """
    Checks if the message is from the NOW_COMMAND_ALLOWED_USER_ID and is a private chat.
    This applies to /start, /now, /test, /status.
    """
    if message.chat.type != 'private':
        notify_generic(message.chat.id, "ℹ️ Эта команда доступна только в личных сообщениях с ботом.", "private chat only command")
        logger.warning(f"Telebot: Command '{message.text}' from {message.from_user.id} in non-private chat {message.chat.id}. Command is private-only.")
        return False

    if message.from_user.id != NOW_COMMAND_ALLOWED_USER_ID:
        notify_generic(message.chat.id, "❌ У вас нет прав для выполнения этой команды.", "unauthorized command")
        logger.warning(f"Telebot: Unauthorized command '{message.text}' from {message.from_user.id} in chat {message.chat.id}. Not {NOW_COMMAND_ALLOWED_USER_ID}.")
        return False
    return True


@bot.message_handler(commands=['start', 'monitor'])
def start_command(m):
    if not check_allowed_main_commands_user(m): return # Permission check
    global user_id_to_notify, monitoring_active, monitor_thread
    logger.info(f"TelebotCmd:{m.text.split()[0]} from {m.from_user.id} in {m.chat.id}")

    with lock:
        active, notify_uid = monitoring_active, user_id_to_notify
    if active:
        notify_generic(m.chat.id, f"ℹ️ Мониторинг подарков уже активен. Уведомления приходят пользователю: {notify_uid}.")
    else:
        notify_generic(m.chat.id, "🚀 Запускаю мониторинг подарков... Вы будете уведомлены о новых подарках.")
        with lock:
            user_id_to_notify=m.chat.id
            monitoring_active=True
            gifts_api_failing=False
        if not (monitor_thread and monitor_thread.is_alive()):
            monitor_thread = threading.Thread(target=check_for_new_gifts_loop, name="GiftMonThread", daemon=True)
            monitor_thread.start()
        else:
            logger.warning("start_command: monitor_thread was alive while monitoring_active was false. This is unusual.")


@bot.message_handler(commands=['stop'])
def stop_monitoring_command(m):
    if not check_allowed_main_commands_user(m): return # Permission check
    global monitoring_active, monitor_thread, user_id_to_notify
    logger.info(f"TelebotCmd:/stop from {m.from_user.id} in {m.chat.id}")

    with lock:
        if not monitoring_active:
            notify_generic(m.chat.id, "ℹ️ Мониторинг подарков уже не активен.")
            return
        # The user_id_to_notify check is redundant here because check_allowed_main_commands_user already
        # ensures only NOW_COMMAND_ALLOWED_USER_ID can run this, and that user is the only one who can start monitoring.
        notify_generic(m.chat.id, "🛑 Останавливаю мониторинг подарков...")
        monitoring_active=False

    if monitor_thread and monitor_thread.is_alive():
        logger.info("Waiting for gift monitor thread to finish...")
        monitor_thread.join(timeout=10)
        if monitor_thread.is_alive():
            logger.warning("Gift monitor thread did not stop in time.")

    with lock:
        user_id_to_notify=None

    notify_generic(m.chat.id, "✅ Мониторинг подарков остановлен.")
    logger.info("Gift monitoring stopped by user command.")

@bot.message_handler(
    func=lambda m: m.text is not None and \
                   m.entities is not None and \
                   len(m.entities) > 0 and \
                   all(e.type == "custom_emoji" for e in m.entities) and \
                   sum(e.length for e in m.entities) == len(m.text),
    content_types=['text']
)
def handle_premium_emoji_ids(message: types.Message):
    if not check_allowed_main_commands_user(message): return # Permission check
    """
    Handles messages that consist exclusively of one or more premium Telegram emojis.
    Replies with the custom_emoji_id for each emoji, one per line.
    """
    logger.info(
        f"Telebot: Received message {message.message_id} from {message.from_user.id} in chat {message.chat.id} "
        f"potentially containing only premium emojis. Text: '{message.text}'"
    )

    emoji_ids = []
    if message.entities:
        for entity in message.entities:
            if entity.type == "custom_emoji" and hasattr(entity, 'custom_emoji_id'):
                emoji_ids.append(str(entity.custom_emoji_id))
            else:
                logger.warning(
                    f"Telebot: In handle_premium_emoji_ids, found non-custom_emoji entity or missing custom_emoji_id "
                    f"despite filter. Entity: {entity}. Message ID: {message.message_id}"
                )

    if emoji_ids:
        reply_text = "\n".join(emoji_ids)
        full_reply = f"IDs ваших премиум эмодзи:\n{reply_text}"

        notify_generic(message.chat.id, full_reply,
                       description="premium emoji IDs reply",
                       reply_to_message_id=message.message_id)
        logger.info(
            f"Telebot: Sent premium emoji IDs for message {message.message_id} "
            f"in chat {message.chat.id}. IDs: {', '.join(emoji_ids)}"
        )
    else:
        logger.warning(
            f"Telebot: Premium emoji handler (handle_premium_emoji_ids) was triggered for "
            f"message {message.message_id} in chat {message.chat.id}, "
            f"but no emoji_ids could be extracted. This might indicate a logic mismatch "
            f"or an edge case with message entities. Text: '{message.text}', Entities: {message.entities}"
        )

@bot.message_handler(commands=['status'])
def status_command(m):
    if not check_allowed_main_commands_user(m): return # Permission check
    logger.info(f"TelebotCmd:/status from {m.from_user.id} in {m.chat.id}")
    with lock:
        mon_s, notify_u, api_f = monitoring_active, user_id_to_notify, gifts_api_failing

    telethon_countdown_text = "N/A (Telethon client not ready)"
    if telethon_client and telethon_client.is_connected() and telethon_loop:
        try:
            # Use run_coroutine_threadsafe to run an async function from a sync context
            # and .result() to get its value, adding a timeout to prevent potential hangs.
            telethon_countdown_text = asyncio.run_coroutine_threadsafe(
                get_telethon_countdown_message_text_generic(), telethon_loop
            ).result(timeout=5)
        except Exception as e:
            logger.error(f"Failed to get Telethon countdown in status command: {e}", exc_info=True)
            telethon_countdown_text = "Ошибка получения отсчета (Telethon)"


    status_msg = (f"📊 <b>Статус системы</b>{_newline_char}{_newline_char}"
                  f"🎁 <b>Мониторинг подарков (Telebot API):</b> {'🟢 Активен' if mon_s else '🔴 Неактивен'}{_newline_char}"
                  f"👤 Уведомления о подарках для: {notify_u if notify_u else 'Никто'}{_newline_char}"
                  f"📡 API Подарков (Telebot): {'✅ В норме' if not api_f else '⚠️ Обнаружены ошибки!'}{_newline_char}{_newline_char}"
                  f"🤖 <b>Клиент Telethon:</b> {'🟢 Подключен' if telethon_client and telethon_client.is_connected() else '🔴 Отключен или ошибка'}{_newline_char}"
                  f"🆔 Telethon User ID: {MY_ID_TELETHON if MY_ID_TELETHON else 'Не определен'}{_newline_char}"
                  f"⏳ {TELETHON_HEART_EMOJI} Обратный отсчет (Telethon): {telethon_countdown_text}")
    notify_generic(m.chat.id, status_msg, "status report", "HTML")

@bot.message_handler(commands=['test'])
def test_command(m):
    if not check_allowed_main_commands_user(m): return # Permission check
    logger.info(f"TelebotCmd:/test from {m.from_user.id} in {m.chat.id}")
    try:
        bot.send_chat_action(m.chat.id, 'typing')
        send_timed_message_telebot("🧪 <b>Тестовая ежедневная сводка</b> 🧪")
        notify_generic(m.chat.id, f"✅ Тестовая сводка отправлена в канал {TARGET_CHANNEL_ID}.")
    except Exception as e:
        logger.error(f"TelebotCmd:/test error: {e}", exc_info=True)
        notify_generic(m.chat.id, f"❌ Ошибка при выполнении /test: {e}")

@bot.message_handler(commands=['now'])
def now_command(m):
    if not check_allowed_main_commands_user(m): return # Permission check
    logger.info(f"TelebotCmd:/now from {m.from_user.id} in {m.chat.id}")
    try:
        bot.send_chat_action(m.chat.id, 'typing')
        # Run send_timed_message_telebot in a separate thread because it performs blocking I/O (requests)
        threading.Thread(target=send_timed_message_telebot, args=(f"📊 Ежедневная сводка по запросу ({datetime.now(MOSCOW_TZ):%H:%M:%S})",), daemon=True).start()
        notify_generic(m.chat.id, f"✅ Сводка формируется и будет отправлена в канал {TARGET_CHANNEL_ID}...")
    except Exception as e:
        logger.error(f"TelebotCmd:/now error: {e}", exc_info=True)
        notify_generic(m.chat.id, f"❌ Ошибка при выполнении /now: {e}")

@bot.message_handler(func=lambda m: m.chat.id == TARGET_REPLY_GROUP_ID and m.from_user.id == TARGET_REPLY_USER_ID)
def handle_specific_user_in_group(m):
    # This handler is specific to a user and a group, not a general command, so it doesn't use check_allowed_main_commands_user
    logger.info(f"Telebot: Specific user {m.from_user.id} triggered reply in group {m.chat.id}")
    notify_generic(m.chat.id, TARGET_REPLY_TEXT, "specific user reply", reply_to_message_id=m.message_id)

# --- Flask Webhook Route ---
@app.route(WEBHOOK_URL_PATH, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_data().decode('utf-8')
        update = types.Update.de_json(json_string)
        # Process the update. telebot's process_new_updates is blocking,
        # but for simple bots, it's often fine to run directly in the webhook handler.
        # For high-throughput bots, you might offload this to a queue/thread pool.
        bot.process_new_updates([update])
        return '!', 200 # Return 200 OK to Telegram
    else:
        abort(403) # Forbidden for non-JSON requests

# --- Main Execution ---
if __name__ == '__main__':
    logger.info("--- Bot System Starting ---")
    if not bot:
        logger.critical("Telebot Bot initialization failed. Exiting.")
        exit(1)

    # Start background threads for monitoring and scheduling
    scheduler_thread = threading.Thread(target=run_scheduler, name="SchedulerThread", daemon=True)
    scheduler_thread.start()
    time.sleep(1) # Give scheduler a moment to set up jobs

    telethon_thread = threading.Thread(target=telethon_thread_runner, name="TelethonClientThread", daemon=True)
    telethon_thread.start()
    time.sleep(2) # Give Telethon client a moment to start and connect

    # Set up webhook for Telebot
    try:
        # Remove any old webhook to prevent conflicts, then set the new one
        bot.remove_webhook()
        time.sleep(0.1) # Small delay to ensure removal propagates
        webhook_url = WEBHOOK_URL_BASE + WEBHOOK_URL_PATH
        bot.set_webhook(url=webhook_url)
        logger.info(f"Telebot Webhook set to: {webhook_url}")
    except Exception as e:
        logger.critical(f"Telebot Webhook setup FAILED: {e}", exc_info=True)
        # If webhook fails to set, the bot cannot receive updates via webhook.
        # It's critical to exit or log prominently.
        exit(1)

    # Start Flask web server (this call is blocking)
    logger.info(f"Starting Flask app on {WEBHOOK_HOST}:{WEBHOOK_PORT}...")
    app.run(host=WEBHOOK_HOST, port=WEBHOOK_PORT)

    logger.info("--- Bot System Stopped ---")
