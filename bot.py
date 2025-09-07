import asyncio
import logging
import os
import re
import sqlite3
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime
import traceback
import html
import json

from flask import Flask, request
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
from telethon.tl.types import Updates, UpdateNewMessage, UpdateNewChannelMessage, UpdateEditMessage, UpdateEditChannelMessage, UpdateDeleteMessages

# Logging setup
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app for Koyeb health check
flask_app = Flask(__name__)

@flask_app.route('/health')
def health():
    return 'OK', 200

# Webhook endpoint (uncomment to use webhooks instead of polling)
# @flask_app.route('/webhook', methods=['POST'])
# async def webhook():
#     json_string = await request.get_json()
#     update = Update.de_json(json_string, app.bot)
#     await app.process_update(update)
#     return 'OK'

def run_flask():
    flask_app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))

# Database setup
DB_FILE = 'forward_bot.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 user_id INTEGER PRIMARY KEY,
                 phone TEXT,
                 session TEXT,
                 sources TEXT DEFAULT '[]',
                 destinations TEXT DEFAULT '[]',
                 replacements TEXT DEFAULT '{}',
                 blacklist TEXT DEFAULT '[]',
                 whitelist TEXT DEFAULT '[]',
                 user_filter TEXT DEFAULT '[]',
                 beginning_text TEXT DEFAULT '',
                 ending_text TEXT DEFAULT '',
                 delay INTEGER DEFAULT 0,
                 edit_enabled BOOLEAN DEFAULT 0,
                 delete_enabled BOOLEAN DEFAULT 0,
                 status TEXT DEFAULT 'STOPPED'
                 )''')
    conn.commit()
    conn.close()

init_db()

# Helper functions
def get_user_config(user_id: int) -> Dict:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'user_id': row[0],
            'phone': row[1],
            'session': row[2],
            'sources': eval(row[3]) if row[3] else [],
            'destinations': eval(row[4]) if row[4] else [],
            'replacements': eval(row[5]) if row[5] else {},
            'blacklist': eval(row[6]) if row[6] else [],
            'whitelist': eval(row[7]) if row[7] else [],
            'user_filter': eval(row[8]) if row[8] else [],
            'beginning_text': row[9] or '',
            'ending_text': row[10] or '',
            'delay': row[11] or 0,
            'edit_enabled': bool(row[12]),
            'delete_enabled': bool(row[13]),
            'status': row[14] or 'STOPPED'
        }
    return {
        'user_id': user_id,
        'phone': '',
        'session': '',
        'sources': [],
        'destinations': [],
        'replacements': {},
        'blacklist': [],
        'whitelist': [],
        'user_filter': [],
        'beginning_text': '',
        'ending_text': '',
        'delay': 0,
        'edit_enabled': False,
        'delete_enabled': False,
        'status': 'STOPPED'
    }

def update_user_config(user_id: int, config: Dict):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO users (user_id, phone, session, sources, destinations, replacements, blacklist, whitelist,
                 user_filter, beginning_text, ending_text, delay, edit_enabled, delete_enabled, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, config.get('phone', ''), config.get('session', ''), str(config['sources']), str(config['destinations']),
               str(config['replacements']), str(config['blacklist']), str(config['whitelist']), str(config['user_filter']),
               config['beginning_text'], config['ending_text'], config['delay'],
               int(config['edit_enabled']), int(config['delete_enabled']), config['status']))
    conn.commit()
    conn.close()

# Telethon client management
clients: Dict[int, TelegramClient] = {}

async def get_client(user_id: int, config: Dict) -> Optional[TelegramClient]:
    if user_id in clients:
        return clients[user_id]
    if not config.get('session'):
        return None
    api_id = os.environ.get('API_ID', 'YOUR_API_ID')
    api_hash = os.environ.get('API_HASH', 'YOUR_API_HASH')
    client = TelegramClient(f'sessions/{user_id}', api_id, api_hash)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return None
        clients[user_id] = client
        return client
    except Exception as e:
        logger.error(f"Client setup error for {user_id}: {e}")
        return None

# Forwarding logic
message_id_maps: Dict[int, Dict] = {}

def apply_filters(text: str, config: Dict) -> Optional[str]:
    if not text:
        return text
    for pattern in config['blacklist']:
        if re.search(pattern, text, re.IGNORECASE):
            return None
    if config['whitelist']:
        if not any(re.search(pattern, text, re.IGNORECASE) for pattern in config['whitelist']):
            return None
    for old, new in config['replacements'].items():
        text = re.sub(old, new, text, flags=re.IGNORECASE)
    if config['beginning_text']:
        text = config['beginning_text'] + '\n' + text
    if config['ending_text']:
        text = text + '\n' + config['ending_text']
    return text

async def forward_message(client: TelegramClient, update, config: Dict, context: ContextTypes.DEFAULT_TYPE):
    if config['status'] != 'RUNNING':
        return
    message = None
    if isinstance(update, UpdateNewMessage) or isinstance(update, UpdateNewChannelMessage):
        message = update.message
    if not message or message.chat_id not in config['sources']:
        return
    if config['user_filter'] and message.from_id and message.from_id.user_id not in config['user_filter']:
        return
    text = message.message or ''
    filtered_text = apply_filters(text, config)
    if filtered_text is None and not message.photo and not message.video and not message.document:
        return
    for dest_id in config['destinations']:
        try:
            if message.photo:
                photo = max(message.photo.sizes, key=lambda s: s.size).file_id
                sent_msg = await client.send_file(dest_id, photo, caption=filtered_text if filtered_text != text else None)
            elif message.video:
                sent_msg = await client.send_file(dest_id, message.video.file_id, caption=filtered_text if filtered_text != text else None)
            elif message.document:
                sent_msg = await client.send_file(dest_id, message.document.file_id, caption=filtered_text if filtered_text != text else None)
            elif text:
                sent_msg = await client.send_message(dest_id, filtered_text or text)
            else:
                continue
            if config['edit_enabled'] or config['delete_enabled']:
                user_id = config['user_id']
                if user_id not in message_id_maps:
                    message_id_maps[user_id] = {}
                message_id_maps[user_id][(message.chat_id, message.id)] = (dest_id, sent_msg.id)
            time.sleep(config['delay'])
        except Exception as e:
            logger.error(f"Error forwarding to {dest_id}: {e}")
            await context.bot.send_message(config['user_id'], f"Error forwarding to {dest_id}. Check permissions.")

async def handle_edit(client: TelegramClient, update, config: Dict):
    if config['status'] != 'RUNNING' or not config['edit_enabled']:
        return
    message = None
    if isinstance(update, UpdateEditMessage) or isinstance(update, UpdateEditChannelMessage):
        message = update.message
    if not message or message.chat_id not in config['sources']:
        return
    user_id = config['user_id']
    key = (message.chat_id, message.id)
    if user_id in message_id_maps and key in message_id_maps[user_id]:
        dest_id, sent_id = message_id_maps[user_id][key]
        new_text = apply_filters(message.message or '', config)
        if new_text:
            try:
                await client.edit_message(dest_id, sent_id, new_text)
            except:
                pass

async def handle_delete(client: TelegramClient, update: UpdateDeleteMessages, config: Dict):
    if config['status'] != 'RUNNING' or not config['delete_enabled']:
        return
    user_id = config['user_id']
    if user_id not in message_id_maps:
        return
    for msg_id in update.messages:
        for src_id in config['sources']:
            key = (src_id, msg_id)
            if key in message_id_maps[user_id]:
                dest_id, sent_id = message_id_maps[user_id][key]
                try:
                    await client.delete_messages(dest_id, sent_id)
                    del message_id_maps[user_id][key]
                except:
                    pass

async def telethon_handler(event, context: ContextTypes.DEFAULT_TYPE):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT user_id, session FROM users WHERE ? IN (eval(sources)) AND status = "RUNNING"', (event.chat_id))
    users = c.fetchall()
    conn.close()
    for user_id, _ in users:
        config = get_user_config(user_id)
        client = await get_client(user_id, config)
        if not client:
            continue
        if isinstance(event, (UpdateNewMessage, UpdateNewChannelMessage)):
            await forward_message(client, event, config, context)
        elif isinstance(event, (UpdateEditMessage, UpdateEditChannelMessage)):
            await handle_edit(client, event, config)
        elif isinstance(event, UpdateDeleteMessages):
            await handle_delete(client, event, config)

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Exception while handling an update:", exc_info=context.error)
    if isinstance(context.error, telegram.error.Conflict):
        logger.warning("Polling conflict detected. Ensure only one instance is running.")
        dev_chat_id = os.environ.get('ADMIN_ID')
        if dev_chat_id:
            try:
                await context.bot.send_message(
                    int(dev_chat_id), "Bot conflict: Only one instance should run. Check Koyeb deploys."
                )
            except:
                pass
    tb_list = traceback.format_exception(None, context.error, context.error.__traceback__)
    tb_string = "".join(tb_list)
    dev_chat_id = os.environ.get('ADMIN_ID')
    if dev_chat_id:
        update_str = update.to_dict() if isinstance(update, Update) else str(update)
        message = (
            "An exception was raised while handling an update:\n"
            f"<pre>update = {html.escape(json.dumps(update_str, indent=2, ensure_ascii=False))}</pre>\n\n"
            f"<pre>{html.escape(tb_string)}</pre>"
        )
        try:
            await context.bot.send_message(
                chat_id=int(dev_chat_id), text=message, parse_mode='HTML'
            )
        except:
            pass

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text("Welcome to Auto Forwarder Bot! Use /authorize to log in with your phone number. Pin source/destination chats for easy selection. Check /features.")

async def authorize(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    if config.get('phone'):
        await update.message.reply_text("You're already logged in. Use /incoming to set source chats or /config to view setup.")
        return
    await update.message.reply_text("Enter your phone number (e.g., +91876543210):")

async def handle_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    phone = update.message.text
    if not phone.startswith('+') or not phone[1:].isdigit():
        await update.message.reply_text("Invalid phone number. Send like +91876543210.")
        return
    config = get_user_config(user_id)
    config['phone'] = phone
    update_user_config(user_id, config)
    api_id = os.environ.get('API_ID', 'YOUR_API_ID')
    api_hash = os.environ.get('API_HASH', 'YOUR_API_HASH')
    client = TelegramClient(f'sessions/{user_id}', api_id, api_hash)
    try:
        await client.connect()
        await client.send_code_request(phone)
        clients[user_id] = client
        await update.message.reply_text("Sent a login code to your Telegram. Enter it like: HELLO12345")
    except Exception as e:
        await update.message.reply_text(f"Error sending code: {e}. Try again.")
        clients.pop(user_id, None)

async def handle_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in clients:
        await update.message.reply_text("Start with /authorize first.")
        return
    code = update.message.text.replace('HELLO', '')
    client = clients[user_id]
    try:
        await client.sign_in(code=code)
        config = get_user_config(user_id)
        config['session'] = f'sessions/{user_id}'
        update_user_config(user_id, config)
        await update.message.reply_text("Successfully logged in! Use /incoming to set source chats.")
    except PhoneCodeInvalidError:
        await update.message.reply_text("Invalid code. Try again with HELLO<code>.")
    except SessionPasswordNeededError:
        await update.message.reply_text("2FA password required. Send /password <your_password>.")
    except Exception as e:
        await update.message.reply_text(f"Error: {e}. Try /authorize again.")
        clients.pop(user_id, None)

async def password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in clients:
        await update.message.reply_text("Start with /authorize first.")
        return
    password = ' '.join(context.args)
    client = clients[user_id]
    try:
        await client.sign_in(password=password)
        config = get_user_config(user_id)
        config['session'] = f'sessions/{user_id}'
        update_user_config(user_id, config)
        await update.message.reply_text("Successfully logged in! Use /incoming to set source chats.")
    except Exception as e:
        await update.message.reply_text(f"Error: {e}. Try /authorize again.")
        clients.pop(user_id, None)

async def incoming(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    if not config.get('session'):
        await update.message.reply_text("Please /authorize first.")
        return
    client = await get_client(user_id, config)
    if not client:
        await update.message.reply_text("Not logged in. Use /authorize.")
        return
    await update.message.reply_text("Pin source chats to top, then send /list_chats to select, or send chat ID/username.")

async def list_chats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    client = await get_client(user_id, get_user_config(user_id))
    if not client:
        await update.message.reply_text("Not logged in. Use /authorize.")
        return
    chats = []
    async for dialog in client.iter_dialogs(limit=20):
        chats.append((dialog.id, dialog.title))
    if not chats:
        await update.message.reply_text("No chats found. Join some and pin them.")
        return
    keyboard = [[InlineKeyboardButton(f"{i+1}. {title}", callback_data=f"src_{chat_id}")] for i, (chat_id, title) in enumerate(chats)]
    await update.message.reply_text("Select a source chat:", reply_markup=InlineKeyboardMarkup(keyboard))

async def outgoing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    if not config.get('session'):
        await update.message.reply_text("Please /authorize first.")
        return
    await update.message.reply_text("Pin destination chats to top, then send /list_chats to select, or send chat ID/username.")

async def callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    query = update.callback_query
    data = query.data
    config = get_user_config(user_id)
    if data.startswith('src_'):
        chat_id = int(data.replace('src_', ''))
        if chat_id not in config['sources']:
            config['sources'].append(chat_id)
            update_user_config(user_id, config)
        await query.message.reply_text(f"Added chat ID {chat_id} as source. Use /incoming for more or /outgoing for destinations.")
    elif data.startswith('dest_'):
        chat_id = int(data.replace('dest_', ''))
        if chat_id not in config['destinations']:
            config['destinations'].append(chat_id)
            update_user_config(user_id, config)
        await query.message.reply_text(f"Added chat ID {chat_id} as destination. Use /outgoing for more or /work to start.")
    await query.answer()

async def filter_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        rule = ' '.join(context.args)
        if '==' in rule:
            old, new = rule.split('==', 1)
            config = get_user_config(user_id)
            config['replacements'][old] = new
            update_user_config(user_id, config)
            await update.message.reply_text(f'"{old}" will be replaced by "{new}". Use regex!')
        else:
            await update.message.reply_text('Send: old==new (e.g., https://t.me/old==https://t.me/new)')
    else:
        await update.message.reply_text('Send: old==new (e.g., https://t.me/old==https://t.me/new)')

async def blacklist_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        pattern = ' '.join(context.args)
        config = get_user_config(user_id)
        config['blacklist'].append(pattern)
        update_user_config(user_id, config)
        await update.message.reply_text(f'Added "{pattern}" to blacklist.')
    else:
        await update.message.reply_text('Send pattern to blacklist (e.g., badlink.com)')

async def whitelist_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        pattern = ' '.join(context.args)
        config = get_user_config(user_id)
        config['whitelist'].append(pattern)
        update_user_config(user_id, config)
        await update.message.reply_text(f'Added "{pattern}" to whitelist.')
    else:
        await update.message.reply_text('Send pattern to whitelist (e.g., goodlink.com)')

async def userfilter_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        try:
            uid = int(context.args[0])
            config = get_user_config(user_id)
            config['user_filter'].append(uid)
            update_user_config(user_id, config)
            await update.message.reply_text(f'Added user ID {uid} to filter.')
        except:
            await update.message.reply_text('Send a valid user ID (e.g., 123456789).')
    else:
        await update.message.reply_text('Send user ID to filter (e.g., /userfilter 123456789)')

async def beginning_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        text = ' '.join(context.args)
        config = get_user_config(user_id)
        config['beginning_text'] = text
        update_user_config(user_id, config)
        await update.message.reply_text(f'Set beginning text: {text}')
    else:
        await update.message.reply_text('Send text to prepend (e.g., /beginning_text Prefix:)')

async def ending_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        text = ' '.join(context.args)
        config = get_user_config(user_id)
        config['ending_text'] = text
        update_user_config(user_id, config)
        await update.message.reply_text(f'Set ending text: {text}')
    else:
        await update.message.reply_text('Send text to append (e.g., /ending_text Suffix:)')

async def delay_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if context.args:
        try:
            delay = int(context.args[0])
            if 0 <= delay <= 999:
                config = get_user_config(user_id)
                config['delay'] = delay
                update_user_config(user_id, config)
                await update.message.reply_text(f'Delay set to {delay}s.')
            else:
                await update.message.reply_text('Delay between 0-999s.')
        except:
            await update.message.reply_text('Send a number (e.g., /delay 5)')
    else:
        config = get_user_config(user_id)
        await update.message.reply_text(f'Current delay: {config["delay"]}s. Send /delay N')

async def should_edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    config['edit_enabled'] = not config['edit_enabled']
    update_user_config(user_id, config)
    status = 'YES' if config['edit_enabled'] else 'NO'
    await update.message.reply_text(f'Editing messages: {status}')

async def should_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    config['delete_enabled'] = not config['delete_enabled']
    update_user_config(user_id, config)
    status = 'YES' if config['delete_enabled'] else 'NO'
    await update.message.reply_text(f'Deleting messages: {status}')

async def config_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    msg = f"""Current config:
- Sources: {config['sources']}
- Destinations: {config['destinations']}
- Replacements: {config['replacements']}
- Blacklist: {config['blacklist']}
- Whitelist: {config['whitelist']}
- User Filter: {config['user_filter']}
- Beginning Text: {config['beginning_text']}
- Ending Text: {config['ending_text']}
- Delay: {config['delay']}s
- Edit Messages: {'Yes' if config['edit_enabled'] else 'No'}
- Delete Messages: {'Yes' if config['delete_enabled'] else 'No'}
- Status: {config['status']}"""
    await update.message.reply_text(msg)

async def work_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    if not config.get('session'):
        await update.message.reply_text("Please /authorize first.")
        return
    if not config['sources'] or not config['destinations']:
        await update.message.reply_text('Set /incoming and /outgoing first!')
        return
    client = await get_client(user_id, config)
    if not client:
        await update.message.reply_text("Not logged in. Use /authorize.")
        return
    config['status'] = 'RUNNING'
    update_user_config(user_id, config)
    await update.message.reply_text('Forwarding started! /stop to stop.')
    if user_id not in clients:
        clients[user_id] = client
        client.add_event_handler(lambda event: telethon_handler(event, context), Updates)
        await client.run_until_disconnected()

async def stop_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    config['status'] = 'STOPPED'
    update_user_config(user_id, config)
    if user_id in clients:
        await clients[user_id].disconnect()
        clients.pop(user_id)
    await update.message.reply_text('Forwarding stopped.')

async def remove_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    if user_id in clients:
        await clients[user_id].disconnect()
        clients.pop(user_id)
    config['phone'] = ''
    config['session'] = ''
    config['status'] = 'STOPPED'
    update_user_config(user_id, config)
    await update.message.reply_text('Session removed. Use /authorize to log in again or /delete_config to clear all data.')

async def delete_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in clients:
        await clients[user_id].disconnect()
        clients.pop(user_id)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    await update.message.reply_text('All data deleted. Start fresh with /start.')

async def features(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = """Features:
- Forward from multiple source chats to multiple destinations
- Text replacement (e.g., /filter old==new)
- Blacklist/Whitelist for filtering messages
- User filter by ID
- Add beginning/ending text
- Delay forwarding (0-999s)
- Sync edited/deleted messages
- Pin chats for easy selection
- User login for restricted channels
Commands: /authorize, /incoming, /outgoing, /list_chats, /filter, /blacklist, /whitelist, /userfilter, /beginning_text, /ending_text, /delay, /should_edit, /should_delete, /config, /work, /stop, /remove_session, /delete_config"""
    await update.message.reply_text(msg)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    config = get_user_config(user_id)
    text = update.message.text
    if config.get('phone') and not config.get('session') and text.startswith('HELLO'):
        await handle_code(update, context)
    elif not config.get('phone') and text.startswith('+') and text[1:].isdigit():
        await handle_phone(update, context)

def main():
    token = os.environ['BOT_TOKEN']
    global app  # Needed for webhook if enabled
    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("authorize", authorize))
    app.add_handler(CommandHandler("password", password))
    app.add_handler(CommandHandler("incoming", incoming))
    app.add_handler(CommandHandler("outgoing", outgoing))
    app.add_handler(CommandHandler("list_chats", list_chats))
    app.add_handler(CommandHandler("filter", filter_cmd))
    app.add_handler(CommandHandler("blacklist", blacklist_cmd))
    app.add_handler(CommandHandler("whitelist", whitelist_cmd))
    app.add_handler(CommandHandler("userfilter", userfilter_cmd))
    app.add_handler(CommandHandler("beginning_text", beginning_text))
    app.add_handler(CommandHandler("ending_text", ending_text))
    app.add_handler(CommandHandler("delay", delay_cmd))
    app.add_handler(CommandHandler("should_edit", should_edit))
    app.add_handler(CommandHandler("should_delete", should_delete))
    app.add_handler(CommandHandler("config", config_cmd))
    app.add_handler(CommandHandler("work", work_cmd))
    app.add_handler(CommandHandler("stop", stop_cmd))
    app.add_handler(CommandHandler("remove_session", remove_session))
    app.add_handler(CommandHandler("delete_config", delete_config))
    app.add_handler(CommandHandler("features", features))
    app.add_handler(CallbackQueryHandler(callback_query))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Polling with conflict prevention
    app.run_polling(drop_pending_updates=True, timeout=10, bootstrap_retries=-1)

    # Webhook alternative (uncomment to use)
    # webhook_url = 'https://your-app.koyeb.app/webhook'  # Replace with your Koyeb URL
    # app.run_webhook(
    #     listen='0.0.0.0',
    #     port=int(os.environ.get('PORT', 8000)),
    #     url_path='/webhook',
    #     webhook_url=webhook_url
    # )

if __name__ == '__main__':
    main()
