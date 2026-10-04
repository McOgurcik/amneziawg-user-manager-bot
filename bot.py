import asyncio
import base64
import io
import os
import re
import secrets
import shlex
import sqlite3
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import docker
import qrcode
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, ReplyKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ["ADMIN_ID"])
DATA_DIR = Path("/data")
DB_PATH = DATA_DIR / "bot.sqlite3"
AWG_CONTAINER = os.getenv("AWG_CONTAINER", "amnezia-awg2")
AWG_CONFIG = Path(os.getenv("AWG_CONFIG", "/awg/awg0.conf"))
SERVER_HOST = os.getenv("SERVER_HOST", "VPN_SERVER_IP")
SERVER_BACKUP_DIR = Path(os.getenv("SERVER_BACKUP_DIR", "/server-backup"))
CONFIG_LOCK = asyncio.Lock()


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


@contextmanager
def db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                client_private TEXT NOT NULL,
                client_public TEXT NOT NULL UNIQUE,
                psk TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shares (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                redeemed_at TEXT,
                redeemed_by INTEGER
            );
            """
        )


def owner_only(update: Update) -> bool:
    return bool(update.effective_user and update.effective_user.id == ADMIN_ID)


def menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [["➕ Создать конфиг", "👥 Пользователи"], ["ℹ️ Помощь"]],
        resize_keyboard=True,
    )


def docker_client():
    return docker.from_env()


def awg_exec(args: list[str]) -> str:
    client = docker_client()
    container = client.containers.get(AWG_CONTAINER)
    result = container.exec_run(args, stdout=True, stderr=True, demux=False)
    output = result.output.decode("utf-8", errors="replace") if result.output else ""
    if result.exit_code != 0:
        raise RuntimeError(output.strip() or "AmneziaWG command failed")
    return output.strip()


def genkey() -> str:
    return awg_exec(["awg", "genkey"])


def pubkey(private_key: str) -> str:
    return awg_exec(["sh", "-lc", f"printf '%s\\n' {shlex.quote(private_key)} | awg pubkey"])


def genpsk() -> str:
    return awg_exec(["awg", "genpsk"])


def config_sections() -> tuple[dict[str, str], list[dict[str, str]]]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    section = ""
    for raw in AWG_CONFIG.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section == "Peer":
                current = {}
                peers.append(current)
            else:
                current = interface if section == "Interface" else None
            continue
        if " = " in line and current is not None:
            key, value = line.split(" = ", 1)
            current[key] = value
    return interface, peers


def next_ip(users: list[sqlite3.Row]) -> str:
    occupied = {row["ip"] for row in users}
    for host in range(2, 255):
        address = f"10.8.1.{host}"
        if address not in occupied:
            return address
    raise RuntimeError("Свободные адреса в подсети закончились")


def server_public_key() -> str:
    value = (Path("/awg/wireguard_server_public_key.key")).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("Не найден публичный ключ сервера")
    return value


def client_config(user: sqlite3.Row) -> str:
    interface, _ = config_sections()
    server_key = server_public_key()
    order = [
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
        "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    ]
    lines = ["[Interface]", f"Address = {user['ip']}/32", "DNS = 1.1.1.1, 1.0.0.1", f"PrivateKey = {user['client_private']}"]
    for key in order:
        if interface.get(key):
            lines.append(f"{key} = {interface[key]}")
    lines.extend([
        "I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
        "", "[Peer]", f"PublicKey = {server_key}", f"PresharedKey = {user['psk']}",
        "AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {SERVER_HOST}:585", "PersistentKeepalive = 25-35", "",
    ])
    return "\n".join(lines)


def render_server_config(users: list[sqlite3.Row]) -> None:
    interface, _ = config_sections()
    server_order = [
        "PrivateKey", "Address", "ListenPort", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
        "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    ]
    lines = ["[Interface]"]
    for key in server_order:
        if interface.get(key):
            lines.append(f"{key} = {interface[key]}")
    for user in users:
        if not user["active"]:
            continue
        expires = parse_iso(user["expires_at"])
        if expires and expires <= now():
            continue
        lines.extend(["", "[Peer]", f"PublicKey = {user['client_public']}", f"PresharedKey = {user['psk']}", f"AllowedIPs = {user['ip']}/32"])
    tmp = AWG_CONFIG.with_suffix(".conf.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, AWG_CONFIG)


def sync_awg() -> None:
    awg_exec(["bash", "-lc", "awg syncconf awg0 <(awg-quick strip /opt/amnezia/awg/awg0.conf)"])


async def apply_users() -> None:
    async with CONFIG_LOCK:
        with db() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        await asyncio.to_thread(render_server_config, rows)
        await asyncio.to_thread(sync_awg)


def user_label(row: sqlite3.Row) -> str:
    expiry = parse_iso(row["expires_at"])
    if not row["active"]:
        state = "⛔"
    elif expiry and expiry <= now():
        state = "⌛"
    else:
        state = "✅"
    suffix = expiry.astimezone().strftime("%d.%m") if expiry else "∞"
    return f"{state} {row['name']} · {suffix}"


async def send_profile(message, user: sqlite3.Row, caption: str = "") -> None:
    content = client_config(user)
    document = io.BytesIO(content.encode())
    document.name = f"{user['name'].replace(' ', '_') or 'amneziawg'}.conf"
    qr_buffer = io.BytesIO()
    qrcode.make(content).save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    qr_buffer.name = f"{user['name']}_QR.png"
    await message.reply_document(InputFile(document), caption=caption or f"Конфиг: {user['name']}")
    await message.reply_photo(InputFile(qr_buffer), caption="QR-код этого конфига")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    argument = context.args[0] if context.args else ""
    if argument.startswith("cfg_") and not owner_only(update):
        token = argument[4:]
        with db() as conn:
            share = conn.execute("SELECT * FROM shares WHERE token = ?", (token,)).fetchone()
            if not share or share["redeemed_at"] or parse_iso(share["expires_at"]) <= now():
                await update.effective_message.reply_text("Эта ссылка недействительна или уже использована.")
                return
            user = conn.execute("SELECT * FROM users WHERE id = ?", (share["user_id"],)).fetchone()
            if not user or not user["active"]:
                await update.effective_message.reply_text("Доступ к этому конфигу отключён.")
                return
            conn.execute("UPDATE shares SET redeemed_at = ?, redeemed_by = ? WHERE token = ?", (iso(now()), update.effective_user.id, token))
        await send_profile(update.effective_message, user, "Ваш конфиг AmneziaWG")
        return
    if not owner_only(update):
        await update.effective_message.reply_text("Этот бот выдаёт конфигурации только по персональным ссылкам.")
        return
    await update.effective_message.reply_text("Панель управления AmneziaWG 3.1 готова.", reply_markup=menu())


async def create_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not owner_only(update):
        return
    context.user_data["waiting"] = "create"
    await update.effective_message.reply_text("Введите имя нового пользователя (например, Иван или iPhone).")


async def create_user(update: Update, context: ContextTypes.DEFAULT_TYPE, name: str) -> None:
    name = name.strip()[:64]
    if not name:
        await update.effective_message.reply_text("Имя не должно быть пустым.")
        return
    with db() as conn:
        existing = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        address = next_ip(existing)
        private = await asyncio.to_thread(genkey)
        public = await asyncio.to_thread(pubkey, private)
        psk = await asyncio.to_thread(genpsk)
        cur = conn.execute(
            "INSERT INTO users(name, ip, client_private, client_public, psk, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, address, private, public, psk, iso(now() + timedelta(days=30)), iso(now())),
        )
        user_id = cur.lastrowid
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    await apply_users()
    token = secrets.token_urlsafe(18).replace("-", "").replace("_", "")
    with db() as conn:
        conn.execute("INSERT INTO shares(token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, iso(now() + timedelta(days=7))))
    link = f"https://t.me/{(await context.bot.get_me()).username}?start=cfg_{token}"
    await update.effective_message.reply_text(f"Пользователь «{name}» создан. Одноразовая ссылка (действует 7 дней):\n{link}")
    await send_profile(update.effective_message, user)


async def show_users(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 0) -> None:
    if not owner_only(update):
        return
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_pages = max(1, (total + 9) // 10)
        page = max(0, min(page, total_pages - 1))
        rows = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 10 OFFSET ?", (page * 10,)).fetchall()
    if not total:
        await update.effective_message.reply_text("Пользователей пока нет.")
        return
    keyboard = [[InlineKeyboardButton(user_label(row), callback_data=f"user:{row['id']}")] for row in rows]
    navigation = []
    if page > 0:
        navigation.append(InlineKeyboardButton("◀️", callback_data=f"userspage:{page - 1}"))
    navigation.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop:0"))
    if page < total_pages - 1:
        navigation.append(InlineKeyboardButton("▶️", callback_data=f"userspage:{page + 1}"))
    keyboard.append(navigation)
    await update.effective_message.reply_text(f"Пользователи ({total}), страница {page + 1} из {total_pages}:", reply_markup=InlineKeyboardMarkup(keyboard))


async def show_user(query, user_id: int) -> None:
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        await query.edit_message_text("Пользователь не найден.")
        return
    expiry = parse_iso(user["expires_at"])
    status = "активен" if user["active"] and (not expiry or expiry > now()) else "отключён"
    until = expiry.astimezone().strftime("%d.%m.%Y %H:%M") if expiry else "без ограничения"
    text = f"{user['name']}\nID: {user['id']}\nIP: {user['ip']}\nСтатус: {status}\nСрок: {until}"
    actions = [
        [InlineKeyboardButton("📥 Конфиг", callback_data=f"config:{user_id}"), InlineKeyboardButton("🔗 Новая ссылка", callback_data=f"link:{user_id}")],
        [InlineKeyboardButton("⏱ +30 дней", callback_data=f"extend:{user_id}"), InlineKeyboardButton("✏️ Переименовать", callback_data=f"rename:{user_id}")],
        [InlineKeyboardButton("🔒 Отключить" if user["active"] else "🔓 Включить", callback_data=f"toggle:{user_id}"), InlineKeyboardButton("🗑 Удалить", callback_data=f"delete:{user_id}")],
        [InlineKeyboardButton("👥 К списку", callback_data="userspage:0")],
    ]
    await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(actions))


async def callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not owner_only(update):
        return
    action, value = query.data.split(":", 1)
    if action == "noop":
        return
    if action == "userspage":
        page = int(value)
        with db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_pages = max(1, (total + 9) // 10)
            page = max(0, min(page, total_pages - 1))
            rows = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 10 OFFSET ?", (page * 10,)).fetchall()
        keyboard = [[InlineKeyboardButton(user_label(row), callback_data=f"user:{row['id']}")] for row in rows]
        navigation = []
        if page > 0:
            navigation.append(InlineKeyboardButton("◀️", callback_data=f"userspage:{page - 1}"))
        navigation.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop:0"))
        if page < total_pages - 1:
            navigation.append(InlineKeyboardButton("▶️", callback_data=f"userspage:{page + 1}"))
        keyboard.append(navigation)
        await query.edit_message_text(f"Пользователи ({total}), страница {page + 1} из {total_pages}:", reply_markup=InlineKeyboardMarkup(keyboard))
        return
    user_id = int(value)
    if action == "user":
        await show_user(query, user_id)
        return
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            await query.edit_message_text("Пользователь не найден.")
            return
        if action == "config":
            await send_profile(query.message, user)
            return
        if action == "link":
            token = secrets.token_urlsafe(18).replace("-", "").replace("_", "")
            conn.execute("INSERT INTO shares(token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, iso(now() + timedelta(days=7))))
            username = (await context.bot.get_me()).username
            await query.message.reply_text(f"Одноразовая ссылка (7 дней):\nhttps://t.me/{username}?start=cfg_{token}")
            return
        if action == "extend":
            base = parse_iso(user["expires_at"]) or now()
            base = max(base, now())
            conn.execute("UPDATE users SET expires_at = ?, active = 1 WHERE id = ?", (iso(base + timedelta(days=30)), user_id))
        elif action == "toggle":
            conn.execute("UPDATE users SET active = ? WHERE id = ?", (0 if user["active"] else 1, user_id))
        elif action == "delete":
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await apply_users()
            await query.edit_message_text("Пользователь удалён, его доступ отозван.")
            return
        elif action == "rename":
            context.user_data["waiting"] = f"rename:{user_id}"
            await query.message.reply_text("Введите новое имя пользователя.")
            return
    await apply_users()
    await show_user(query, user_id)


async def limit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not owner_only(update):
        return
    if len(context.args) < 2:
        await update.effective_message.reply_text("Использование: /limit ID, IP или имя 30d. Пример: /limit 10.8.1.3 25d")
        return
    selector = " ".join(context.args[:-1]).strip()
    value = context.args[-1].lower()
    try:
        if value.endswith("d") and value[:-1].isdigit():
            expiry = now() + timedelta(days=int(value[:-1]))
        else:
            expiry = datetime.fromisoformat(value).replace(tzinfo=timezone.utc) + timedelta(days=1)
    except ValueError:
        await update.effective_message.reply_text("Неверный срок. Пример: 30d или 2026-12-31")
        return
    with db() as conn:
        if selector.isdigit():
            user = conn.execute("SELECT id FROM users WHERE id = ?", (int(selector),)).fetchone()
        else:
            user = conn.execute("SELECT id FROM users WHERE ip = ? OR name = ? COLLATE NOCASE", (selector, selector)).fetchone()
        if user:
            conn.execute("UPDATE users SET expires_at = ?, active = 1 WHERE id = ?", (iso(expiry), user["id"]))
    if not user:
        await update.effective_message.reply_text("Пользователь не найден.")
        return
    await apply_users()
    await update.effective_message.reply_text(f"Срок доступа установлен до {expiry.astimezone().strftime('%d.%m.%Y %H:%M')}.")


async def unlimit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not owner_only(update):
        return
    selector = " ".join(context.args).strip()
    if not selector:
        await update.effective_message.reply_text("Использование: /unlimit ID, IP или имя. Пример: /unlimit 10.8.1.3")
        return
    with db() as conn:
        if selector.isdigit():
            user = conn.execute("SELECT id FROM users WHERE id = ?", (int(selector),)).fetchone()
        else:
            user = conn.execute("SELECT id FROM users WHERE ip = ? OR name = ? COLLATE NOCASE", (selector, selector)).fetchone()
        if user:
            conn.execute("UPDATE users SET expires_at = NULL, active = 1 WHERE id = ?", (user["id"],))
    if not user:
        await update.effective_message.reply_text("Пользователь не найден.")
        return
    await apply_users()
    await update.effective_message.reply_text("Срок снят: доступ включён бессрочно.")


async def backup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send the administrator a full private VPN and bot recovery archive."""
    if not owner_only(update):
        return
    with db() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    if not users:
        await update.effective_message.reply_text("В резервной копии пока нет пользователей.")
        return

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(
            "README-RESTORE.txt",
            "Private AmneziaWG server backup.\n\n"
            "Contents:\n"
            "- awg/: server configuration and keys\n"
            "- bot/data/: SQLite user database\n"
            "- bot/app/: bot source used on the server\n"
            "- bot/bot.env: bot token and deployment settings\n\n"
            "Keep this archive encrypted and private. Anyone with it can access the VPN server and bot.\n",
        )
        for user in users:
            safe_name = re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "_", user["name"]).strip("._") or f"user_{user['id']}"
            filename = f"{user['id']:03d}_{safe_name}_{user['ip']}.conf"
            bundle.writestr(filename, client_config(user))
        protected_files = {
            "/awg/awg0.conf": "awg/awg0.conf",
            "/awg/wireguard_server_private_key.key": "awg/wireguard_server_private_key.key",
            "/awg/wireguard_server_public_key.key": "awg/wireguard_server_public_key.key",
            "/awg/wireguard_psk.key": "awg/wireguard_psk.key",
            "/data/bot.sqlite3": "bot/data/bot.sqlite3",
            str(SERVER_BACKUP_DIR / "bot.env"): "bot/bot.env",
            str(SERVER_BACKUP_DIR / "app" / "bot.py"): "bot/app/bot.py",
            str(SERVER_BACKUP_DIR / "app" / "Dockerfile"): "bot/app/Dockerfile",
            str(SERVER_BACKUP_DIR / "app" / "requirements.txt"): "bot/app/requirements.txt",
        }
        missing = []
        for source, destination in protected_files.items():
            path = Path(source)
            if path.is_file():
                bundle.writestr(destination, path.read_bytes())
            else:
                missing.append(destination)
        if missing:
            bundle.writestr("MISSING-FILES.txt", "\n".join(missing) + "\n")
    archive.seek(0)
    archive.name = f"amneziawg-backup-{SERVER_HOST}.zip"
    await update.effective_message.reply_document(
        InputFile(archive),
        caption=f"Полная резервная копия: {len(users)} конфигов, серверные ключи и данные бота. Храните архив в защищённом месте.",
    )


async def text_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not owner_only(update):
        return
    waiting = context.user_data.pop("waiting", None)
    value = update.effective_message.text
    if waiting == "create":
        await create_user(update, context, value)
    elif waiting and waiting.startswith("rename:"):
        name = value.strip()[:64]
        if not name:
            await update.effective_message.reply_text("Имя не должно быть пустым.")
            return
        user_id = int(waiting.split(":", 1)[1])
        with db() as conn:
            conn.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
        await update.effective_message.reply_text("Имя изменено.")
    elif value == "➕ Создать конфиг":
        await create_prompt(update, context)
    elif value == "👥 Пользователи":
        await show_users(update, context)
    elif value == "ℹ️ Помощь":
        await update.effective_message.reply_text("Создавайте пользователей кнопкой. Для точного срока: /limit ID 30d или /limit ID 2026-12-31. Для бессрочного доступа: /unlimit ID. Резервная копия: /backup. Кнопка +30 дней продлевает текущий срок.")


async def expire_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    with db() as conn:
        expired = conn.execute("SELECT id FROM users WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?", (iso(now()),)).fetchall()
        if not expired:
            return
        conn.execute("UPDATE users SET active = 0 WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?", (iso(now()),))
    await apply_users()


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    print(f"Update error: {context.error}", flush=True)


def main() -> None:
    init_db()
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("users", show_users))
    app.add_handler(CommandHandler("limit", limit))
    app.add_handler(CommandHandler("unlimit", unlimit))
    app.add_handler(CommandHandler("backup", backup))
    app.add_handler(CallbackQueryHandler(callbacks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_input))
    app.add_error_handler(error_handler)
    app.job_queue.run_repeating(expire_job, interval=3600, first=60, name="expire-users")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
