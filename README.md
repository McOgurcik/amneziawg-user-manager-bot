# AmneziaWG User Manager Bot

Private Telegram admin bot for managing users of a self-hosted AmneziaWG 3.1 server.

It creates AmneziaWG configuration files, QR codes, and one-time delivery links. The bot can list users, set or remove access expiry, rename users, enable or disable access, and revoke users. Expired accounts are disabled automatically.

## Security model

- Only the Telegram user ID in `ADMIN_ID` can manage users.
- The bot token, administrator ID, server address, SQLite database, and generated `.conf` files are supplied at deployment time and must never be committed.
- One-time delivery links expire after seven days and are redeemed once.
- The bot requires access to the Docker socket only to synchronise the AmneziaWG peer configuration with the named container.

## Deploy with Docker

1. Copy `.env.example` to a private `bot.env` file and fill the values.
2. Build the image:

   ```bash
   docker build -t amnezia-user-bot .
   ```

3. Start it alongside an existing AmneziaWG container. Adjust the host paths if needed:

   ```bash
   docker run -d --name amnezia-user-bot --restart unless-stopped \
     --env-file /opt/amnezia-bot/bot.env \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /opt/amnezia/awg:/awg:rw \
     -v /opt/amnezia-bot/data:/data \
     amnezia-user-bot
   ```

The directory mounted at `/data` contains the private user database and must be protected accordingly.

## Fresh-server one-command installer

For a new Ubuntu server, the public installer deploys Docker, AmneziaWG 3.1, and the bot. It generates new VPN server keys; use the bot to create users afterwards.

```bash
curl -fsSL 'https://api.github.com/repos/McOgurcik/amneziawg-user-manager-bot/contents/install.sh?ref=main' -o /tmp/install-vpn.json
python3 -c 'import base64,json;open("/tmp/install-vpn.sh","wb").write(base64.b64decode(json.load(open("/tmp/install-vpn.json"))["content"]))'
sudo env BOT_TOKEN='token-from-botfather' ADMIN_ID='your-numeric-telegram-id' SERVER_HOST='your-server-ip' bash /tmp/install-vpn.sh
```

Optional values: `AWG_PORT` (defaults to UDP `443`), `AWG_SUBNET` (defaults to `10.8.1.0`), and `INSTALL_DIR`. UDP and TCP may use port `443` simultaneously, so this does not conflict with SSH on TCP `443`. `SOURCE_DIR` is intended for an offline/local-source bootstrap and is not needed for normal installs.

The installer refuses to overwrite existing `amnezia-awg2` or `amnezia-user-bot` containers.

## Commands

- `/start` — admin panel
- `/users` — user list with pagination
- `/limit ID_OR_IP_OR_NAME 30d` — grant time-limited access
- `/limit ID_OR_IP_OR_NAME 2026-12-31` — set an explicit expiry date
- `/unlimit ID_OR_IP_OR_NAME` — make access unlimited
- `/backup` — send the administrator a ZIP archive of client profiles, AmneziaWG server keys/configuration, and bot recovery data. Treat this archive as highly sensitive.

The button interface also supports user creation, configuration re-issue, one-time links, QR generation, renaming, disabling, enabling, deletion, and 30-day extensions.

## Requirements

- A running AmneziaWG 3.1 Docker container named `amnezia-awg2` (or set `AWG_CONTAINER`).
- Docker access from the bot container.
- Python dependencies listed in `requirements.txt` (included in the Docker image).

## License

MIT
