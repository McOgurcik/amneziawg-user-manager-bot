#!/usr/bin/env bash
# Installs a fresh AmneziaWG 3.1 server and the Telegram user-manager bot.
set -Eeuo pipefail

GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com/repos/McOgurcik/amneziawg-user-manager-bot/contents}"
GITHUB_REF="${GITHUB_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/amnezia-user-manager-bot-src}"
AWG_PORT="${AWG_PORT:-585}"
AWG_SUBNET="${AWG_SUBNET:-10.8.1.0}"
AWG_CIDR="${AWG_CIDR:-24}"
AWG_CONTAINER="amnezia-awg2"
BOT_CONTAINER="amnezia-user-bot"

require() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { echo "Missing required variable: $name" >&2; exit 2; }
}

[[ "${EUID}" -eq 0 ]] || { echo "Run as root (for example: sudo env ... bash)." >&2; exit 1; }
require BOT_TOKEN
require ADMIN_ID
require SERVER_HOST

if ! [[ "$ADMIN_ID" =~ ^[0-9]+$ ]]; then
  echo "ADMIN_ID must be a numeric Telegram ID." >&2
  exit 2
fi
if ! [[ "$AWG_PORT" =~ ^[0-9]+$ ]] || (( AWG_PORT < 1 || AWG_PORT > 65535 )); then
  echo "AWG_PORT must be between 1 and 65535." >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl docker.io python3
systemctl enable --now docker

if docker inspect "$AWG_CONTAINER" >/dev/null 2>&1 || docker inspect "$BOT_CONTAINER" >/dev/null 2>&1; then
  echo "An AmneziaWG or bot container already exists. Refusing to overwrite it." >&2
  exit 3
fi
if ss -lunH | grep -Eq ":$AWG_PORT([[:space:]]|$)"; then
  echo "UDP port $AWG_PORT is already in use." >&2
  exit 3
fi

rm -rf "$INSTALL_DIR"
install -d -m 700 "$INSTALL_DIR"
download_source_file() {
  local source_file="$1"
  local destination="$2"
  curl --fail --location --proto '=https' --retry 3 \
    "$GITHUB_API_BASE/$source_file?ref=$GITHUB_REF" \
    | python3 -c 'import base64, json, sys; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["content"]))' \
    > "$destination"
}
for source_file in Dockerfile Dockerfile.awg requirements.txt bot.py; do
  download_source_file "$source_file" "$INSTALL_DIR/$source_file"
done

install -d -m 700 /opt/amnezia/awg /opt/amnezia-bot/data
printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-amneziawg.conf
sysctl --system >/dev/null

docker build --pull -f "$INSTALL_DIR/Dockerfile.awg" -t "$AWG_CONTAINER" "$INSTALL_DIR"
docker run -d --name "$AWG_CONTAINER" --restart unless-stopped \
  --log-driver none --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
  --sysctl='net.ipv4.conf.all.src_valid_mark=1' \
  -p "$AWG_PORT:$AWG_PORT/udp" \
  -v /lib/modules:/lib/modules \
  -v /opt/amnezia/awg:/opt/amnezia/awg \
  "$AWG_CONTAINER"

server_private="$(docker exec "$AWG_CONTAINER" awg genkey)"
server_public="$(printf '%s\n' "$server_private" | docker exec -i "$AWG_CONTAINER" awg pubkey)"
header_key="$(docker exec "$AWG_CONTAINER" awg genkey)"
printf '%s\n' "$server_private" > /opt/amnezia/awg/wireguard_server_private_key.key
printf '%s\n' "$server_public" > /opt/amnezia/awg/wireguard_server_public_key.key
cat > /opt/amnezia/awg/awg0.conf <<EOF
[Interface]
PrivateKey = $server_private
Address = $AWG_SUBNET/$AWG_CIDR
ListenPort = $AWG_PORT
Jc = 6
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = $header_key
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
EOF
chmod 600 /opt/amnezia/awg/*

cat > "$INSTALL_DIR/awg-start.sh" <<EOF
#!/bin/bash
set -e
awg-quick down /opt/amnezia/awg/awg0.conf || true
awg-quick up /opt/amnezia/awg/awg0.conf
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -s $AWG_SUBNET/$AWG_CIDR -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s $AWG_SUBNET/$AWG_CIDR -o eth0 -j MASQUERADE
tail -f /dev/null
EOF
chmod 700 "$INSTALL_DIR/awg-start.sh"
docker cp "$INSTALL_DIR/awg-start.sh" "$AWG_CONTAINER:/opt/amnezia/start.sh"
docker restart "$AWG_CONTAINER" >/dev/null

cat > /opt/amnezia-bot/bot.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ADMIN_ID=$ADMIN_ID
SERVER_HOST=$SERVER_HOST
AWG_CONTAINER=$AWG_CONTAINER
AWG_CONFIG=/awg/awg0.conf
SERVER_BACKUP_DIR=/server-backup
EOF
chmod 600 /opt/amnezia-bot/bot.env

docker build --pull -t "$BOT_CONTAINER:latest" "$INSTALL_DIR"
docker run -d --name "$BOT_CONTAINER" --restart unless-stopped \
  --env-file /opt/amnezia-bot/bot.env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/amnezia/awg:/awg:rw \
  -v /opt/amnezia-bot/data:/data \
  -v /opt/amnezia-bot/bot.env:/server-backup/bot.env:ro \
  -v "$INSTALL_DIR":/server-backup/app:ro \
  "$BOT_CONTAINER:latest"

if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  ufw allow "$AWG_PORT/udp"
fi

sleep 3
docker exec "$AWG_CONTAINER" awg show awg0 >/dev/null
docker ps --filter "name=^/$AWG_CONTAINER$" --filter "name=^/$BOT_CONTAINER$" --format '{{.Names}}|{{.Status}}'
echo "Installation complete. Open your bot and send /start."
