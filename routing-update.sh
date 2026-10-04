#!/usr/bin/env bash
# Fetch and validate split-routing profiles and update the AWG-container RU IP set.
set -Eeuo pipefail

ROUTING_DIR="${ROUTING_DIR:-/opt/amnezia-bot/routing}"
AWG_DIR="${AWG_DIR:-/opt/amnezia/awg}"
AWG_CONTAINER="${AWG_CONTAINER:-amnezia-awg2}"
BASE_URL="${ROUTING_BASE_URL:-https://github.com/lib4u/amnezia-tunneling-ru/releases/download/latest}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

install -d -m 700 "$ROUTING_DIR" "$AWG_DIR"
for file in amnezia.json amnezia-ip-lite.json amnezia-ip.json; do
  curl --fail --location --proto '=https' --retry 3 "$BASE_URL/$file" -o "$work_dir/$file"
done

python3 - "$work_dir" "$AWG_DIR/ru-ipset.restore" <<'PY'
import ipaddress, json, os, sys
from pathlib import Path

work, output = map(Path, sys.argv[1:])
for filename in ('amnezia.json', 'amnezia-ip-lite.json', 'amnezia-ip.json'):
    data = json.loads((work / filename).read_text(encoding='utf-8'))
    if not isinstance(data, list) or not data:
        raise SystemExit(f'{filename}: expected a non-empty JSON list')

entries = json.loads((work / 'amnezia-ip.json').read_text(encoding='utf-8'))
nets = set()
for entry in entries:
    if not isinstance(entry, dict) or not isinstance(entry.get('hostname'), str):
        raise SystemExit('amnezia-ip.json: invalid record')
    if not entry['hostname']:
        continue
    net = ipaddress.ip_network(entry['hostname'], strict=False)
    if net.version != 4 or not net.is_global:
        raise SystemExit(f'amnezia-ip.json: non-global IPv4 range {net}')
    nets.add(str(net))
if len(nets) < 100:
    raise SystemExit('amnezia-ip.json: unexpectedly small network list')

target = Path(output)
tmp = target.with_suffix('.tmp')
tmp.write_text(
    'create ru_ipv4 hash:net family inet hashsize 16384 maxelem 20000\nflush ru_ipv4\n'
    + ''.join(f'add ru_ipv4 {net}\n' for net in sorted(nets))
    + 'COMMIT\n', encoding='utf-8')
os.chmod(tmp, 0o600)
tmp.replace(target)
PY

for file in amnezia.json amnezia-ip-lite.json amnezia-ip.json; do
  install -m 600 "$work_dir/$file" "$ROUTING_DIR/$file"
done

docker exec -i "$AWG_CONTAINER" ipset restore -exist < "$AWG_DIR/ru-ipset.restore"
docker exec "$AWG_CONTAINER" iptables -C FORWARD -i awg0 -m set --match-set ru_ipv4 dst -j REJECT 2>/dev/null \
  || docker exec "$AWG_CONTAINER" iptables -I FORWARD 1 -i awg0 -m set --match-set ru_ipv4 dst -j REJECT
