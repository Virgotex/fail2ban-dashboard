#!/usr/bin/env bash
# install-tunnels.sh — turn servers.json into managed SSH tunnels.
#
# Each agent listens on 127.0.0.1:3001 on its own host and is never exposed to
# the network. The hub reaches it through an SSH tunnel bound to a distinct
# local port on THIS host — the "baseUrl" of that server in servers.json.
#
# A tunnel that dies silently looks exactly like a down server, so these are
# systemd units rather than backgrounded ssh: they restart on failure, come
# back after a reboot, and you can see their state with systemctl.
#
# Usage (on the hub host):
#   sudo bash install-tunnels.sh                 # install/refresh every tunnel
#   sudo TUNNEL_USER=carlton bash install-tunnels.sh
#   sudo bash install-tunnels.sh --status        # just show current state
#   sudo bash install-tunnels.sh --remove        # tear everything down
#
# servers.json entries need an "ssh" field for this script:
#   { "id":"web-01", "baseUrl":"http://127.0.0.1:4101", "ssh":"carlton@web-01" }
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVERS_FILE="${HUB_SERVERS_FILE:-$HERE/servers.json}"
CONF_DIR="/etc/fail2ban-tunnels"
UNIT="/etc/systemd/system/fail2ban-tunnel@.service"
AGENT_PORT_DEFAULT="${AGENT_PORT:-3001}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
die() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

MODE="install"
case "${1:-}" in
  --status) MODE="status" ;;
  --remove) MODE="remove" ;;
  "")       MODE="install" ;;
  *)        die "Unknown argument: $1 (expected --status or --remove)" ;;
esac

[ "$(id -u)" -eq 0 ] || die "Run with sudo — this writes systemd units."
command -v node >/dev/null 2>&1 || die "node not found (needed to read servers.json)."
[ -f "$SERVERS_FILE" ] || die "No servers.json at $SERVERS_FILE. Copy servers.example.json first."

# The tunnels must run as a user whose SSH key can reach the agents — normally
# the same user the hub service runs as, not root.
TUNNEL_USER="${TUNNEL_USER:-${SUDO_USER:-}}"
[ -n "$TUNNEL_USER" ] || die "Set TUNNEL_USER=<user> (the user whose SSH key reaches the agents)."
id "$TUNNEL_USER" >/dev/null 2>&1 || die "No such user: $TUNNEL_USER"

# ── Read servers.json → "id<TAB>localPort<TAB>sshTarget" lines ───────────────
# Node does the parsing so we don't depend on jq being installed.
mapfile -t ENTRIES < <(node - "$SERVERS_FILE" <<'NODE'
const fs = require('fs');
let list;
try { list = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')); }
catch (e) { console.error(`Could not parse servers.json: ${e.message}`); process.exit(1); }
if (!Array.isArray(list)) { console.error('servers.json must be a JSON array.'); process.exit(1); }

let bad = 0;
for (const s of list) {
  if (!s || !s.id) { console.error('Entry with no "id" — skipped.'); bad++; continue; }
  if (!s.ssh) { console.error(`! ${s.id}: no "ssh" field — skipped (add "ssh": "user@host").`); bad++; continue; }
  let u;
  try { u = new URL(s.baseUrl); } catch { console.error(`! ${s.id}: invalid baseUrl — skipped.`); bad++; continue; }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname) || u.hostname === '::1';
  if (!loopback) { console.error(`! ${s.id}: baseUrl host is ${u.hostname}, not loopback — skipped (a tunnel forwards to 127.0.0.1).`); bad++; continue; }
  if (!u.port) { console.error(`! ${s.id}: baseUrl has no port — skipped.`); bad++; continue; }
  process.stdout.write(`${s.id}\t${u.port}\t${s.ssh}\n`);
}
if (bad) console.error(`(${bad} entr${bad === 1 ? 'y' : 'ies'} skipped)`);
NODE
)

[ "${#ENTRIES[@]}" -gt 0 ] || die "No usable entries in $SERVERS_FILE."

ids=(); ports=(); targets=()
for line in "${ENTRIES[@]}"; do
  IFS=$'\t' read -r id port target <<<"$line"
  ids+=("$id"); ports+=("$port"); targets+=("$target")
done

# ── --status / --remove ──────────────────────────────────────────────────────
if [ "$MODE" = "status" ]; then
  printf '%-16s %-8s %-28s %s\n' SERVER PORT TARGET STATE
  for i in "${!ids[@]}"; do
    state="$(systemctl is-active "fail2ban-tunnel@${ids[$i]}" 2>/dev/null || true)"
    printf '%-16s %-8s %-28s %s\n' "${ids[$i]}" "${ports[$i]}" "${targets[$i]}" "${state:-not-installed}"
  done
  exit 0
fi

if [ "$MODE" = "remove" ]; then
  for id in "${ids[@]}"; do
    systemctl disable --now "fail2ban-tunnel@${id}" 2>/dev/null || true
    rm -f "$CONF_DIR/${id}.conf"
  done
  rm -f "$UNIT"
  systemctl daemon-reload
  echo -e "${GREEN}✓ Tunnels removed.${NC}"
  exit 0
fi

# ── Install ──────────────────────────────────────────────────────────────────
if command -v autossh >/dev/null 2>&1; then
  SSH_BIN="$(command -v autossh)"
  # -M 0 disables autossh's own monitoring port; we rely on SSH keepalives,
  # and systemd restarts the unit if autossh itself exits.
  SSH_ARGS='-M 0'
  echo -e "${GREEN}✓ autossh found — using it${NC}"
else
  SSH_BIN="$(command -v ssh)"
  SSH_ARGS=''
  echo -e "${YELLOW}⚠  autossh not installed — falling back to plain ssh.${NC}"
  echo    "   systemd will still restart a dropped tunnel, but reconnects are"
  echo    "   slower. Install it with: sudo apt install autossh"
fi

install -d -m 0755 "$CONF_DIR"

cat > "$UNIT" <<EOF
[Unit]
Description=Fail2Ban dashboard SSH tunnel to %i
Documentation=file://$HERE/README.md
After=network-online.target
Wants=network-online.target
# Never stop trying: a monitored server can be down for hours.
StartLimitIntervalSec=0

[Service]
Type=simple
User=$TUNNEL_USER
EnvironmentFile=$CONF_DIR/%i.conf
# Make autossh restart even if the very first connection fails.
Environment=AUTOSSH_GATETIME=0
ExecStart=$SSH_BIN $SSH_ARGS -N \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \\
  -o BatchMode=yes -o StrictHostKeyChecking=accept-new \\
  -L 127.0.0.1:\${LOCAL_PORT}:127.0.0.1:\${AGENT_PORT} \${SSH_TARGET}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
echo -e "${GREEN}✓ Wrote $UNIT (running as $TUNNEL_USER)${NC}"

for i in "${!ids[@]}"; do
  id="${ids[$i]}"; port="${ports[$i]}"; target="${targets[$i]}"
  cat > "$CONF_DIR/${id}.conf" <<EOF
# Generated by install-tunnels.sh from $SERVERS_FILE — do not edit by hand.
LOCAL_PORT=$port
AGENT_PORT=$AGENT_PORT_DEFAULT
SSH_TARGET=$target
EOF
  chmod 0644 "$CONF_DIR/${id}.conf"
done

# Retire units for servers that have since left servers.json.
shopt -s nullglob
for conf in "$CONF_DIR"/*.conf; do
  existing="$(basename "$conf" .conf)"
  keep=false
  for id in "${ids[@]}"; do [ "$id" = "$existing" ] && keep=true && break; done
  if [ "$keep" = false ]; then
    echo -e "${YELLOW}⚠  $existing is no longer in servers.json — removing its tunnel${NC}"
    systemctl disable --now "fail2ban-tunnel@${existing}" 2>/dev/null || true
    rm -f "$conf"
  fi
done
shopt -u nullglob

systemctl daemon-reload

echo ""
for i in "${!ids[@]}"; do
  id="${ids[$i]}"; port="${ports[$i]}"; target="${targets[$i]}"
  # A tunnel can only come up if this user can log in non-interactively.
  if ! sudo -u "$TUNNEL_USER" ssh -o BatchMode=yes -o ConnectTimeout=8 \
        -o StrictHostKeyChecking=accept-new "$target" true 2>/dev/null; then
    echo -e "${YELLOW}⚠  $id: $TUNNEL_USER cannot SSH to $target without a password.${NC}"
    echo    "   Fix with: sudo -u $TUNNEL_USER ssh-copy-id $target"
  fi
  systemctl enable --now "fail2ban-tunnel@${id}" >/dev/null 2>&1 || true
  state="$(systemctl is-active "fail2ban-tunnel@${id}" 2>/dev/null || true)"
  if [ "$state" = "active" ]; then
    echo -e "${GREEN}✓ $id${NC}  127.0.0.1:$port → $target:127.0.0.1:$AGENT_PORT_DEFAULT"
  else
    echo -e "${RED}✗ $id${NC}  $state — journalctl -u fail2ban-tunnel@$id -n 30"
  fi
done

echo ""
echo "Listening ports:  ss -tlnp | grep -E '$(IFS='|'; echo "${ports[*]}")'"
echo "Status any time:  sudo bash install-tunnels.sh --status"
echo "Restart one:      sudo systemctl restart fail2ban-tunnel@<id>"
