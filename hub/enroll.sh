#!/usr/bin/env bash
# enroll.sh — add a live server to this hub with one command.
#
# Run this ON THE HUB MACHINE. It does over SSH exactly what Part A of DEPLOY.md
# tells you to do by hand: pre-flight the box, install the agent, grant it access
# to fail2ban and the logs, run it as a service, then register it here with its
# own key — so the key never passes through a clipboard.
#
# Usage:
#   bash hub/enroll.sh carlton@197.139.44.207
#   bash hub/enroll.sh --dry-run carlton@197.139.44.207     # show the plan, change nothing
#   bash hub/enroll.sh --id web-01 --name "Web 01" deploy@web-01.example.com
#
# Re-running it on an already-enrolled server is safe: it updates the code,
# keeps the existing API_SECRET, and re-syncs the registry entry.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
step() { echo -e "\n${BLUE}▶ $*${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "\n${RED}✗ $*${NC}" >&2; exit 1; }

HUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$HUB_DIR/.." && pwd)"
REGISTRY="${HUB_SERVERS_FILE:-$HUB_DIR/servers.json}"

# ─── Arguments ────────────────────────────────────────────────────────────
TARGET=""; ID=""; NAME=""; PORT=""; BRANCH=""; REPO_URL=""
REMOTE_DIR="/opt/fail2ban-dashboard"
AGENT_PORT="${AGENT_PORT:-3001}"
DRY_RUN=0; INSTALL_NODE=0; NO_SERVICE=0

usage() {
  cat <<EOF
Usage: bash hub/enroll.sh [options] user@host

  --id <slug>        registry id (default: derived from the hostname)
  --name <text>      display name in the UI (default: same as --id)
  --port <n>         local tunnel port on this machine (default: next free from 4101)
  --branch <name>    branch to deploy (default: this clone's current branch)
  --repo <url>       git URL to clone on the server (default: this clone's origin)
  --dir <path>       install path on the server (default: $REMOTE_DIR)
  --install-node     install Node.js 20 from NodeSource if the server has none
  --no-service       install the code but skip the systemd unit
  --dry-run          print what would happen; touch nothing
  -h, --help         this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --id)       ID="${2:?--id needs a value}"; shift 2 ;;
    --name)     NAME="${2:?--name needs a value}"; shift 2 ;;
    --port)     PORT="${2:?--port needs a value}"; shift 2 ;;
    --branch)   BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    --repo)     REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
    --dir)      REMOTE_DIR="${2:?--dir needs a value}"; shift 2 ;;
    --install-node) INSTALL_NODE=1; shift ;;
    --no-service)   NO_SERVICE=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    -*)         die "Unknown option: $1" ;;
    *)          [ -z "$TARGET" ] || die "Only one target allowed (got '$TARGET' and '$1')"; TARGET="$1"; shift ;;
  esac
done

[ -n "$TARGET" ] || { usage; exit 1; }
[[ "$TARGET" == *@* ]] || die "Target must be user@host (the SSH user matters — the agent runs as it)."

command -v ssh  >/dev/null || die "ssh not found."
command -v node >/dev/null || die "node not found. The hub needs it, and so does this script."

# ─── One SSH connection for the whole run ─────────────────────────────────
# Every separate session is an auth event in the target's logs, and an sshd jail
# in aggressive mode bans on patterns of short-lived connections — this tool
# would otherwise get itself banned by the very software it monitors. A shared
# ControlMaster socket means one authentication no matter how many steps run.
CTL_SOCK="$(mktemp -u "${TMPDIR:-/tmp}/f2b-enroll-%C.XXXXXX")"
SSH_OPTS=(-o ControlMaster=auto -o "ControlPath=$CTL_SOCK" -o ControlPersist=120s
          -o ConnectTimeout=10 -o ServerAliveInterval=15)
close_ssh() { ssh -O exit -o "ControlPath=$CTL_SOCK" "${TARGET:-x}" 2>/dev/null || true; }
rsh()  { ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$TARGET" "$@"; }
rsht() { ssh "${SSH_OPTS[@]}" -tt "$TARGET" "$@"; }   # TTY, so sudo can prompt
# Close the shared connection on any exit, including the --dry-run path, rather
# than leaving it idling for ControlPersist.
trap close_ssh EXIT

REMOTE_HOST="${TARGET#*@}"
[ -n "$ID" ] || ID="$(echo "$REMOTE_HOST" | sed 's/\..*$//; s/[^a-zA-Z0-9_-]/-/g')"
[ -n "$NAME" ] || NAME="$ID"
[[ "$ID" =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || die "Bad --id '$ID' (allowed: letters, digits, _ and -)."

if [ -z "$BRANCH" ]; then
  BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
fi
if [ -z "$REPO_URL" ]; then
  REPO_URL="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
  [ -n "$REPO_URL" ] || die "Could not read origin from this clone — pass --repo <url>."
fi

# ─── Pick a free local tunnel port ────────────────────────────────────────
# Ports are local to this machine, so any free one works; staying in the 41xx
# range keeps them recognisable next to the systemd unit names.
pick_port() {
  node - "$REGISTRY" "$ID" <<'NODE'
const fs = require('fs');
const [file, id] = process.argv.slice(2);
let list = [];
try { list = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { list = []; }
if (!Array.isArray(list)) list = [];
const mine = list.find(s => s && s.id === id);
if (mine && mine.baseUrl) {                     // re-enrolling: keep its port
  const p = Number(new URL(mine.baseUrl).port);
  if (p) { console.log(p); process.exit(0); }
}
const taken = new Set(list.map(s => {
  try { return Number(new URL(s.baseUrl).port); } catch { return 0; }
}).filter(Boolean));
let p = 4101;
while (taken.has(p)) p++;
console.log(p);
NODE
}
[ -n "$PORT" ] || PORT="$(pick_port)"
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || die "Bad --port '$PORT'."

echo -e "${GREEN}🛡  Enrolling a server into this hub${NC}"
cat <<EOF

  target        $TARGET
  registry id   $ID  ("$NAME")
  tunnel        127.0.0.1:$PORT  →  $TARGET:127.0.0.1:$AGENT_PORT
  install       $REMOTE_DIR  ($REPO_URL, branch $BRANCH)
  registry      $REGISTRY
EOF
[ "$DRY_RUN" = "1" ] && echo -e "\n  ${YELLOW}dry run — nothing will be changed${NC}"

# ─── 1+2. Reachability and pre-flight, in ONE connection ──────────────────
# Deliberately a single SSH session: each connection is a line in the server's
# auth.log, and this tool exists to talk to hosts that ban on auth patterns.
step "1/5  Connecting and pre-flighting $REMOTE_HOST"
PREFLIGHT="$(rsh bash <<PF 2>/dev/null || true
  echo "remote_user=\$(whoami)"
  echo "hub_ip=\${SSH_CLIENT%% *}"
  echo "hostname=\$(hostname)"
  # Probe the binary, not \`fail2ban-client version\` — on fail2ban 1.x that
  # command opens the socket and fails for an unprivileged user, which would
  # look exactly like fail2ban being absent.
  echo "f2b=\$(command -v fail2ban-client 2>/dev/null || echo MISSING)"
  echo "f2b_ver=\$(dpkg-query -W -f='\${Version}' fail2ban 2>/dev/null || echo unknown)"
  echo "f2b_active=\$(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
  echo "node=\$(command -v node >/dev/null 2>&1 && node -v || echo MISSING)"
  echo "git=\$(command -v git >/dev/null 2>&1 && echo yes || echo MISSING)"
  echo "port_busy=\$(ss -tlnH 2>/dev/null | grep -c ':$AGENT_PORT ' || true)"
  # Deliberately NOT probing sudo here. A failed \`sudo -n\` writes a PAM
  # authentication failure to auth.log, and a jail watching that file (the
  # pam-generic pattern, usually with an allports action) will ban the hub —
  # locking you out of the very server you are enrolling. sudo is used once,
  # later, under a TTY where it can prompt properly.
  echo "in_adm=\$(id -nG | tr ' ' '\n' | grep -qx adm && echo yes || echo no)"
  echo "ignoreip=\$(grep -hs '^ *ignoreip' /etc/fail2ban/jail.local /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2- | xargs || echo none)"
  echo "installed=\$([ -d $REMOTE_DIR/.git ] && echo yes || echo no)"
PF
)"
get() { echo "$PREFLIGHT" | sed -n "s/^$1=//p"; }

REMOTE_USER="$(get remote_user)"
[ -n "$REMOTE_USER" ] || die "Cannot SSH to $TARGET without a password.
   Fix it first — the tunnel needs it too:
     ssh-copy-id $TARGET
     ssh -o BatchMode=yes $TARGET true"
ok "key auth works, remote user is '$REMOTE_USER'"

R_F2B="$(get f2b)"; R_NODE="$(get node)"; R_GIT="$(get git)"
R_PORT_BUSY="$(get port_busy)"; R_INSTALLED="$(get installed)"

[ "$R_F2B" != "MISSING" ] || die "fail2ban is not installed on $REMOTE_HOST.
   This tool monitors an existing fail2ban; it does not configure one.
   Install and configure your jails first (DEPLOY.md A2)."
R_F2B_ACTIVE="$(get f2b_active)"
ok "fail2ban $(get f2b_ver) at $R_F2B, service is $R_F2B_ACTIVE"
[ "$R_F2B_ACTIVE" = "active" ] || warn "fail2ban is not running — the agent will install fine but report nothing until it is"

if [ "$R_NODE" = "MISSING" ]; then
  [ "$INSTALL_NODE" = "1" ] || die "Node.js is missing on $REMOTE_HOST.
   Re-run with --install-node to install Node 20 from NodeSource, or install it yourself."
  warn "Node.js missing — will install Node 20 from NodeSource"
else
  NODE_MAJOR="$(echo "$R_NODE" | sed 's/^v//; s/\..*$//')"
  if [ "${NODE_MAJOR:-0}" -lt 18 ]; then
    [ "$INSTALL_NODE" = "1" ] || die "Node $R_NODE is too old (need 18+). Re-run with --install-node."
    warn "Node $R_NODE too old — will install Node 20"
  else
    ok "Node $R_NODE"
  fi
fi
[ "$R_GIT" = "yes" ] || warn "git missing — will install it"

if [ "$R_PORT_BUSY" != "0" ] && [ "$R_INSTALLED" = "no" ]; then
  die "Port $AGENT_PORT is already in use on $REMOTE_HOST by something else.
   Pick another with AGENT_PORT=<n> bash hub/enroll.sh … (it is loopback-only either way)."
fi
[ "$R_INSTALLED" = "yes" ] && ok "already installed at $REMOTE_DIR — this will update it in place" \
                           || ok "port $AGENT_PORT is free"

# ─── Can this server ban the hub? ─────────────────────────────────────────
# The hub keeps a long-lived SSH connection open and reconnects with backoff.
# If its egress IP isn't exempt, a jail on this server can lock the hub out —
# and an all-ports action locks out your shell with it.
HUB_IP="$(get hub_ip)"
R_IGNOREIP="$(get ignoreip)"

# ignoreip entries are usually CIDR ranges, so a string compare would report a
# covered address as missing. Test containment properly.
ip_is_ignored() {
  node - "$1" "$2" <<'NODE'
const [ip, list] = process.argv.slice(2);
const toInt = a => a.split('.').reduce((n, o) => (n << 8 >>> 0) + Number(o), 0) >>> 0;
const isV4 = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
if (!isV4(ip)) process.exit(1);                       // IPv6: fall back to exact match below
const target = toInt(ip);
for (const raw of list.split(/[\s,]+/).filter(Boolean)) {
  const [addr, bitsRaw] = raw.split('/');
  if (!isV4(addr)) { if (addr === ip) process.exit(0); continue; }
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  if ((target & mask) >>> 0 === (toInt(addr) & mask) >>> 0) process.exit(0);
}
process.exit(1);
NODE
}

if [ -n "$HUB_IP" ]; then
  if ip_is_ignored "$HUB_IP" "$R_IGNOREIP" || echo " $R_IGNOREIP " | grep -q " $HUB_IP "; then
    ok "this hub's IP ($HUB_IP) is in fail2ban's ignoreip"
  else
    warn "this hub's IP ($HUB_IP) is NOT in fail2ban's ignoreip on $REMOTE_HOST."
    warn "   The hub reconnects continuously; a jail here can ban it and lock you out."
    warn "   Add to /etc/fail2ban/jail.local, then 'sudo fail2ban-client reload':"
    warn "     [DEFAULT]"
    warn "     ignoreip = ${R_IGNOREIP:-127.0.0.1/8 ::1} $HUB_IP"
  fi
fi

if [ "$DRY_RUN" = "1" ]; then
  echo -e "\n${YELLOW}Dry run complete.${NC} Pre-flight passed; nothing was changed."
  echo    "Re-run without --dry-run to install the agent and register this server."
  exit 0
fi

# ─── 3. Install the agent ─────────────────────────────────────────────────
# The script is staged remotely and then run under a TTY so sudo can prompt
# without fighting the script for stdin.
step "2/5  Installing the agent on $REMOTE_HOST"
REMOTE_SCRIPT="$(mktemp)"
trap 'rm -f "$REMOTE_SCRIPT"; close_ssh' EXIT
cat > "$REMOTE_SCRIPT" <<EOF
set -euo pipefail
REMOTE_DIR="$REMOTE_DIR"
REPO_URL="$REPO_URL"
BRANCH="$BRANCH"
AGENT_PORT="$AGENT_PORT"
INSTALL_NODE=$INSTALL_NODE
NO_SERVICE=$NO_SERVICE
EOF
cat >> "$REMOTE_SCRIPT" <<'EOF'
say() { echo "  · $*"; }

if [ "$INSTALL_NODE" = "1" ]; then
  if ! command -v node >/dev/null 2>&1 || [ "$(node -e 'process.stdout.write(process.version.match(/v(\d+)/)[1])')" -lt 18 ]; then
    say "installing Node.js 20 + git"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null
    sudo apt-get install -y nodejs git >/dev/null
  fi
fi
command -v git >/dev/null 2>&1 || { say "installing git"; sudo apt-get install -y git >/dev/null; }

# Code
if [ -d "$REMOTE_DIR/.git" ]; then
  say "updating $REMOTE_DIR to $BRANCH"
  cd "$REMOTE_DIR"
  git fetch --quiet origin "$BRANCH"
  git checkout --quiet "$BRANCH"
  git pull --quiet --ff-only origin "$BRANCH"
else
  say "cloning into $REMOTE_DIR"
  sudo mkdir -p "$REMOTE_DIR"
  sudo chown "$USER:$USER" "$REMOTE_DIR"
  git clone --quiet --branch "$BRANCH" "$REPO_URL" "$REMOTE_DIR"
  cd "$REMOTE_DIR"
fi

# Agent deps + .env (setup.sh keeps an existing API_SECRET)
say "installing agent dependencies"
bash setup.sh agent >/dev/null
[ "$AGENT_PORT" = "3001" ] || sed -i "s/^PORT=.*/PORT=$AGENT_PORT/" backend/.env

# Access to fail2ban and the logs
if ! sudo -n fail2ban-client ping >/dev/null 2>&1; then
  say "granting passwordless fail2ban-client (sudoers)"
  F2B_BIN="$(command -v fail2ban-client)"
  echo "$USER ALL=(root) NOPASSWD: $F2B_BIN" | sudo tee /etc/sudoers.d/fail2ban-dashboard >/dev/null
  sudo chmod 440 /etc/sudoers.d/fail2ban-dashboard
  sudo visudo -c >/dev/null || { sudo rm -f /etc/sudoers.d/fail2ban-dashboard; echo "  ✗ sudoers file rejected — removed it"; exit 1; }
fi
id -nG | tr ' ' '\n' | grep -qx adm || { say "adding $USER to adm (log reads)"; sudo usermod -aG adm "$USER"; }

# Service. Systemd starts it with fresh group membership, so the adm group
# above takes effect here without needing a new login shell.
if [ "$NO_SERVICE" != "1" ]; then
  say "installing the fail2ban-agent service"
  sudo tee /etc/systemd/system/fail2ban-agent.service >/dev/null <<UNIT
[Unit]
Description=Fail2Ban Dashboard Agent (API only)
After=network.target fail2ban.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$REMOTE_DIR/backend
EnvironmentFile=$REMOTE_DIR/backend/.env
ExecStart=$(command -v node) src/server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  # An older single-service deployment would hold the port; retire it.
  if systemctl is-active --quiet fail2ban-dashboard 2>/dev/null; then
    say "stopping the previous fail2ban-dashboard unit"
    sudo systemctl disable --now fail2ban-dashboard >/dev/null 2>&1 || true
  fi
  sudo systemctl enable --now fail2ban-agent >/dev/null 2>&1
  sudo systemctl restart fail2ban-agent
fi
echo "  · agent install done"
EOF

rsh "cat > /tmp/f2b-enroll.$$.sh" < "$REMOTE_SCRIPT"
rsht "bash /tmp/f2b-enroll.$$.sh; rc=\$?; rm -f /tmp/f2b-enroll.$$.sh; exit \$rc" \
  || die "Remote install failed — see the output above. Nothing was added to the registry."
ok "agent installed"

# ─── 3. Verify the agent from the server's own side ───────────────────────
# One remote invocation: read the key, wait for the agent to answer, probe
# fail2ban. Retrying from this side would mean a round trip per attempt.
step "3/5  Verifying the agent"
VERIFY="$(rsh bash <<VF
  KEY=\$(grep '^API_SECRET=' $REMOTE_DIR/backend/.env | cut -d= -f2-)
  echo "key=\$KEY"
  for i in 1 2 3 4 5; do
    H=\$(curl -s -m 5 http://127.0.0.1:$AGENT_PORT/api/health || true)
    case "\$H" in *'"role":"agent"'*) break ;; esac
    sleep 2
  done
  echo "health=\$H"
  echo "status=\$(curl -s -m 8 -H "X-API-Key: \$KEY" http://127.0.0.1:$AGENT_PORT/api/status || true)"
VF
)"
vget() { echo "$VERIFY" | sed -n "s/^$1=//p"; }
AGENT_KEY="$(vget key)"
[ -n "$AGENT_KEY" ] || die "Could not read API_SECRET from $REMOTE_DIR/backend/.env."

case "$(vget health)" in
  *'"role":"agent"'*) ok "/api/health → role=agent" ;;
  *) die "The agent is not answering on 127.0.0.1:$AGENT_PORT.
   Check it with: ssh $TARGET 'journalctl -u fail2ban-agent -n 40 --no-pager'" ;;
esac

case "$(vget status)" in
  *'"ok":true'*) ok "/api/status → fail2ban replied (sudo rule works)" ;;
  *) warn "the agent runs but fail2ban did not reply: $(vget status)"
     warn "usually the sudoers rule — check: ssh $TARGET 'sudo -n fail2ban-client ping'" ;;
esac

# ─── 5. Register it here ──────────────────────────────────────────────────
step "4/5  Registering in $(basename "$REGISTRY")"
AGENT_KEY="$AGENT_KEY" node - "$REGISTRY" "$ID" "$NAME" "$PORT" "$TARGET" <<'NODE'
const fs = require('fs');
const [file, id, name, port, ssh] = process.argv.slice(2);
const apiKey = process.env.AGENT_KEY;
let list = [];
if (fs.existsSync(file)) {
  const raw = fs.readFileSync(file, 'utf8').trim();
  if (raw) {
    try { list = JSON.parse(raw); } catch (e) {
      console.error(`  ✗ ${file} is not valid JSON (${e.message}) — fix or move it, then re-run.`);
      process.exit(1);
    }
  }
}
if (!Array.isArray(list)) { console.error(`  ✗ ${file} must contain a JSON array.`); process.exit(1); }

// Drop untouched example rows: a placeholder entry is a tunnel that can never
// connect, and the hub refuses to start while one is present.
const before = list.length;
list = list.filter(s => s && !/^PASTE_/.test(s.apiKey || '') && !/\.example\.com(:|$)/.test(s.ssh || ''));
const dropped = before - list.length;

const entry = { id, name, baseUrl: `http://127.0.0.1:${port}`, apiKey, ssh };
const at = list.findIndex(s => s && s.id === id);
const action = at >= 0 ? 'updated' : 'added';
if (at >= 0) list[at] = entry; else list.push(entry);

fs.writeFileSync(file, JSON.stringify(list, null, 2) + '\n', { mode: 0o600 });
fs.chmodSync(file, 0o600);
if (dropped) console.log(`  · removed ${dropped} unedited example entr${dropped === 1 ? 'y' : 'ies'}`);
console.log(`  · ${action} "${id}" → 127.0.0.1:${port} (${list.length} server(s) registered)`);
NODE
ok "registry written (mode 600), key copied straight from the server"

# ─── 6. What's next ───────────────────────────────────────────────────────
step "5/5  Done"
echo ""
echo -e "  ${GREEN}$NAME ($ID) is enrolled.${NC}"
echo ""
echo "  The hub reads servers.json at startup, so pick it up with whichever applies:"
echo ""
echo "    workstation hub :  Ctrl-C in the hub terminal, then  cd hub && npm start"
echo "    shared hub      :  sudo TUNNEL_USER=\$USER bash hub/install-tunnels.sh"
echo "                       sudo systemctl restart fail2ban-hub"
echo ""
echo -e "  Then open  ${GREEN}http://127.0.0.1:3100${NC}  — use 127.0.0.1, not localhost."
echo ""
