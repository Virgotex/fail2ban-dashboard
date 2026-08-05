#!/usr/bin/env bash
# setup.sh — bootstrap one role of the fail2ban dashboard.
#
# The dashboard is a two-role system:
#
#   agent  — runs on each MONITORED server. API only, no UI, no build step.
#   hub    — runs on ONE management host. Aggregates every agent and serves
#            the only web UI. This is what you point a browser at.
#
# Usage:
#   bash setup.sh agent         # on a server you want to monitor
#   bash setup.sh hub           # on a management server
#   bash setup.sh hub --local   # on your own machine (hub opens its own tunnels)
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ROLE="${1:-}"
LOCAL=0
[ "${2:-}" = "--local" ] && LOCAL=1

if [ "$ROLE" != "agent" ] && [ "$ROLE" != "hub" ]; then
  echo -e "${RED}✗ Specify a role.${NC}\n"
  echo "  bash setup.sh agent        — on a server you want to monitor (API only, no UI)"
  echo "  bash setup.sh hub          — on a management server (serves the UI to SSH users)"
  echo "  bash setup.sh hub --local  — on your own laptop/desktop (the hub opens its own"
  echo "                               SSH tunnels; no root, no systemd, just npm start)"
  echo ""
  echo "Every monitored server needs an agent. Each person viewing the fleet runs a hub."
  exit 1
fi

echo -e "${GREEN}🛡  Fail2Ban Dashboard Setup — ${BLUE}${ROLE}${NC}\n"

# ── Prerequisites ─────────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || { echo -e "${RED}✗ Node.js not found. Install from https://nodejs.org${NC}"; exit 1; }
command -v npm  >/dev/null 2>&1 || { echo -e "${RED}✗ npm not found.${NC}"; exit 1; }
NODE_MAJOR=$(node -e "process.stdout.write(process.version.match(/v(\d+)/)[1])")
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo -e "${RED}✗ Node.js 18+ required (found $(node -v))${NC}"; exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v)${NC}"

gen_secret() { node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"; }

# Everything below generates real secrets into this working tree. Point git at
# the repo's hooks so a stray `git add` can't publish them — .gitignore alone
# doesn't survive `git add -f`, a rename, or a key pasted into a doc.
if [ -d .git ] && [ -x .githooks/pre-commit ]; then
  if [ "$(git config --get core.hooksPath 2>/dev/null)" != ".githooks" ]; then
    git config core.hooksPath .githooks 2>/dev/null \
      && echo -e "${GREEN}✓ Enabled the secret-blocking pre-commit hook${NC}"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────
#  AGENT
# ─────────────────────────────────────────────────────────────────────────
if [ "$ROLE" = "agent" ]; then
  if [ ! -f backend/.env ]; then
    cp backend/.env.example backend/.env
    sed -i "s/change_this_to_a_random_secret_string/$(gen_secret)/g" backend/.env
    echo -e "${GREEN}✓ Created backend/.env with a generated API_SECRET${NC}"
  else
    echo -e "${YELLOW}⚠  backend/.env already exists — keeping its API_SECRET${NC}"
  fi

  # Only the agent's dependencies. The frontend is never built on a monitored
  # server — that's the whole point of the agent being headless.
  echo -e "\n📦 Installing agent dependencies…"
  (cd backend && npm install --omit=dev --silent)

  echo ""
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo -e "${GREEN}✓ fail2ban-client found${NC}"
    if sudo fail2ban-client ping 2>/dev/null | grep -q pong; then
      echo -e "${GREEN}✓ fail2ban daemon is running${NC}"
    else
      echo -e "${YELLOW}⚠  fail2ban daemon not responding — start it with: sudo systemctl start fail2ban${NC}"
    fi
  else
    echo -e "${YELLOW}⚠  fail2ban-client not found. Install with: sudo apt install fail2ban${NC}"
  fi

  AGENT_KEY=$(grep '^API_SECRET=' backend/.env | cut -d= -f2-)

  echo -e "\n${GREEN}✅ Agent ready.${NC}"
  echo ""
  echo -e "${YELLOW}This server's API_SECRET — the hub needs it:${NC}"
  echo "  $AGENT_KEY"
  echo ""
  echo "Next:"
  echo "  1. Grant fail2ban access (sudoers + log ACLs) — see DEPLOY.md A5"
  echo "  2. Run it as a service                        — see DEPLOY.md A6"
  echo "  3. On the hub host, add this server to hub/servers.json with the key above"
  echo ""
  echo -e "${RED}⚠  ${NC}The agent binds to 127.0.0.1 and has no UI. Do not open port 3001"
  echo    "   in your firewall — the hub reaches it over an SSH tunnel."
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────
#  HUB
# ─────────────────────────────────────────────────────────────────────────
if [ ! -f hub/.env ]; then
  cp hub/.env.example hub/.env
  sed -i "s/change_this_to_a_random_secret_string/$(gen_secret)/g" hub/.env
  echo -e "${GREEN}✓ Created hub/.env with a generated HUB_API_SECRET${NC}"
else
  echo -e "${YELLOW}⚠  hub/.env already exists — keeping its HUB_API_SECRET${NC}"
fi

HUB_KEY=$(grep '^HUB_API_SECRET=' hub/.env | cut -d= -f2-)

# Workstation mode: the hub supervises its own SSH tunnels, so there's nothing
# to install as root and nothing left running when you quit.
if [ "$LOCAL" = "1" ]; then
  grep -v '^HUB_MANAGE_TUNNELS=' hub/.env > hub/.env.tmp && mv hub/.env.tmp hub/.env
  echo "HUB_MANAGE_TUNNELS=true" >> hub/.env
  echo -e "${GREEN}✓ Local mode: the hub will open and supervise its own SSH tunnels${NC}"
  command -v ssh >/dev/null 2>&1 || echo -e "${YELLOW}⚠  ssh not found on PATH — the hub needs it to reach your servers${NC}"
fi

# The SPA is served by the hub, so its embedded key is the HUB's key.
if [ ! -f frontend/.env.local ] || ! grep -q "^VITE_API_KEY=${HUB_KEY}$" frontend/.env.local; then
  echo "VITE_API_KEY=${HUB_KEY}" > frontend/.env.local
  echo -e "${GREEN}✓ Wrote frontend/.env.local (matches HUB_API_SECRET)${NC}"
else
  echo -e "${GREEN}✓ frontend/.env.local already matches HUB_API_SECRET${NC}"
fi

if [ ! -f hub/servers.json ]; then
  cp hub/servers.example.json hub/servers.json
  echo -e "${GREEN}✓ Created hub/servers.json from the example${NC}"
  NEEDS_REGISTRY=1
else
  echo -e "${YELLOW}⚠  hub/servers.json already exists — leaving it alone${NC}"
  NEEDS_REGISTRY=0
fi

echo -e "\n📦 Installing hub dependencies…"
(cd hub && npm install --silent)

echo "📦 Installing frontend build tooling…"
(cd frontend && npm install --silent)

echo "🏗  Building the dashboard…"
(cd frontend && npm run build >/dev/null)
echo -e "${GREEN}✓ Built frontend/dist — the hub serves this${NC}"

echo -e "\n${GREEN}✅ Hub ready.${NC}"
echo ""
if [ "$NEEDS_REGISTRY" = "1" ]; then
  echo -e "${YELLOW}Next: register your servers.${NC} Edit hub/servers.json — one entry per"
  echo    "agent, with its tunnel port, its own API_SECRET, and its ssh target:"
  echo    '  { "id":"web-01", "name":"Web 01", "baseUrl":"http://127.0.0.1:4101",'
  echo    '    "apiKey":"<that agent'"'"'s API_SECRET>", "ssh":"user@web-01" }'
  echo ""
fi
if [ "$LOCAL" = "1" ]; then
  echo "Make sure you can SSH to each server without a password:"
  echo "  ssh -o BatchMode=yes user@your-server true      # else: ssh-copy-id user@your-server"
  echo ""
  echo "Then start everything with one command:"
  echo "  cd hub && npm start"
  echo ""
  echo -e "  → ${GREEN}http://localhost:3100${NC}"
  echo ""
  echo "The hub opens a tunnel per server as it starts, reconnects them if they"
  echo "drop, and closes them when you quit (Ctrl-C). Nothing is left running."
  echo ""
  echo -e "${RED}⚠  Security note:${NC} hub/servers.json on this machine holds every agent's"
  echo    "   key. Keep it to yourself (chmod 600) and see docs/SECURITY.md."
else
  echo "Then:"
  echo "  sudo TUNNEL_USER=\$USER bash hub/install-tunnels.sh   # systemd SSH tunnels to every agent"
  echo "  cd hub && npm start                                  # or install the unit, see DEPLOY.md"
  echo ""
  echo "Reach it from your laptop:"
  echo -e "  ssh -L 3100:127.0.0.1:3100 $(whoami)@$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo -e "  → ${GREEN}http://localhost:3100${NC}"
  echo ""
  echo -e "${RED}⚠  Security note:${NC} the hub binds to 127.0.0.1 only. Reach it over the"
  echo    "   SSH tunnel above rather than opening port 3100. See docs/SECURITY.md."
fi
