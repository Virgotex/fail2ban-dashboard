#!/usr/bin/env bash
# setup.sh — bootstrap the fail2ban-dashboard project
# Run once after cloning: bash setup.sh
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}🛡  Fail2Ban Dashboard Setup${NC}\n"

# ── Check prerequisites ────────────────────────────────────────────────────
command -v node  >/dev/null 2>&1 || { echo -e "${RED}✗ Node.js not found. Install from https://nodejs.org${NC}"; exit 1; }
command -v npm   >/dev/null 2>&1 || { echo -e "${RED}✗ npm not found.${NC}"; exit 1; }
NODE_MAJOR=$(node -e "process.stdout.write(process.version.match(/v(\d+)/)[1])")
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo -e "${RED}✗ Node.js 18+ required (found $(node -v))${NC}"; exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v)${NC}"

# ── Generate a secret ─────────────────────────────────────────────────────
SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# ── Backend .env ──────────────────────────────────────────────────────────
if [ ! -f backend/.env ]; then
  cp backend/.env.example backend/.env
  sed -i "s/change_this_to_a_random_secret_string/${SECRET}/g" backend/.env
  echo -e "${GREEN}✓ Created backend/.env with generated secret${NC}"
else
  echo -e "${YELLOW}⚠  backend/.env already exists — skipping${NC}"
fi

# ── Frontend .env.local ───────────────────────────────────────────────────
if [ ! -f frontend/.env.local ]; then
  cp frontend/.env.example frontend/.env.local
  sed -i "s/change_this_to_a_random_secret_string/${SECRET}/g" frontend/.env.local
  echo -e "${GREEN}✓ Created frontend/.env.local${NC}"
else
  echo -e "${YELLOW}⚠  frontend/.env.local already exists — skipping${NC}"
fi

# ── Install dependencies ──────────────────────────────────────────────────
echo -e "\n📦 Installing backend dependencies…"
cd backend && npm install --silent && cd ..

echo "📦 Installing frontend dependencies…"
cd frontend && npm install --silent && cd ..

# ── Fail2ban check ────────────────────────────────────────────────────────
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

echo -e "\n${GREEN}✅ Setup complete!${NC}"
echo ""
echo "To start the dashboard:"
echo -e "  ${YELLOW}Terminal 1:${NC} cd backend  && npm run dev"
echo -e "  ${YELLOW}Terminal 2:${NC} cd frontend && npm run dev"
echo ""
echo -e "Then open ${GREEN}http://localhost:5173${NC}"
echo ""
echo -e "${RED}⚠  Security note:${NC} The backend binds to 127.0.0.1 only."
echo    "   Do NOT expose port 3001 through your firewall."
echo    "   See docs/SECURITY.md for hardening guidance."
