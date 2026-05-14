# 🛡 Fail2Ban Dashboard

A lightweight, security-hardened web dashboard for monitoring and managing Fail2Ban on your local Linux machine. Inspired by the [swissmakers/fail2ban-ui](https://github.com/swissmakers/fail2ban-ui) project.

**Stack:** React + Vite (frontend) · Express.js (backend API) · WebSocket (real-time updates)

---

## Features

- Live jail status (banned IPs, session totals)
- Real-time log viewer with filtering by level and text
- Ban/unban IPs directly from the UI
- 7-day ban trend charts and country breakdown
- Security posture checklist
- WebSocket live updates every 10 seconds
- Secure by default (see Security section)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 18+ | [nodejs.org](https://nodejs.org) |
| npm 8+ | Comes with Node |
| fail2ban | `sudo apt install fail2ban` |
| Linux | Ubuntu 20.04+ / Debian 11+ recommended |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/virgotex/fail2ban-dashboard.git
cd fail2ban-dashboard

# 2. One-shot setup (generates secrets, installs deps)
bash setup.sh

# 3. Start the backend (Terminal 1)
cd backend && npm run dev

# 4. Start the frontend (Terminal 2)
cd frontend && npm run dev

# 5. Open http://localhost:5173
```

> **First run:** The dashboard starts in demo mode with mock data if fail2ban isn't running. Once the daemon is up, refresh and it connects automatically.

---

## Connecting to Your Real Fail2Ban

The backend calls `fail2ban-client` as the current user. You need permission to run it:

```bash
# Option A: add yourself to the fail2ban group (restart required)
sudo usermod -aG fail2ban $USER

# Option B: passwordless sudo for fail2ban-client only (more controlled)
sudo visudo
# Add this line:
# youruser ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

Then update `backend/.env`:

```env
FAIL2BAN_LOG=/var/log/fail2ban.log   # path to your fail2ban log
FAIL2BAN_SOCKET=/var/run/fail2ban/fail2ban.sock
```

Restart the backend and the status indicator in the sidebar will turn green.

---

## Project Structure

```
fail2ban-dashboard/
├── backend/
│   ├── src/
│   │   ├── server.js          # Express API + WebSocket server
│   │   └── fail2banClient.js  # Talks to fail2ban-client binary
│   ├── .env.example
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Main React app (all pages)
│   │   ├── hooks/useApi.js    # API client
│   │   ├── index.css
│   │   └── main.jsx
│   ├── .env.example
│   ├── index.html
│   └── vite.config.js
├── docs/
│   └── SECURITY.md
├── setup.sh
└── README.md
```

---

## Security

### What's built in

| Layer | Implementation |
|---|---|
| Secure HTTP headers | Helmet (XSS, HSTS, no-sniff, CSP) |
| CORS | Restricted to `localhost:5173` only |
| Rate limiting | 100 req/min global · 20 req/min for writes |
| Input validation | All parameters validated before use |
| No shell injection | Commands built as arg arrays — never string-interpolated |
| IP validation | Strict IPv4/IPv6/CIDR regex before any ban/unban |
| API key auth | Constant-time comparison to prevent timing attacks |
| WebSocket auth | Origin check + API key required on every upgrade |
| Payload size limit | JSON body capped at 10KB |

### What you should add for LAN/production use

1. **Put it behind a reverse proxy with HTTPS** (Nginx or Caddy)
2. **Add OIDC authentication** (Keycloak, Authentik, or Pocket-ID)
3. **Firewall port 3001** — it must NEVER be reachable from outside `127.0.0.1`

See `docs/SECURITY.md` for detailed hardening steps.

---

## Hosting on GitHub

```bash
git init
git add .
git commit -m "Initial commit: fail2ban dashboard"
gh repo create fail2ban-dashboard --public --source=. --push
# or manually:
# git remote add origin https://github.com/virgotex/fail2ban-dashboard.git
# git push -u origin main
```

The `.gitignore` already excludes `.env`, `.env.local`, and `node_modules`.

> **Important:** The `.env` files contain your API secret — they are gitignored. Never commit them.

---

## Development

```bash
# Backend with auto-reload
cd backend && npm run dev

# Frontend with HMR
cd frontend && npm run dev

# Build frontend for production
cd frontend && npm run build
```

---

## License

MIT — do whatever you want, stay secure.
