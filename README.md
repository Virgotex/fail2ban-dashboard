# 🛡 Fail2Ban Dashboard

A lightweight, security-hardened web dashboard for monitoring and managing Fail2Ban on your local Linux machine. Inspired by the [swissmakers/fail2ban-ui](https://github.com/swissmakers/fail2ban-ui) project.

**Stack:** React + Vite (frontend) · Express.js (backend API) · WebSocket (real-time updates)

> **Deploying to a server?** For a hardened, tunnel-only server install (bind to
> loopback, run as a `systemd` service, reach it over SSH — nothing exposed to the
> network), follow **[`DEPLOY.md`](DEPLOY.md)**. It's a start-to-finish, verified
> walkthrough, and its *Managing multiple servers* section covers both one-tab-per-server
> and the combined **[hub](hub/README.md)** dashboard. The Quick Start below is for
> local development.

---

## Features

- Live jail status (banned IPs, session totals)
- Real-time log viewer with filtering by level and text
- Ban/unban IPs directly from the UI
- 7-day ban trend charts and country breakdown
- Security posture checklist
- WebSocket live updates every 10 seconds
- Secure by default (see Security section)
- **Multi-server:** an optional [hub](hub/README.md) aggregates many servers into one dashboard with a fleet overview + per-server drill-down

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

> **First run:** If the fail2ban daemon isn't running or your user can't reach it, the dashboard renders empty jail lists and the sidebar marks the daemon offline. Start fail2ban (`sudo systemctl start fail2ban`) and refresh — it will connect automatically.

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
├── hub/                     # optional multi-server aggregator
│   ├── src/hub.js           # fans out to each agent, serves the fleet view
│   ├── servers.example.json # per-agent registry (copy to servers.json)
│   ├── tunnels.sh           # opens SSH tunnels to each agent
│   └── README.md            # hub setup guide
├── docs/
│   └── SECURITY.md
├── DEPLOY.md                # hardened tunnel-only server + multi-server setup
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
| Rate limiting | 100 req/min global · 20 req/min for writes (honours `trust proxy`) |
| Input validation | All parameters validated before use |
| No shell injection | Commands built as arg arrays — never string-interpolated |
| IP validation | Strict IPv4/IPv6/CIDR regex before any ban/unban |
| API key transport | `X-API-Key` header for HTTP; `Sec-WebSocket-Protocol` for WS — never in URLs or access logs |
| Constant-time key check | `crypto.timingSafeEqual` to prevent timing attacks |
| WebSocket auth | Origin check + API key on every upgrade |
| Payload size limit | JSON body capped at 10KB |
| Log reads bounded | Only the last few MB of `fail2ban.log` and friends are read per request |
| Geo lookups proxied | IP intel goes through the backend (cached) so investigated IPs don't leak to a third party from your browser |

> **Auth scope:** The `VITE_API_KEY` ships inside the React bundle — anyone who can load the dashboard URL holds the key. It exists to gate non-browser callers, not to authenticate end users. For multi-user / LAN access add OIDC or a session+password layer in front (see `docs/SECURITY.md`).

### What you should add for LAN/production use

1. **Put it behind a reverse proxy with HTTPS** (Nginx or Caddy).
2. **Switch to OIDC** by setting `OIDC_ENABLED=true` and the matching env vars (see `backend/.env.example`). Works with Keycloak, Authentik, Okta, Azure AD, Auth0 — anything OIDC-compliant. Set `OIDC_REQUIRED_GROUP` to limit ban/unban to a specific group/role.
3. **Restrict reachability** — host firewall on the dashboard's port (or a private subnet / NetworkPolicy in k8s); only the reverse proxy should be able to reach it.

See `docs/SECURITY.md` for the detailed OIDC walkthrough and example reverse-proxy configs.

---

## Production deployment

For a full, verified server walkthrough — host hardening, fail2ban setup,
least-privilege sudo, `systemd` service, and SSH-tunnel access — follow
**[`DEPLOY.md`](DEPLOY.md)**. The short version:

```bash
# 1. Build the SPA
cd frontend && npm run build

# 2. Configure the backend
cd ../backend && cp .env.example .env
# Set NODE_ENV=production, BIND_ADDRESS=127.0.0.1, and (for LAN/public) OIDC_*.

# 3. Start it (or better, run it as a systemd service — see DEPLOY.md Part 6)
NODE_ENV=production node src/server.js
```

### Multiple servers

Two ways to monitor a fleet, both in **[`DEPLOY.md`](DEPLOY.md)** → *Managing
multiple servers*:

- **One tab per server** — deploy an agent on each and tunnel to each on a
  different local port. No extra service.
- **Combined dashboard (hub)** — run the optional **[hub](hub/README.md)**, which
  aggregates every agent into a single fleet overview with a server picker and
  per-server drill-down. Live aggregator (no stored history), good for up to a
  few dozen servers.

When `frontend/dist/index.html` exists, the backend serves the SPA from the same origin — one process, one port, one auth boundary. The startup banner confirms it:

```
🛡  Fail2Ban Dashboard API
   Listening on http://0.0.0.0:3001
   Auth mode:    OIDC (writes require "fail2ban-admins")
   SPA serving:  on (/srv/fail2ban-dashboard/frontend/dist)
```

Every ban/unban emits a structured audit line (`[AUDIT] {"ts":…,"user":"<oidc-sub>","action":"ban",…}`) — pipe stdout to journald or your log aggregator.

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
