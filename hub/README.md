# Multi-Server Hub

One dashboard across many servers. The **hub** aggregates the per-server
dashboard backends ("agents") you've already deployed and lets you see a fleet
overview and drill into any single server — with the same Dashboard, Logs,
Reports, Banned IPs, and IP-investigation views you get in single-server mode.

```
Your laptop ──SSH tunnel──▶ Hub (this)
                              │  reads servers.json, fans out concurrently
                              ├──SSH tunnel──▶ Agent web-01  (127.0.0.1:3001) ─▶ fail2ban
                              ├──SSH tunnel──▶ Agent web-02  (127.0.0.1:3001) ─▶ fail2ban
                              └──SSH tunnel──▶ Agent db-01   (127.0.0.1:3001) ─▶ fail2ban
```

## How it works

- **Agents** are unchanged single-server installs (see [`../DEPLOY.md`](../DEPLOY.md)).
  Each stays bound to `127.0.0.1:3001` on its own host and keeps its own
  `API_SECRET`.
- **The hub** reaches each agent over an **SSH tunnel** to a distinct local port
  (e.g. `4101`, `4102`, …). It authenticates to each agent with that agent's
  `API_SECRET`, stored server-side in `servers.json` — the agent keys **never**
  reach the browser.
- **The browser** talks only to the hub (over its own SSH tunnel), authenticated
  with the hub's own `HUB_API_SECRET`.
- One dead agent degrades to an "offline" row; it never breaks the fleet view.

> **Scope / limits.** This is a *live* aggregator: it shows real-time data by
> querying each agent on demand. It does **not** store history — if a server is
> offline you see nothing for it until it's back. This design is comfortable for
> up to a few dozen servers. Beyond that, or if you need history that survives
> downtime, you'd want a push-to-central-store architecture instead (not built
> here).

---

## Setup

Do this on the **hub host** — a box that can SSH to every agent. It can be a
dedicated management server or one of the agents.

### 1. Deploy the agents first

Each server you want to monitor must already run the dashboard as an agent —
follow [`../DEPLOY.md`](../DEPLOY.md) Parts 1–6 on each. Note each agent's
`API_SECRET` (from its `backend/.env`); you'll need them below.

### 2. Install the hub

```bash
cd /opt/fail2ban-dashboard/hub
npm install
cp .env.example .env
```

Generate the hub's own secret and put it in `.env` as `HUB_API_SECRET`:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Set `NODE_ENV=production` and keep `HUB_BIND_ADDRESS=127.0.0.1`.

### 3. Open tunnels to each agent

Edit the `AGENTS` list in [`tunnels.sh`](tunnels.sh) — one line per agent,
`"<localPort> <ssh-target>"` — then:
```bash
bash tunnels.sh
ss -tlnp | grep -E '410[0-9]'      # confirm the local ports are listening
```
Each agent is now reachable at `http://127.0.0.1:<localPort>` on the hub host.
(For production, run these as `autossh` or per-tunnel systemd units so they
auto-reconnect.)

### 4. Register the servers

```bash
cp servers.example.json servers.json
nano servers.json
```
For each agent set `id`, `name`, the tunnel `baseUrl`
(`http://127.0.0.1:<localPort>`), and that agent's `API_SECRET` as `apiKey`:
```json
[
  { "id": "web-01", "name": "Web 01", "baseUrl": "http://127.0.0.1:4101", "apiKey": "<web-01 API_SECRET>" },
  { "id": "web-02", "name": "Web 02", "baseUrl": "http://127.0.0.1:4102", "apiKey": "<web-02 API_SECRET>" }
]
```
> `servers.json` holds every agent's secret — it's **gitignored**. Never commit it.

### 5. Build the SPA for the hub

The bundle's embedded key must be the **hub** secret. Build the frontend with
`VITE_API_KEY` set to `HUB_API_SECRET`:
```bash
cd ../frontend
echo "VITE_API_KEY=$(grep '^HUB_API_SECRET' ../hub/.env | cut -d= -f2)" > .env.local
npm run build
cd ../hub
```
The hub serves this build from `../frontend/dist`.

### 6. Run the hub as a service

```bash
sudo tee /etc/systemd/system/fail2ban-hub.service >/dev/null <<EOF
[Unit]
Description=Fail2Ban Dashboard Hub
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/fail2ban-dashboard/hub
EnvironmentFile=/opt/fail2ban-dashboard/hub/.env
ExecStart=/usr/bin/node src/hub.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now fail2ban-hub
systemctl status fail2ban-hub --no-pager
ss -tlnp | grep 3100                 # MUST show 127.0.0.1:3100
```

### 7. Access it

From your **laptop**, tunnel to the hub and open it:
```bash
ssh -L 3100:127.0.0.1:3100 youruser@HUB_HOST_IP
# → http://localhost:3100
```
You'll land on the **Fleet overview**. Pick a server (sidebar dropdown or click a
row) to drill into its per-server dashboard.

---

## API reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | none | Liveness |
| `GET /api/mode` | none | Tells the SPA it's a hub |
| `GET /api/servers` | key | List of `{id,name}` (no secrets) |
| `GET /api/overview` | key | Per-server summary + fleet totals |
| `* /api/servers/:id/<agentPath>` | key | Whitelisted proxy to one agent |

Auth is the `X-API-Key` header carrying `HUB_API_SECRET` (constant-time compare).

## Verify

```bash
curl -s http://127.0.0.1:3100/api/mode; echo
curl -s -H "X-API-Key: $(grep '^HUB_API_SECRET' .env | cut -d= -f2)" \
     http://127.0.0.1:3100/api/overview; echo
```
`/api/overview` should list every server with `online:true` and jail counts.
An `online:false` server means the tunnel is down or that agent's `apiKey` is
wrong in `servers.json`.
