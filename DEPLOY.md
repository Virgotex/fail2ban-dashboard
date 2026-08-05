# Deployment Guide — One Dashboard, Many Servers

This guide deploys the Fail2Ban Dashboard across a fleet. Nothing is ever
exposed to the network: every service binds to `127.0.0.1` and all traffic
between them rides SSH tunnels.

There are exactly **two roles**:

```
   ┌─────────────────────────────────────┐
   │  HUB  — your laptop, or a server    │  serves the UI, holds every agent's
   │  http://localhost:3100              │  key, fans out to the fleet
   └─────────────────────────────────────┘
        │  SSH tunnels (auto-reconnecting)
        ├──────────────▶ AGENT web-01   127.0.0.1:3001 ──▶ fail2ban
        ├──────────────▶ AGENT web-02   127.0.0.1:3001 ──▶ fail2ban
        └──────────────▶ AGENT db-01    127.0.0.1:3001 ──▶ fail2ban
```

- **Agent** — runs on every monitored server. An API and nothing else: no UI, no
  session, no WebSocket, no background poll loop, and no frontend build. Its
  reads are cached and coalesced so hub polling can't turn into a stream of
  `fail2ban-client` subprocesses on a production box.
- **Hub** — the only thing with a web UI and the only thing a browser ever talks
  to. It authenticates to each agent with that agent's own key, kept
  server-side; those keys never reach the browser.

**The hub does not have to live on a server.** Run it on your own machine and it
opens its own SSH tunnels — `npm start`, then `http://localhost:3100`, no root
and nothing left running afterwards. Or run it on a management box (or one of
the monitored servers) and share it over SSH. Part B covers both; the agents are
identical either way.

> **Scope.** The hub is a *live* aggregator: it queries agents on demand and
> stores no history. An offline server shows as offline rather than showing
> stale data. This is comfortable to a few dozen servers. Past that, or if you
> need history that survives downtime, you want a push-to-central-store design
> — not what's built here.

**Assumptions:** Ubuntu/Debian, your login user has `sudo`, you have SSH access.

---

## Runbook — the order to do things in

The detail is in Parts A and B; this is the sequence, so you always know what's
next. Roughly 20 minutes for the first server, ~5 for each one after.

| # | Where | Do this | You're done when |
|---|---|---|---|
| 1 | GitHub | Host the repo; confirm no config went with it (*Secrets and hosting* below) | `git ls-files` shows no `servers.json` or `.env` |
| 2 | First monitored server | Part A — pre-flight, install agent, sudo rule, systemd unit | `/api/health` returns `role":"agent"` and `/api/status` returns `ok":true` |
| 3 | — | **Copy that server's `API_SECRET`** (`grep '^API_SECRET' backend/.env`) | you have it pasted somewhere safe |
| 4 | Hub machine (your laptop or a server) | Part B — `setup.sh hub --local` (or `hub`) | `HUB_API_SECRET` generated, UI built |
| 5 | Hub machine | Add server #1 to `hub/servers.json`: id, name, free local port, its `API_SECRET`, `ssh` target | `chmod 600 hub/servers.json` done |
| 6 | Hub machine | `ssh -o BatchMode=yes user@server true` | prints nothing / no password prompt |
| 7 | Hub machine | `cd hub && npm start` | `[tunnel] … up`, and **http://localhost:3100** shows one green row |
| 8 | Each further server | Repeat 2–3, then add an entry on the next free port and restart the hub | new row appears in the fleet overview |

Two things people trip on, both covered below: the agent's `API_SECRET` in
`servers.json` must match that server's `backend/.env` exactly, and the hub
machine must reach each server over SSH **without a password**.

### Upgrading a server that ran the older single-service build

If a box already runs the pre-split dashboard (one service serving both the API
and the UI), it becomes an agent in place — its `API_SECRET`, sudoers rule and
`adm` membership all carry over:

```bash
cd /opt/fail2ban-dashboard
git fetch origin && git checkout feat/multi-server-hub && git pull
cd backend && npm install --omit=dev && cd ..     # prunes ws / cors / oidc
sudo systemctl restart fail2ban-dashboard          # the existing unit runs the agent as-is

curl -s http://127.0.0.1:3001/api/health; echo     # → role":"agent"
grep '^API_SECRET' backend/.env                    # ← the hub needs this
rm -rf frontend/dist                               # optional: no longer served here
```

Keeping the old unit name is fine — it already runs `node src/server.js` from
`backend/`, which *is* the agent. **That box stops serving a UI** at this point:
`http://localhost:3001` will return `{"error":"Not found"}`, and the dashboard
comes from the hub instead.

---

## Step 0 — Key-based SSH is a prerequisite

The hub reaches every agent over an SSH tunnel, so **the hub host's user must be
able to log into each server without a password.** Set that up first — from the
**hub host** (not your laptop), for each server you'll monitor:

```bash
ls ~/.ssh/*.pub                        # does the hub user have a key? if not:
ssh-keygen -t ed25519                  # press Enter through the prompts
ssh-copy-id youruser@SERVER_IP         # installs it (asks for the password once)
ssh -o BatchMode=yes youruser@SERVER_IP true && echo "key auth OK"
```

That last line is the exact check `install-tunnels.sh` runs later; if it fails,
the tunnel to that server won't come up.

> ⚠️ **If you also plan to run the A1 hardening block** (fresh servers only — it
> disables password login), confirm key auth works *first* and keep a second SSH
> session open while you do it, or you can lock yourself out.

---

# Part A — Deploy an agent on each monitored server

Repeat this part on **every** server you want in the dashboard.

Most of these will be **live production servers already running fail2ban**. That
case is deliberately small: you are adding one Node process that reads
`fail2ban-client` and some log files. Read this section before you start —
it's what you'd want to know before touching a box that's serving traffic.

### What the agent adds to a server

| Change | Detail | Reversible |
|---|---|---|
| One directory | `/opt/fail2ban-dashboard` (~12 MB of dependencies + 2 MB of code) | `rm -rf` |
| One systemd service | `fail2ban-agent`, ~65 MB RSS, idles at ~0% CPU | `systemctl disable --now` |
| One listening socket | `127.0.0.1:3001` — **loopback only**, not reachable from the network | stop the service |
| One sudoers file | `/etc/sudoers.d/fail2ban-dashboard`: passwordless `fail2ban-client` for the service user | delete the file |
| One group membership | service user added to `adm` so it can read `/var/log/fail2ban.log` | `gpasswd -d` |
| Node.js 18+ | only if the server doesn't already have it | apt remove |

### What it does **not** touch

- **Your fail2ban configuration.** No jails are added, changed or reloaded. The
  agent only reads status and, when you click ban/unban, runs the same
  `fail2ban-client set …` you'd type by hand.
- **fail2ban itself is never restarted** by the install.
- **No open ports.** Nothing is added to your firewall; the agent is loopback-only
  and reached through the hub's SSH tunnel.
- **No UI, no build step, no web server** on the monitored box.
- **Your existing jails just appear** in the dashboard — that's the point.

At runtime the agent only ever: runs `fail2ban-client` (`ping`, `status`,
`status <jail>`, and `set <jail> banip|unbanip <ip>` when you click), and reads
the tail of `/var/log/fail2ban.log` plus `auth.log`/`secure`/`syslog` for IP
investigation. It writes nothing except its own journal output.

### A0 — Pre-flight on a live server

Confirm all five before you install:

```bash
fail2ban-client version          # 1. fail2ban is installed and running
sudo fail2ban-client ping        #    → Server replied: pong
node -v                          # 2. v18+ (if missing, A3 installs it)
ss -tlnp | grep 3001             # 3. port 3001 is free (empty output = good)
sudo -v                          # 4. your user has sudo
whoami                           # 5. note this user — the hub SSHes in as it
```

If port 3001 is already taken by something else, pick another and set `PORT=` in
`backend/.env` later; the hub doesn't care which port an agent uses locally.

### Quick path for an already-configured live server

If the box is already hardened and running fail2ban — the normal case —
**skip A1 and A2** and go straight to A3 → A4 → A5 → A6. In full:

```bash
# A3 (only if node -v was missing or < 18)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git

# A4 — install the agent
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard && bash setup.sh agent      # ← prints this server's API_SECRET

# A5 — let it reach fail2ban and the logs
echo "$USER ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" | sudo tee /etc/sudoers.d/fail2ban-dashboard
sudo chmod 440 /etc/sudoers.d/fail2ban-dashboard
sudo visudo -c
sudo usermod -aG adm $USER        # reconnect SSH afterwards

# A6 — run it (unit file below), then verify
curl -s http://127.0.0.1:3001/api/health
```

Save the `API_SECRET` it prints — the hub needs it in Part B. The sections
below explain each step.

## A1 — Harden the server *(fresh servers only)*

> ### ⚠️ Do not run this block on a live server
>
> It is written for a **fresh, single-purpose box**. On a server that's already
> serving traffic it will break things:
>
> - `ufw default deny incoming` + `ufw allow OpenSSH` closes **everything except
>   SSH** — your web server, database ports, and anything else your users depend
>   on go dark the moment you run `ufw enable`.
> - Overwriting the SSH config can lock you out if your access relies on
>   password auth or a non-default setup.
>
> A live server is presumably already hardened. **Skip to A2** (or A3). If you do
> want to add a firewall to a live box, enumerate its real services first
> (`ss -tlnp`), allow each explicitly, and only then enable ufw:
>
> ```bash
> sudo ufw allow OpenSSH
> sudo ufw allow 80/tcp && sudo ufw allow 443/tcp   # ← plus whatever else you found
> sudo ufw enable
> ```
>
> Either way the agent needs **no** firewall rule of its own: it is loopback-only.

For a fresh server:

```bash
# Update everything
sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y

# Harden SSH: key-only, no root login
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
EOF
sudo systemctl restart ssh
# → In a SECOND terminal, confirm: ssh youruser@SERVER_IP logs in with your key.

# Firewall: allow only SSH inbound. The agent is tunneled, never exposed.
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status verbose
```

## A2 — Install fail2ban and your jails *(skip if already running fail2ban)*

> **Live servers: skip this entire section.** The agent reads whatever
> `fail2ban-client` already reports — every jail, filter and ban you already
> have shows up in the dashboard with no config change and no reload.

Configure jails in `jail.local` — never edit `jail.conf` directly (it's
overwritten on package upgrades).

```bash
sudo apt install -y fail2ban

# Minimal starting point — replace/extend with YOUR jails and filters:
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status          # daemon up
sudo fail2ban-client status sshd     # jail present
```

Custom jails appear in the dashboard automatically. To give one a severity
badge and intent label in the UI, add it to `JAIL_META` at the top of
`frontend/src/App.jsx` and rebuild **on the hub** (that's where the UI lives).

After changing jail config later: `sudo fail2ban-client reload`.

## A3 — Install Node.js 18+ (with npm)

Install from **NodeSource** — the distro's base `nodejs` package can ship
*without* `npm`, which makes `setup.sh` fail with `✗ npm not found`:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git
node -v && npm -v                    # expect v20.x (or newer) and npm 10.x
```

If `npm -v` still errors, a conflicting Node install is on `PATH` — remove it
(`sudo apt remove -y nodejs && sudo apt autoremove -y`) and re-run the above.

## A4 — Install the agent

```bash
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard

bash setup.sh agent          # agent deps + a generated API_SECRET
```

`setup.sh agent` installs **only** the agent's dependencies — no React, no build
step, nothing user-facing on a production server. It prints this server's
`API_SECRET` at the end:

```
This server's API_SECRET — the hub needs it:
  6f1c…
```

**Write it down** (or re-read it later with
`grep '^API_SECRET' /opt/fail2ban-dashboard/backend/.env`). You'll paste it into
the hub's `servers.json` in Part B. Each agent has its own distinct key.

`backend/.env` ships with `NODE_ENV=production` and `BIND_ADDRESS=127.0.0.1`.
**Leave the bind address alone — it's the security keystone of the whole
setup:** the agent is unreachable except through the hub's SSH tunnel.

## A5 — Give the agent access to fail2ban and logs

The agent runs `fail2ban-client` via `sudo`, so it needs a passwordless rule,
and it needs to read the fail2ban/auth logs.

```bash
# Passwordless sudo for fail2ban-client
echo "$USER ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" | \
  sudo tee /etc/sudoers.d/fail2ban-dashboard
sudo chmod 440 /etc/sudoers.d/fail2ban-dashboard
sudo visudo -c                       # must report "parsed OK"

# Read access to fail2ban + auth logs (for the IP investigation feature)
sudo usermod -aG adm $USER           # reconnect SSH afterward for this to apply
```

Confirm it works with **no password prompt** — this is exactly what the service
does at runtime:

```bash
sudo -n fail2ban-client ping         # expect: Server replied: pong
```

> **Why the whole binary, not scoped verbs?** Older docs used a `Cmnd_Alias` with
> per-verb wildcards like `set * banip *`. Modern sudo on Ubuntu rejects wildcards
> that aren't at the end of a command, so that rule fails `visudo -c`. The
> binary-scoped rule above always validates. The agent still validates every IP
> and jail name and builds fixed argument arrays — no shell, ever.

## A6 — Run the agent as a service

```bash
sudo tee /etc/systemd/system/fail2ban-agent.service >/dev/null <<EOF
[Unit]
Description=Fail2Ban Dashboard Agent (API only)
After=network.target fail2ban.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/fail2ban-dashboard/backend
EnvironmentFile=/opt/fail2ban-dashboard/backend/.env
ExecStart=/usr/bin/node src/server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now fail2ban-agent
systemctl status fail2ban-agent --no-pager
```

**Verify** — bound to loopback, alive, and talking to fail2ban:

```bash
cd /opt/fail2ban-dashboard

ss -tlnp | grep 3001                 # MUST show 127.0.0.1:3001, NOT 0.0.0.0

curl -s http://127.0.0.1:3001/api/health; echo
# → {"status":"ok","role":"agent","time":"..."}

curl -s -H "X-API-Key: $(grep '^API_SECRET' backend/.env | cut -d= -f2)" \
     http://127.0.0.1:3001/api/status; echo
# → {"ok":true,"raw":"Server replied: pong"}   ← proves the fail2ban link works
```

If `/api/status` returns `{"ok":false,…}`, the sudo rule from A5 isn't working —
re-check `sudo -n fail2ban-client ping` and restart the service.

Requesting `http://127.0.0.1:3001/` returns `{"error":"Not found"}`. That is
correct: **agents have no UI.**

## A7 — Removing an agent (rollback)

Worth knowing before you install on production. Nothing here touches fail2ban
itself — the server goes back to exactly how it was:

```bash
sudo systemctl disable --now fail2ban-agent
sudo rm /etc/systemd/system/fail2ban-agent.service
sudo systemctl daemon-reload

sudo rm -f /etc/sudoers.d/fail2ban-dashboard      # revoke the sudo rule
sudo gpasswd -d $USER adm                         # revoke log access (optional)
sudo rm -rf /opt/fail2ban-dashboard               # remove the code

# Verify nothing is left listening
ss -tlnp | grep 3001                              # expect no output
```

Then remove that server's entry from `hub/servers.json` on the hub, re-run
`sudo bash hub/install-tunnels.sh` (it retires the orphaned tunnel), and restart
the hub.

To pause monitoring without uninstalling, just
`sudo systemctl stop fail2ban-agent` — the server shows as offline in the fleet
view and everything else keeps working.

---

# Part B — Set up the hub

The hub is the dashboard. It can run in either of two places, and the code is
identical — only who opens the SSH tunnels differs:

| | **Workstation** (`setup.sh hub --local`) | **Shared server** (`setup.sh hub`) |
|---|---|---|
| Runs on | your laptop/desktop | a management server |
| Tunnels | the hub process opens and supervises them | systemd units from `install-tunnels.sh` |
| Needs root | no | yes, once, to install the units |
| You reach it at | `http://localhost:3100` directly | `ssh -L 3100:…` then `http://localhost:3100` |
| Each viewer needs | their own clone + SSH keys + the agent keys | just SSH access to the hub host |
| Agent keys live | on every viewer's machine | on one hardened box |
| Best when | one or two admins, or you want it on your own machine | a team, or you want the keys in one place |

Pick one and follow **B-local** or **B-server** below. They can coexist — a
shared hub on a server and your own local hub against the same fleet is fine;
agents don't care how many hubs query them.

---

## B-local — Run the hub on your own machine

Nothing is installed as a service and nothing is left running when you quit.

**1. Clone and set up** (on your laptop, not a server):

```bash
git clone https://github.com/virgotex/fail2ban-dashboard.git
cd fail2ban-dashboard
bash setup.sh hub --local
```

That generates your own `HUB_API_SECRET`, builds the UI, and sets
`HUB_MANAGE_TUNNELS=true` so the hub handles its own tunnels.

**2. Confirm passwordless SSH to each server** — this is what the tunnels use:

```bash
ssh -o BatchMode=yes deploy@your-server true && echo "key auth OK"
# if it fails:  ssh-copy-id deploy@your-server
```

**3. Register your servers** in `hub/servers.json` — same fields as B2 below.
`baseUrl` ports are local to *your* machine, so pick anything free (4101, 4102, …):

```json
[
  { "id": "test-01", "name": "Test 01", "baseUrl": "http://127.0.0.1:4101",
    "apiKey": "<that agent's API_SECRET>", "ssh": "deploy@test-01" }
]
```

**4. Start it:**

```bash
cd hub && npm start
```

You'll see a tunnel line per server, then the dashboard is at
**http://localhost:3100** — no `ssh -L` needed, the hub is already local.

```
[tunnel] managing 2 tunnel(s) with ssh
[tunnel] test-01 up — 127.0.0.1:4101 → deploy@test-01:127.0.0.1:3001
```

Tunnels reconnect on their own with exponential backoff (a server down for an
hour doesn't mean a reconnect storm), and Ctrl-C closes every one of them.
Because the hub owns the tunnels, the fleet view can tell you *which half* is
broken — a row reads **"tunnel down"** or **"agent down"**, not just
"unreachable".

**Sharing this with someone else:** they repeat steps 1–4 on their own machine
with their own SSH keys and their own copy of `servers.json`. Nothing needs
deploying for a new viewer. Read
[`docs/SECURITY.md`](docs/SECURITY.md) §2 first — it means the agent keys exist
on another laptop.

**Notes:**
- Works on macOS as well as Linux (needs `ssh` on `PATH`; `install-tunnels.sh`
  is Linux/systemd-only, but workstation mode doesn't use it).
- Install `autossh` and set `HUB_SSH_BIN=autossh` in `hub/.env` for faster
  reconnects on flaky links.
- Laptop sleep/wake: tunnels die and re-establish within a minute.
- Keep `hub/servers.json` to yourself: `chmod 600 hub/servers.json`.

---

## B-server — Run the hub on a management server

Run this on the host that will serve the dashboard. It needs SSH access to
every agent.

## B1 — Install

Node 18+ and git as in A3, then:

```bash
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard

bash setup.sh hub
```

`setup.sh hub` generates `HUB_API_SECRET`, points `frontend/.env.local` at it,
installs the hub + build tooling, and builds the SPA the hub serves.

> The key baked into the bundle is the **hub's** key — never an agent's. Anyone
> who can load the page holds it, which is why the hub stays on `127.0.0.1` and
> you reach it over SSH.

## B2 — Register your servers

Edit `hub/servers.json` — one entry per agent:

```json
[
  { "id": "web-01", "name": "Web 01", "baseUrl": "http://127.0.0.1:4101",
    "apiKey": "<web-01's API_SECRET>", "ssh": "deploy@web-01.example.com" },
  { "id": "web-02", "name": "Web 02", "baseUrl": "http://127.0.0.1:4102",
    "apiKey": "<web-02's API_SECRET>", "ssh": "deploy@web-02.example.com" }
]
```

| Field | Meaning |
|---|---|
| `id` | Stable slug, used in URLs and unit names. `[a-zA-Z0-9_-]` |
| `name` | Display name in the UI |
| `baseUrl` | The **local** tunnel port on this hub host — one per agent (4101, 4102, …) |
| `apiKey` | That agent's `API_SECRET` from A4 |
| `ssh` | SSH target for the tunnel (honours `~/.ssh/config`) |

> `servers.json` holds every agent's secret. It's **gitignored — never commit it.**
> `chmod 600 hub/servers.json` is worth doing.

## B3 — Bring up the tunnels

Each agent listens on `127.0.0.1:3001` on its own host; a tunnel maps it to a
distinct local port here. These are systemd units, not backgrounded `ssh`,
because a tunnel that dies silently looks exactly like a down server:

```bash
sudo TUNNEL_USER=$USER bash hub/install-tunnels.sh
```

It reads `servers.json`, writes one `fail2ban-tunnel@<id>` unit per agent
(using `autossh` if installed, plain `ssh` otherwise), starts them, and warns
about any agent that `$TUNNEL_USER` can't SSH into without a password.

```bash
sudo bash hub/install-tunnels.sh --status   # per-tunnel state
ss -tlnp | grep -E '410[0-9]'               # local ports listening
```

The tunnels restart on failure and come back after a reboot. To retire a
server, drop it from `servers.json` and re-run the installer — it disables the
orphaned unit for you.

## B4 — Run the hub as a service

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
ss -tlnp | grep 3100                 # MUST show 127.0.0.1:3100

# Verify the fan-out — every server should be online with jail counts:
cd /opt/fail2ban-dashboard/hub
curl -s -H "X-API-Key: $(grep '^HUB_API_SECRET' .env | cut -d= -f2)" \
     http://127.0.0.1:3100/api/overview; echo
```

Each server in that response carries two flags worth knowing apart:

- `reachable:false` — the **tunnel** is down, or the agent isn't running.
- `reachable:true, online:false` — the tunnel is fine, but that server's
  fail2ban isn't answering (usually the A5 sudo rule).

A `403` from an agent means its `apiKey` in `servers.json` doesn't match its
`backend/.env`.

## B5 — Open the dashboard

From your **laptop** — this is the only tunnel you open by hand:

```bash
ssh -L 3100:127.0.0.1:3100 youruser@HUB_HOST_IP
```

Browse to **http://localhost:3100**. You land on the **Fleet overview**; pick a
server from the sidebar dropdown (or click its row) to drill into that server's
Dashboard, Logs, Reports, Banned IPs and Settings. Bans and unbans apply to the
selected server.

> If local port 3100 is taken, map another: `ssh -L 8080:127.0.0.1:3100 …` →
> `http://localhost:8080`.

---

## Adding a live server later

This is the routine you'll repeat for the rest of your fleet. About five
minutes per server.

**On the new server** — Part A, skipping A1 and A2 (see *Quick path for an
already-configured live server*):

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -   # only if node < 18
sudo apt install -y nodejs git
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard && bash setup.sh agent          # ← copy the API_SECRET
echo "$USER ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" | sudo tee /etc/sudoers.d/fail2ban-dashboard
sudo chmod 440 /etc/sudoers.d/fail2ban-dashboard && sudo visudo -c
sudo usermod -aG adm $USER                                  # reconnect SSH after this
# …then the A6 systemd unit, and:
curl -s http://127.0.0.1:3001/api/health                    # → role":"agent"
```

**On the hub** — make sure the hub user can reach it, then register it:

```bash
ssh -o BatchMode=yes deploy@new-server true && echo "key auth OK"   # else: ssh-copy-id
nano hub/servers.json          # add the entry with the next free local port (4104, 4105, …)
sudo TUNNEL_USER=$USER bash hub/install-tunnels.sh
sudo systemctl restart fail2ban-hub                                  # registry is read at startup
sudo bash hub/install-tunnels.sh --status
```

It appears in the fleet overview on the next poll. If it shows offline, work
outward: tunnel (`--status`) → agent (`journalctl -u fail2ban-agent` on that
host) → `apiKey` mismatch.

To remove one again, see [A7](#a7--removing-an-agent-rollback).

---

## Secrets and hosting

The repo is safe to publish; your configuration is not. That split is
deliberate, so hosting needs nothing special — just don't defeat it.

**Never committed** (all gitignored): `hub/servers.json` (every agent's key *and*
your real hostnames), `hub/.env`, `backend/.env`, `frontend/.env.local`, and
`frontend/dist/` (the bundle carries `HUB_API_SECRET`). Committed instead:
`servers.example.json` and the `.env.example` files, with placeholders.

**Enable the pre-commit hook once per clone** — `.gitignore` can't stop
`git add -f`, a rename, or a key pasted into a doc:

```bash
git config core.hooksPath .githooks      # setup.sh does this for you
```

It refuses any commit that stages a `servers.json` / `.env`, private key
material, `frontend/dist/*`, or a diff containing a 32+ character hex string.

**Check before pushing:**

```bash
git ls-files | grep -Ei 'servers\.json|\.env$|\.env\.local'    # expect nothing
git grep -nE '[0-9a-f]{32,}' -- . ':!*package-lock.json'       # expect nothing
```

**If a key does reach a remote,** rotate it rather than rewriting history —
history lives on in clones and forks. Generate a new value, update that agent's
`backend/.env` and the hub's `servers.json`, restart both. Because agents are
loopback-only, the leaked key was only usable by someone who could already SSH to
that host; rotating and reviewing that host's `auth.log` is the proportionate
response. Full procedure: [`docs/SECURITY.md`](docs/SECURITY.md) §2.

**Deploying from a private repo:** each server's `git clone` needs credentials.
A read-only deploy key per server is tidiest; a fine-grained PAT also works.
Nothing in the dashboard depends on the repo being reachable after install.

---

## Load on the monitored servers

The hub polls, so a fleet is a steady trickle of requests rather than a spike.
Three settings bound it, and the defaults are already conservative:

| Setting | Where | Default | Effect |
|---|---|---|---|
| `AGENT_CACHE_TTL_MS` | agent `.env` | `5000` | Reuse window for `fail2ban-client` reads. Concurrent reads coalesce into one. |
| `LOG_CACHE_TTL_MS` | agent `.env` | `10000` | Same, for log parsing (logs, reports, IP investigation). |
| `HUB_OVERVIEW_TTL_MS` | hub `.env` | `10000` | The fleet overview is computed once per window and shared by every viewer. |
| `HUB_FANOUT_CONCURRENCY` | hub `.env` | `4` | How many agents are queried at once, so a big fleet isn't woken all at the same instant. |

Consequences worth knowing:

- **Extra operators are free.** Ten people with the dashboard open cost the same
  as one — the hub shares its cached overview.
- **A background tab costs nothing.** The UI stops polling when it isn't visible
  and refreshes the moment you come back.
- **Worst case per agent** is roughly one `status` + one `jails` call per
  `AGENT_CACHE_TTL_MS`, no matter what the front end does.

Raise the TTLs if you'd rather have a lighter touch than fresher numbers.

---

## Operations

```bash
# On the hub — includes the fan-out and any agent errors
journalctl -u fail2ban-hub -f

# On an agent — includes [AUDIT] lines for every ban/unban
journalctl -u fail2ban-agent -f

# Tunnel trouble on the hub
sudo bash /opt/fail2ban-dashboard/hub/install-tunnels.sh --status
journalctl -u fail2ban-tunnel@web-01 -n 30
sudo systemctl restart fail2ban-tunnel@web-01

# Rebuild the UI after editing frontend/ (e.g. JAIL_META) — HUB ONLY
cd /opt/fail2ban-dashboard/frontend && npm run build
sudo systemctl restart fail2ban-hub

# Pull code updates — hub
cd /opt/fail2ban-dashboard && git pull && (cd frontend && npm run build)
sudo systemctl restart fail2ban-hub

# Pull code updates — agent
cd /opt/fail2ban-dashboard && git pull && (cd backend && npm install --omit=dev)
sudo systemctl restart fail2ban-agent
```

### Gotchas

- **Log reads need a reconnect.** After `usermod -aG adm`, the group only applies
  to new sessions — reconnect SSH and restart the agent before the log viewer and
  IP investigation work.
- **`servers.json` is read at startup.** Restart the hub after editing it.
- **Reload fail2ban after config changes:** `sudo fail2ban-client reload`. The
  dashboard reflects it within one poll plus one cache window.
- **Verify bind addresses.** `ss -tlnp | grep 3001` on an agent and `grep 3100`
  on the hub must both show `127.0.0.1`, never `0.0.0.0`.
- **Don't build the frontend on an agent.** If `frontend/dist` exists there it is
  simply ignored — the agent never serves it — but it's wasted disk and build
  time on a production box.
- **`npm not found` during `setup.sh`.** Your Node came without npm — install
  from NodeSource (A3).

See [`hub/README.md`](hub/README.md) for the hub's API reference and
[`docs/SECURITY.md`](docs/SECURITY.md) for the security model.
