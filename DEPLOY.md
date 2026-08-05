# Deployment Guide — Tunnel-Only Server Setup

This guide deploys the Fail2Ban Dashboard on a fresh **Ubuntu/Debian** server that
you reach over **SSH only**. The backend stays bound to `127.0.0.1`, serves the
built SPA + API on a single port (`3001`), and runs as a `systemd` service. You
reach it by forwarding that port over SSH — nothing is ever exposed to the
network.

This is the exact procedure used to stand up a working test server; every command
below has been run and verified.

If you instead need LAN or public access, don't follow this guide — you'll need a
reverse proxy, TLS, and OIDC. See [`docs/SECURITY.md`](docs/SECURITY.md).

**Assumptions:** fresh Ubuntu/Debian, your login user has `sudo`, and you already
have SSH access to the server.

---

## Step 0 — ⚠️ Confirm key-based SSH before hardening

Part 1 disables password login. If key auth isn't working first, you can lock
yourself out. From your **local machine**:

```bash
ls ~/.ssh/*.pub                    # do you already have a key? if not:
ssh-keygen -t ed25519              # press Enter through the prompts
ssh-copy-id youruser@SERVER_IP     # installs your key (asks for password once)
ssh youruser@SERVER_IP             # MUST now log in WITHOUT a password prompt
```

Keep that session open during hardening and confirm a second fresh login works
before closing anything.

---

## Part 1 — Clean & harden the server

Run on the **server**.

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

# Firewall: allow only SSH inbound (the dashboard is tunneled, never exposed)
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status verbose
```

---

## Part 2 — Install fail2ban and your jails

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

The dashboard reads whatever `fail2ban-client` reports, so any custom jails show
up automatically with no code change. To give a jail a severity badge/intent
label in the UI, add it to the `JAIL_META` map at the top of
`frontend/src/App.jsx` and rebuild (Part 4).

After changing jail config later: `sudo fail2ban-client reload`.

---

## Part 3 — Install Node.js 18+ (with npm)

Install from **NodeSource** — the distro's base `nodejs` package can ship
*without* `npm`, which makes `setup.sh` fail with `✗ npm not found`. NodeSource
bundles both:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git
node -v && npm -v                    # expect v20.x (or newer) and npm 10.x
```

If `npm -v` still errors, a conflicting Node install is on `PATH` — remove it
(`sudo apt remove -y nodejs && sudo apt autoremove -y`) and re-run the two
commands above.

---

## Part 4 — Deploy the dashboard

```bash
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard

bash setup.sh                        # installs deps + generates the API secret
```

> **Ignore** the "Terminal 1 / Terminal 2 / port 5173" instructions `setup.sh`
> prints at the end — that's the *development* workflow. This guide runs a single
> production process on port 3001 instead.

`setup.sh` writes the **same** generated secret into both `backend/.env`
(`API_SECRET`) and `frontend/.env.local` (`VITE_API_KEY`), so they already match —
you don't need to touch them.

**Set the backend to production mode** — edit `backend/.env`:

```bash
nano backend/.env
```
Change `NODE_ENV=development` to:
```env
NODE_ENV=production
```
Leave `BIND_ADDRESS=127.0.0.1`, `PORT=3001`, and the generated `API_SECRET` as
they are. Save (`Ctrl+O`, `Enter`, `Ctrl+X`).

- `BIND_ADDRESS=127.0.0.1` → listens on loopback only, unreachable except through
  your SSH tunnel. **This is the security keystone of the whole setup.**

**Build the SPA** so the backend serves the UI + API from one port:

```bash
cd frontend && npm run build && cd ..
```

Once `frontend/dist/index.html` exists, the backend serves the SPA — one process,
one port, one auth boundary. (A "chunks larger than 500 kB" warning is expected
and harmless.)

> **Auth note:** `VITE_API_KEY` is baked into the built JS bundle, so anyone who
> can load the page holds the key. In tunnel-only mode this is fine — only users
> with SSH access can reach port 3001. For LAN/public access, switch to OIDC (see
> `docs/SECURITY.md`).

---

## Part 5 — Give the app access to fail2ban and logs

The backend runs `fail2ban-client` via `sudo`, so it needs a passwordless sudo
rule. It also needs to read the fail2ban/auth logs.

```bash
# Passwordless sudo for fail2ban-client
echo "$USER ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" | \
  sudo tee /etc/sudoers.d/fail2ban-dashboard
sudo chmod 440 /etc/sudoers.d/fail2ban-dashboard
sudo visudo -c                       # must report "parsed OK"

# Read access to fail2ban + auth logs (for the IP investigation feature)
sudo usermod -aG adm $USER           # reconnect SSH afterward for this to apply
```

Confirm the rule works with **no password prompt** — this is exactly what the
service does at runtime:

```bash
sudo -n fail2ban-client ping         # expect: Server replied: pong
```

> **Why the whole binary, not scoped verbs?** Older docs used a `Cmnd_Alias` with
> per-verb wildcards like `set * banip *`. Modern sudo on Ubuntu rejects wildcards
> that aren't at the end of a command (`wildcards are not allowed in command
> arguments`), so that rule fails `visudo -c`. The binary-scoped rule above always
> validates. It lets `fail2ban-client` run as root with any arguments; on a
> single-user box that's an acceptable trade-off, and the app still validates
> every IP/jail and builds fixed argument arrays.

---

## Part 6 — Run as a systemd service

```bash
sudo tee /etc/systemd/system/fail2ban-dashboard.service >/dev/null <<EOF
[Unit]
Description=Fail2Ban Dashboard
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
sudo systemctl enable --now fail2ban-dashboard
systemctl status fail2ban-dashboard --no-pager
```

**Verify** the server is up, bound to loopback, and talking to fail2ban:

```bash
cd /opt/fail2ban-dashboard

ss -tlnp | grep 3001                 # MUST show 127.0.0.1:3001, NOT 0.0.0.0

curl -s http://127.0.0.1:3001/api/health; echo
# → {"status":"ok","time":"..."}

curl -s -H "X-API-Key: $(grep '^API_SECRET' backend/.env | cut -d= -f2)" \
     http://127.0.0.1:3001/api/status; echo
# → {"ok":true,"raw":"Server replied: pong"}   ← proves the fail2ban link works
```

If `/api/status` returns `{"ok":false,...}`, the sudo rule from Part 5 isn't
working — re-check `sudo -n fail2ban-client ping` and restart the service.

---

## Part 7 — Access the dashboard from your laptop

From your **local machine**, open an SSH tunnel that forwards local port 3001 to
the server's loopback:

```bash
ssh -L 3001:127.0.0.1:3001 youruser@SERVER_IP
```

Leave that session open, then browse to **http://localhost:3001**.

You should see the dashboard load, with a green **"Daemon running"** dot and
**"ws connected"** in the bottom-left sidebar, and your jails listed on the
Dashboard page.

> If local port 3001 is already in use, map a different one:
> `ssh -L 8080:127.0.0.1:3001 youruser@SERVER_IP` → browse to `http://localhost:8080`.

---

## Managing multiple servers

Each dashboard install ("agent") talks only to the fail2ban on its *own* machine.
To monitor several servers you have **two options** — pick one:

- **A. One tab per server (no extra service).** Deploy an agent on each server,
  then open a separate SSH tunnel per server on a different local port.
- **B. One combined dashboard (the hub).** Deploy an agent on each server, then
  run the **hub** — a small aggregator that fans out to every agent and gives you
  a fleet overview plus a server picker, with the same per-server views. This is
  the "single pane of glass".

### Option A — one tab per server

Deploy the dashboard on each server (repeat Parts 1–6 per host), then tunnel to
each on a **different local port**:

```bash
# Server A → laptop port 3001
ssh -L 3001:127.0.0.1:3001 youruser@SERVER_A_IP     # http://localhost:3001

# Server B → laptop port 3002  (change the LEFT number per server)
ssh -L 3002:127.0.0.1:3001 youruser@SERVER_B_IP     # http://localhost:3002

# Server C → laptop port 3003
ssh -L 3003:127.0.0.1:3001 youruser@SERVER_C_IP     # http://localhost:3003
```

The number on the **right** is always `3001` (the port the backend listens on
*inside* each server). Only the number on the **left** — your laptop's local
port — changes, so each tab maps to a distinct server.

### Option B — one combined dashboard (the hub)

The hub reaches each agent over an SSH tunnel and authenticates with that agent's
own key (kept server-side, never sent to the browser). You then tunnel to the hub
and see everything in one place. It's a *live* aggregator (no stored history),
comfortable up to a few dozen servers. Full reference: **[`hub/README.md`](hub/README.md)**.

Run these on the **hub host** — any box that can SSH to every agent (a dedicated
management box, or one of the servers).

**1. Deploy an agent on every server** you want to monitor — Parts 1–6 above, on
each host. Note each agent's `API_SECRET` (from its `backend/.env`).

**2. Install the hub:**
```bash
cd /opt/fail2ban-dashboard/hub
npm install
cp .env.example .env
# Generate the hub's own key and put it in .env as HUB_API_SECRET:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
nano .env      # set HUB_API_SECRET, NODE_ENV=production, keep HUB_BIND_ADDRESS=127.0.0.1
```

**3. Open a tunnel to each agent** — edit the `AGENTS` list in `hub/tunnels.sh`
(one line per agent: `"<localPort> <ssh-target>"`), then:
```bash
bash tunnels.sh
ss -tlnp | grep -E '410[0-9]'      # confirm the local ports are listening
```
Each agent is now reachable at `http://127.0.0.1:<localPort>` on the hub host.
(For production, run these as `autossh` or per-tunnel systemd units so they
auto-reconnect.)

**4. Register the servers:**
```bash
cp servers.example.json servers.json
nano servers.json
```
For each agent set `id`, `name`, the tunnel `baseUrl`
(`http://127.0.0.1:<localPort>`), and that agent's `API_SECRET` as `apiKey`.
`servers.json` holds every agent's secret — it's **gitignored; never commit it**.

**5. Build the SPA with the hub's key** (the bundle's embedded key must be the
*hub* secret, not an agent's):
```bash
cd ../frontend
echo "VITE_API_KEY=$(grep '^HUB_API_SECRET' ../hub/.env | cut -d= -f2)" > .env.local
npm run build
cd ../hub
```

**6. Run the hub as a service:**
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
ss -tlnp | grep 3100               # MUST show 127.0.0.1:3100

# Verify the fan-out (every server should show online:true with jail counts):
curl -s -H "X-API-Key: $(grep '^HUB_API_SECRET' .env | cut -d= -f2)" \
     http://127.0.0.1:3100/api/overview; echo
```
An `online:false` server means its tunnel is down or its `apiKey` in
`servers.json` is wrong.

**7. Access the hub** from your laptop:
```bash
ssh -L 3100:127.0.0.1:3100 youruser@HUB_HOST_IP     # → http://localhost:3100
```
You land on the **Fleet overview**; pick a server (sidebar dropdown or click a
row) to drill into its per-server dashboard.

---

## Operations

```bash
# Watch app logs (includes [AUDIT] lines on every ban/unban)
journalctl -u fail2ban-dashboard -f

# Restart after a config or code change
sudo systemctl restart fail2ban-dashboard

# Rebuild the SPA after editing frontend/ (e.g. JAIL_META), then restart
cd /opt/fail2ban-dashboard/frontend && npm run build
sudo systemctl restart fail2ban-dashboard

# Pull code updates
cd /opt/fail2ban-dashboard && git pull && (cd frontend && npm run build)
sudo systemctl restart fail2ban-dashboard
```

### Gotchas

- **Log reads need a reconnect.** After `usermod -aG adm`, the group only applies
  to new sessions — reconnect SSH and restart the service before the log viewer
  and IP investigation work.
- **Reload fail2ban after config changes.** Run `sudo fail2ban-client reload`;
  the dashboard reflects it on its next 10-second poll.
- **Verify the bind address.** `ss -tlnp | grep 3001` must show `127.0.0.1`, never
  `0.0.0.0`. If it's `0.0.0.0`, check `BIND_ADDRESS` in `backend/.env` and restart.
- **`npm not found` during `setup.sh`.** Your Node came without npm — install from
  NodeSource (Part 3).
