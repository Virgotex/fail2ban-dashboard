# Deployment Guide — Tunnel-Only Server Setup

This guide deploys the Fail2Ban Dashboard on a fresh **Ubuntu/Debian** server that
you reach over **SSH only**. The backend stays bound to `127.0.0.1`, serves the
built SPA + API on a single port (`3001`), and you reach it by forwarding that
port over SSH. Nothing is ever exposed to the network.

If you instead need LAN or public access, don't follow this guide — you'll need a
reverse proxy, TLS, and OIDC. See [`docs/SECURITY.md`](docs/SECURITY.md).

**Assumptions:** fresh Ubuntu/Debian, your user has `sudo`, and you already have
SSH key access to the server.

---

## Step 0 — ⚠️ Confirm key-based SSH before hardening

Part 1 disables password login. If key auth isn't working first, you can lock
yourself out. From your **local machine**:

```bash
ssh-copy-id youruser@SERVER_IP     # if your key isn't installed yet
ssh youruser@SERVER_IP             # must log in WITHOUT prompting for a password
```

Keep this session open during hardening and verify a second fresh login works
before closing it.

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

## Part 3 — Install Node.js 18+

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git
node -v && npm -v
```

---

## Part 4 — Deploy the dashboard

```bash
sudo mkdir -p /opt/fail2ban-dashboard && sudo chown $USER:$USER /opt/fail2ban-dashboard
git clone https://github.com/virgotex/fail2ban-dashboard.git /opt/fail2ban-dashboard
cd /opt/fail2ban-dashboard

bash setup.sh                        # installs deps + generates API_SECRET
```

Edit `backend/.env` for production:

```env
NODE_ENV=production
BIND_ADDRESS=127.0.0.1
PORT=3001
```

Build the SPA so the backend serves UI + API on one port. The frontend key must
match the backend secret:

```bash
grep API_SECRET backend/.env | sed 's/API_SECRET=/VITE_API_KEY=/' > frontend/.env.local
cd frontend && npm run build && cd ..
```

Once `frontend/dist/index.html` exists, the backend serves the SPA — one process,
one port, one auth boundary.

> **Note on auth:** `VITE_API_KEY` is baked into the built JS bundle, so anyone
> who can load the page holds the key. In tunnel-only mode this is fine — only
> users with SSH access can reach port 3001. For LAN/public access, switch to
> OIDC (see `docs/SECURITY.md`).

---

## Part 5 — Least-privilege access

```bash
# Scoped sudo for fail2ban-client (so the app doesn't run as root)
sudo tee /etc/sudoers.d/fail2ban-dashboard >/dev/null <<EOF
Cmnd_Alias FAIL2BAN_CMDS = /usr/bin/fail2ban-client status, \
                           /usr/bin/fail2ban-client status *, \
                           /usr/bin/fail2ban-client ping, \
                           /usr/bin/fail2ban-client get *, \
                           /usr/bin/fail2ban-client set * banip *, \
                           /usr/bin/fail2ban-client set * unbanip *
$USER ALL=(root) NOPASSWD: FAIL2BAN_CMDS
EOF
sudo visudo -c                       # must report "parsed OK"

# Read access to fail2ban + auth logs (for the IP investigation feature)
sudo usermod -aG adm $USER           # reconnect SSH afterward for this to apply
```

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
ss -tlnp | grep 3001                 # MUST show 127.0.0.1:3001, NOT 0.0.0.0
```

---

## Part 7 — Access the dashboard

From your **local machine**, forward the port over SSH:

```bash
ssh -L 3001:127.0.0.1:3001 youruser@SERVER_IP
```

Leave that session open, then browse to **http://localhost:3001**.

---

## Operations

```bash
# Watch app logs (includes [AUDIT] lines on every ban/unban)
journalctl -u fail2ban-dashboard -f

# Restart after a config or code change
sudo systemctl restart fail2ban-dashboard

# Rebuild the SPA after editing frontend/ (e.g. JAIL_META)
cd /opt/fail2ban-dashboard/frontend && npm run build
```

### Gotchas

- **Log reads need a reconnect.** After `usermod -aG adm`, the group only applies
  to new sessions — reconnect SSH and restart the service before the log viewer
  and IP investigation work.
- **Reload fail2ban after config changes.** Run `sudo fail2ban-client reload`;
  the dashboard reflects it on its next 10-second poll.
- **Verify the bind address.** `ss -tlnp | grep 3001` must show `127.0.0.1`, never
  `0.0.0.0`. If it's `0.0.0.0`, check `BIND_ADDRESS` in `backend/.env`.
