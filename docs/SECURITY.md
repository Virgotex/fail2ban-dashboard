# Security Hardening Guide

This document covers production/LAN hardening steps beyond the defaults.

## 1. Never expose port 3001

The Express server is hardcoded to bind on `127.0.0.1:3001`. Verify:

```bash
ss -tlnp | grep 3001
# Should show: 127.0.0.1:3001 — NOT 0.0.0.0:3001
```

If you see `0.0.0.0`, check that `NODE_ENV` isn't overriding the bind address and restart.

## 2. HTTPS via reverse proxy (Caddy is easiest)

```bash
sudo apt install caddy
```

`/etc/caddy/Caddyfile`:
```
fail2ban.local {
    reverse_proxy localhost:5173
    tls internal
}
```

Then access via `https://fail2ban.local` (add to `/etc/hosts` if needed).

## 3. Add OIDC authentication

For any access beyond your own laptop, add an auth proxy like Authentik or use
the `express-openid-connect` package:

```bash
cd backend && npm install express-openid-connect
```

See: https://auth0.github.io/express-openid-connect/

## 4. Rotate the API secret periodically

```bash
# Generate a new secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Update both backend/.env (API_SECRET) and frontend/.env.local (VITE_API_KEY)
# Restart both services
```

## 5. Least-privilege for fail2ban-client

The backend only needs to run `fail2ban-client status`, `fail2ban-client status <jail>`,
`fail2ban-client set <jail> banip <ip>`, and `fail2ban-client set <jail> unbanip <ip>`.

Restrict sudo to exactly those commands:

```sudoers
Cmnd_Alias FAIL2BAN_CMDS = /usr/bin/fail2ban-client status, \
                            /usr/bin/fail2ban-client status *, \
                            /usr/bin/fail2ban-client set * banip *, \
                            /usr/bin/fail2ban-client set * unbanip *
youruser ALL=(root) NOPASSWD: FAIL2BAN_CMDS
```

## 6. Log access

Make sure your user can read the fail2ban log:

```bash
sudo chmod 640 /var/log/fail2ban.log
sudo chown root:adm /var/log/fail2ban.log
sudo usermod -aG adm $USER
# log out and back in
```
