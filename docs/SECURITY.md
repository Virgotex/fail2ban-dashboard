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
    # In production the backend serves the built SPA *and* the API on :3001.
    # Proxy to the backend — NOT the Vite dev server (:5173), which only runs
    # during development.
    reverse_proxy localhost:3001
    tls internal
}
```

Then access via `https://fail2ban.local` (add to `/etc/hosts` if needed).

> If you set `TRUST_PROXY=1` (or the proxy's IP) in `backend/.env` so rate
> limiting and audit logs see the real client IP, Caddy is a non-loopback
> proxy from the backend's point of view.

## 3. Enable OIDC authentication (built-in)

`express-openid-connect` is already wired in — flip `OIDC_ENABLED=true` and
fill in the matching env vars. The backend then:

- Forces every API route through a session login (any IdP that speaks OIDC).
- If `OIDC_REQUIRED_GROUP` is set, restricts ban/unban to users with that
  claim. Reads stay available to any authenticated user.
- Emits an `[AUDIT]` JSON line on every write, attributed to the OIDC `sub`.
- Hands the WebSocket a short-lived single-use ticket instead of the API
  secret, so the secret never leaves the server in OIDC mode.

### Minimum env vars

```env
OIDC_ENABLED=true
OIDC_ISSUER_BASE_URL=https://idp.example.com/realms/company
OIDC_CLIENT_ID=fail2ban-dashboard
OIDC_CLIENT_SECRET=...
OIDC_BASE_URL=https://fail2ban.example.com    # public URL of THIS app
OIDC_SECRET=$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')
OIDC_REQUIRED_GROUP=fail2ban-admins           # optional
OIDC_GROUPS_CLAIM=groups                      # default; override per IdP
```

### IdP configuration cheatsheet

| Provider | Redirect URI to register | Groups claim |
|---|---|---|
| Keycloak | `${OIDC_BASE_URL}/callback` | `groups` (after adding a Group Membership mapper to the client scope) |
| Okta | `${OIDC_BASE_URL}/callback` | `groups` (assign via "Groups claim" in the app settings) |
| Auth0 | `${OIDC_BASE_URL}/callback` | A namespaced claim, e.g. `https://example.com/groups` — set `OIDC_GROUPS_CLAIM` to match |
| Azure AD | `${OIDC_BASE_URL}/callback` | `roles` — set `OIDC_GROUPS_CLAIM=roles` |
| Authentik | `${OIDC_BASE_URL}/callback` | `groups` (default group mapper) |

### Logout post-redirect

The default post-logout redirect lands users back at `/`. To send them to the
IdP's logout page instead, set `auth0Logout: true` in `server.js` and use
`endSessionEndpoint` per provider docs.

### Sanity check after setup

```bash
# Visit https://fail2ban.example.com — expect a redirect to the IdP.
# After login the sidebar bottom-left should show your name + a logout icon.
# Ban/unban a test IP and confirm an [AUDIT] line appears in journald with
# user=<your-sub>.
journalctl -u fail2ban-dashboard -e | grep AUDIT
```

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
