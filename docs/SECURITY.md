# Security Hardening Guide

The security model in one line: **nothing listens on a public interface, and the
browser only ever holds the hub's key.**

```
browser ──[HUB_API_SECRET]──▶ hub ──[each agent's own API_SECRET]──▶ agents
          over an SSH tunnel        over SSH tunnels, loopback-bound
```

Three properties fall out of that, and this document is about keeping them true:

1. **Agents are not web-facing.** They serve JSON, bind to `127.0.0.1`, and have
   no UI, no session and no WebSocket. The hub is their only client.
2. **Agent keys never reach a browser.** They live in `hub/servers.json`,
   server-side. A compromised browser session gets the hub's key, not the fleet's.
3. **Reachability is the outer wall.** Everything is loopback + SSH, so an
   attacker needs SSH access before any of the above is even tested.

---

## 1. Verify the bind addresses

This is the keystone. Check it after every deployment and upgrade:

```bash
# On each agent
ss -tlnp | grep 3001      # MUST be 127.0.0.1:3001 — never 0.0.0.0

# On the hub
ss -tlnp | grep 3100      # MUST be 127.0.0.1:3100 — never 0.0.0.0
```

If either shows `0.0.0.0`, fix `BIND_ADDRESS` / `HUB_BIND_ADDRESS` and restart.
Host firewalls should allow only SSH inbound (see `DEPLOY.md` A1).

## 2. Key hygiene

| Key | Lives in | Who sees it |
|---|---|---|
| `API_SECRET` (per agent) | that agent's `backend/.env` + the hub's `servers.json` | the hub only |
| `HUB_API_SECRET` | `hub/.env` + the built JS bundle | anyone who can load the dashboard |

- **Give every agent a distinct key.** `setup.sh agent` generates one per server.
  A shared key means one compromised agent's key opens the whole fleet.
- **`hub/servers.json` is the crown jewels** — it holds every agent's secret.
  It's gitignored; also `chmod 600` it and keep it off backups you don't control.

### Where the hub runs changes the blast radius

Running the hub on your own machine is convenient and needs no shared
infrastructure. It also copies `servers.json` — every agent's key — onto every
viewer's laptop. Be deliberate about which you want:

| | Hub on a workstation | Hub on a shared server |
|---|---|---|
| Agent keys stored on | every viewer's machine | one hardened box |
| A stolen laptop exposes | the whole fleet's agent keys | nothing (viewer only had SSH) |
| Revoking one person | rotate **every** agent key | remove their SSH access to the hub |
| Each viewer needs | SSH access to every server | SSH access to the hub only |
| Audit of who looked | none | the hub host's SSH/auth logs |

Practical middle ground, in rough order of effort:

1. **Keep the fleet's keys off laptops** — run the shared hub, give people SSH
   access to it, and let them `ssh -L 3100`. One place to protect and revoke.
2. **If people do run local hubs, give each their own SSH key** on every agent,
   restricted to port-forwarding (see §3). Then revoking a person is deleting
   their `authorized_keys` line everywhere — their copy of the agent API keys
   becomes useless without a way to reach the loopback port.
3. **Use full-disk encryption** on any machine holding `servers.json`, and
   rotate agent keys when someone leaves with a copy.

Point 2 is the important one: because agents are loopback-only, an agent API key
is worthless without SSH access to that host. **SSH access is the real
credential** — which means your existing SSH key management is what actually
gates the fleet, and it's the lever to pull when someone leaves.
- **Treat `HUB_API_SECRET` as a gate, not authentication.** It ships inside the
  React bundle, so anyone who can load the page holds it. It stops non-browser
  callers; it does not identify users. See §4.

### Rotating a key

Agent:
```bash
# On the agent
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
nano backend/.env                       # set API_SECRET
sudo systemctl restart fail2ban-agent
# On the hub: paste the same value into servers.json, then
sudo systemctl restart fail2ban-hub
```

Hub (invalidates every open dashboard, which is the point):
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
nano hub/.env                           # set HUB_API_SECRET
echo "VITE_API_KEY=$(grep '^HUB_API_SECRET' hub/.env | cut -d= -f2)" > frontend/.env.local
(cd frontend && npm run build)          # the key is baked into the bundle
sudo systemctl restart fail2ban-hub
```

## 3. Tunnels are part of the security boundary

The agents' loopback binding is only meaningful because the hub reaches them
over SSH. That means:

- The tunnel user should be an ordinary account with a key, not root.
  `install-tunnels.sh` runs the units as `TUNNEL_USER`, not as root; in
  workstation mode (`HUB_MANAGE_TUNNELS=true`) the tunnels run as whoever
  started the hub.
- Prefer a **dedicated key per hub**, and restrict it on each agent. Since the
  hub only needs port forwarding, lock the key down in the agent's
  `~/.ssh/authorized_keys`:

  ```
  restrict,port-forwarding,permitopen="127.0.0.1:3001" ssh-ed25519 AAAA… hub@management
  ```

  That key can then forward to the agent's dashboard port and do nothing else —
  no shell, no other forwards.
- Never point a `baseUrl` at a non-loopback host over plain `http`: the agent's
  key would cross the network in clear. The hub warns loudly at startup if you
  do. Use a tunnel, or `https`.

## 4. Multi-user access — put an authenticating proxy in front of the hub

Earlier versions embedded OIDC in the per-server backend. That's gone: agents no
longer serve a UI or hold sessions, so user authentication belongs in exactly
one place — in front of the hub.

If more than one person needs the dashboard without sharing an SSH tunnel, run a
reverse proxy on the hub host that authenticates users and forwards to
`127.0.0.1:3100`. Keep the hub bound to loopback so the proxy is the only way in.

`/etc/caddy/Caddyfile` with Caddy's `forward_auth` to an identity proxy
(oauth2-proxy, Authelia, Pomerium, …):

```
fail2ban.example.com {
    tls internal      # or a real cert

    forward_auth localhost:4180 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-User X-Auth-Request-Email
    }

    reverse_proxy localhost:3100
}
```

Then in `hub/.env` set `TRUST_PROXY=1` so rate limiting sees the real client IP
rather than the proxy's.

Two caveats to be honest about:

- Anyone who gets past the proxy can ban and unban on **every** server in the
  registry. There is no per-user, per-server or read-only authorisation in the
  hub — the proxy is all-or-nothing.
- The bundle still carries `HUB_API_SECRET`, so the proxy is what actually keeps
  strangers out. Don't expose the hub port itself.

## 5. Least-privilege for fail2ban-client

Each agent only needs `fail2ban-client status`, `status <jail>`,
`set <jail> banip <ip>` and `set <jail> unbanip <ip>`.

The scoped form:

```sudoers
Cmnd_Alias FAIL2BAN_CMDS = /usr/bin/fail2ban-client status, \
                            /usr/bin/fail2ban-client status *, \
                            /usr/bin/fail2ban-client set * banip *, \
                            /usr/bin/fail2ban-client set * unbanip *
youruser ALL=(root) NOPASSWD: FAIL2BAN_CMDS
```

> ⚠️ **Modern sudo (Ubuntu 22.04+ / sudo ≥ 1.9.10) rejects wildcards that aren't
> at the end of a command**, so the `set * banip *` lines fail `visudo -c` with
> `wildcards are not allowed in command arguments`. Use the binary-scoped rule
> instead — it always validates:
>
> ```sudoers
> youruser ALL=(root) NOPASSWD: /usr/bin/fail2ban-client
> ```
>
> This permits any `fail2ban-client` subcommand as root. The agent still
> validates every IP and jail name and builds fixed argument arrays, so no
> untrusted input reaches the command.

## 6. Log access

Each agent needs to read the fail2ban log (and, for IP investigation, the auth
logs):

```bash
sudo chmod 640 /var/log/fail2ban.log
sudo chown root:adm /var/log/fail2ban.log
sudo usermod -aG adm $USER
# log out and back in, then restart the agent
```

## 7. Audit trail

Every ban and unban is executed by the agent that owns the server, and that
agent logs it:

```bash
journalctl -u fail2ban-agent -e | grep AUDIT
# [AUDIT] {"ts":"…","user":"hub","action":"ban","ip":"127.0.0.1","jail":"sshd","target":"203.0.113.5"}
```

`user` is `hub` because the hub's request is what reached the agent — the agent
cannot see which human clicked. If you need per-person attribution, capture it
at the authenticating proxy in §4 and correlate by timestamp.

## 8. What isn't protected

Stated plainly, so it isn't a surprise:

- **No stored history.** The hub queries live. An offline server shows as
  offline; there's no record of what it looked like before.
- **No per-user authorisation.** Dashboard access is fleet-wide ban/unban access.
- **No rate limit across the fleet.** Limits are per agent and per hub, not
  per operator.
- **`hub/servers.json` compromise = fleet compromise.** Protect it accordingly.
