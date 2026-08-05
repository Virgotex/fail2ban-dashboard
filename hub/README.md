# The Hub

The hub is the dashboard. It's the only service with a web UI, the only thing a
browser talks to, and the only place any fleet-wide state lives.

```
Your laptop ──SSH tunnel──▶ Hub (this)  127.0.0.1:3100
                              │  reads servers.json, fans out with bounded concurrency
                              ├──SSH tunnel──▶ Agent web-01  127.0.0.1:3001 ─▶ fail2ban
                              ├──SSH tunnel──▶ Agent web-02  127.0.0.1:3001 ─▶ fail2ban
                              └──SSH tunnel──▶ Agent db-01   127.0.0.1:3001 ─▶ fail2ban
```

Full deployment walkthrough: [`../DEPLOY.md`](../DEPLOY.md). This file is the
reference for how the hub behaves.

## How it works

- **Agents** are API-only processes on the monitored servers — no UI, no
  session, no WebSocket. Each stays bound to `127.0.0.1:3001` on its own host
  and keeps its own `API_SECRET`.
- **The hub** reaches each agent over an SSH tunnel to a distinct local port
  (`4101`, `4102`, …) and authenticates with that agent's key from
  `servers.json`. Agent keys **never** reach the browser.
- **The browser** talks only to the hub, authenticated with `HUB_API_SECRET`.
- One dead agent degrades to an "offline" row; it never breaks the fleet view.

> **Scope / limits.** This is a *live* aggregator: it queries agents on demand
> and stores no history. If a server is offline you see nothing for it until
> it's back, rather than stale numbers. Comfortable to a few dozen servers;
> beyond that, or if you need history that survives downtime, you'd want a
> push-to-central-store architecture (not built here).

## Files

| File | Purpose |
|---|---|
| `src/hub.js` | The service: registry, fan-out, allowlisted proxy, SPA serving |
| `src/mapLimit.js` | Bounded-concurrency helper used by the fan-out |
| `src/tunnels.js` | Supervises the hub's own SSH tunnels in workstation mode |
| `.env` | Hub config — port, `HUB_API_SECRET`, tunnels, cache/fan-out tuning |
| `servers.json` | The registry: one entry per agent, **holds agent secrets**, gitignored |
| `install-tunnels.sh` | Turns `servers.json` into systemd SSH tunnels (server mode) |

## The registry

```json
[
  { "id": "web-01", "name": "Web 01", "baseUrl": "http://127.0.0.1:4101",
    "apiKey": "<that agent's API_SECRET>", "ssh": "carlton@web-01" }
]
```

`ssh` is used only by `install-tunnels.sh`; the hub itself ignores it. The file
is read **at startup** — restart the hub after editing it.

At boot the hub refuses to start on a malformed registry (bad/duplicate `id`,
missing `baseUrl`, non-string `ssh`), and warns about entries with no `apiKey`
or a plain-`http` non-loopback `baseUrl` (which would put an agent's key on the
wire in clear).

## Tunnels

Two ways to get them, depending on where the hub runs.

### Managed by the hub (workstation mode)

Set `HUB_MANAGE_TUNNELS=true` in `.env` — `setup.sh hub --local` does this for
you. The hub then spawns one `ssh -N -L` child per server that has an `ssh`
field, probes the local port to confirm the forward is actually up, reconnects
with exponential backoff (2s doubling to 60s), and kills every child on exit.

No root, no systemd, no state on disk — the tunnels live and die with
`npm start`. This is what makes running the whole dashboard on a laptop
practical, and it also means the fleet view can distinguish **"tunnel down"**
from **"agent down"** (`tunnel` and `tunnelError` appear per server in
`/api/overview`).

```
[tunnel] managing 2 tunnel(s) with ssh
[tunnel] web-01 up — 127.0.0.1:4101 → carlton@web-01:127.0.0.1:3001
[tunnel] web-01 exited (code 255), reconnecting in 2s
```

Related settings: `AGENT_PORT` (far end, default 3001) and `HUB_SSH_BIN` (use
`autossh` for faster reconnects, or a full path on macOS).

### systemd units (server mode)

```bash
sudo TUNNEL_USER=$USER bash install-tunnels.sh     # install / refresh all
sudo bash install-tunnels.sh --status              # per-tunnel state
sudo bash install-tunnels.sh --remove              # tear it all down
```

One `fail2ban-tunnel@<id>` unit per agent — `autossh` when available, plain
`ssh` otherwise, `Restart=always` either way, enabled at boot so tunnels survive
a reboot. Re-running the installer after editing `servers.json` adds new tunnels
and disables ones whose server is gone. It also flags any agent the tunnel user
can't reach without a password. Linux only.

## API reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | none | Liveness |
| `GET /api/mode` | none | Identifies this as a hub, reports server count |
| `GET /api/servers` | key | `{id,name}` per server — never any secret |
| `GET /api/overview` | key | Per-server summary + fleet totals (cached, shared) |
| `* /api/servers/:id/<path>` | key | Allowlisted proxy to one agent |

Auth is `X-API-Key: $HUB_API_SECRET` (constant-time compare).

The proxy is a strict allowlist by method **and** path (`src/hub.js`,
`PROXY_ALLOW`): status, jails, one jail, logs, reports, config, security, IP
details/geo, plus `POST …/ban` and `DELETE …/ban/:ip`. Anything else — including
an agent endpoint that exists but isn't listed — returns `404`.

`/api/overview` per server:

| Field | Meaning |
|---|---|
| `reachable` | The tunnel is up and the agent answered |
| `online` | fail2ban itself replied on that server |
| `jailCount`, `currentlyBanned`, `totalBanned` | Rolled into fleet `totals` |
| `error` | Why it isn't online, when it isn't |

`reachable:false` is a tunnel or agent problem; `reachable:true, online:false`
is a fail2ban problem on that host (usually the sudoers rule).

## Load control

The hub is designed so that watching costs the fleet a bounded, shared amount
of work:

- `HUB_OVERVIEW_TTL_MS` (default `10000`) — the overview is computed once per
  window and shared by every viewer. Concurrent requests during a fan-out join
  the in-flight one instead of starting another.
- `HUB_FANOUT_CONCURRENCY` (default `4`) — agents queried at a time, so a large
  fleet isn't woken all at once.
- `AGENT_TIMEOUT_MS` (default `8000`) — one slow server can't stall the view.
- A ban or unban clears the cached overview, so counts update immediately
  instead of lagging a window.

Agents cache too (`AGENT_CACHE_TTL_MS`), so even a burst of drill-downs can't
turn into a `fail2ban-client` storm on a production box.

## Verify

```bash
curl -s http://127.0.0.1:3100/api/mode; echo
curl -s -H "X-API-Key: $(grep '^HUB_API_SECRET' .env | cut -d= -f2)" \
     http://127.0.0.1:3100/api/overview; echo
```

Every server should be `online:true` with jail counts. If one isn't, check its
tunnel (`--status`), then its agent (`journalctl -u fail2ban-agent` on that
host), then its `apiKey`.
