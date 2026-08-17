# 🛡 Fail2Ban Dashboard

A lightweight, security-hardened web dashboard for monitoring and managing
Fail2Ban across a **fleet of Linux servers** from one place. Inspired by the
[swissmakers/fail2ban-ui](https://github.com/swissmakers/fail2ban-ui) project.

**Stack:** React + Vite (UI) · Express.js (hub + agents)

## Architecture

Two roles. Your monitored servers run only the agent — nothing user-facing goes
on them. The UI runs wherever you put the hub, and **that can be your own
laptop**:

```
   ┌─────────────────────────────────────┐
   │  HUB  — your laptop, or a server    │  the dashboard: serves the UI,
   │  http://127.0.0.1:3100              │  holds the agent keys, fans out
   └─────────────────────────────────────┘
        │  SSH tunnels (auto-reconnecting)
        ├──────────────▶ AGENT web-01   127.0.0.1:3001 ──▶ fail2ban
        ├──────────────▶ AGENT web-02   127.0.0.1:3001 ──▶ fail2ban
        └──────────────▶ AGENT db-01    127.0.0.1:3001 ──▶ fail2ban
```

- **Agent** — one per monitored server. An API and nothing else: no UI, no
  session, no WebSocket, no background poll loop, no frontend build. Reads are
  cached and coalesced so polling can't become a `fail2ban-client` storm on a
  production box.
- **Hub** — the only web-facing service and the only thing a browser talks to.
  Authenticates to each agent with that agent's own key, held server-side; agent
  keys never reach the browser.

Monitoring a single server is just a fleet of one.

### Where does the hub run? Your choice

The hub is just a Node process that opens SSH tunnels and serves a page, so it
can live on a server **or on your own machine**.

**On your own machine (workstation mode).** You clone the repo, list your
servers, and run one command. The hub opens a tunnel to each server as it
starts, reconnects them if they drop, and closes them when you quit — no root,
no systemd, nothing left running:

```bash
git clone https://github.com/virgotex/fail2ban-dashboard.git
cd fail2ban-dashboard
bash setup.sh hub --local
bash hub/enroll.sh you@server-01    # installs the agent there and registers it
cd hub && npm start                 # → http://127.0.0.1:3100
```

Anyone who needs the dashboard does the same on their machine. Connecting to
the servers is then their own business: their SSH keys, their tunnels, their
copy. Nothing has to be deployed for a new viewer.

**On a management server (shared mode).** One hub for everyone; viewers reach
it with `ssh -L 3100:127.0.0.1:3100 you@hub-host` and open
`http://127.0.0.1:3100`. Tunnels are systemd units (`hub/install-tunnels.sh`).
Use this when you'd rather the agent keys lived on one hardened box than on
several laptops — see the trade-off in [`docs/SECURITY.md`](docs/SECURITY.md).

Both modes run identical code and can coexist: a shared hub on a server, and
your own local hub for the same fleet.

### What do I see?

You land on the **fleet overview** — one row per server with reachability, jail
count and ban totals, plus fleet-wide totals. In workstation mode an offline row
also tells you *which half* broke ("tunnel down" vs "agent down"). Pick a server
from the sidebar to get its Dashboard, Logs, **Reports**, Banned IPs and
Settings, and to ban/unban on it.

Reports (7-day trend, per-jail breakdown, recent bans) are **per server**,
derived from that server's own `fail2ban.log`; the cross-server view is the
overview table.

### What do I install where?

| Machine | What you install | What it does |
|---|---|---|
| Wherever you want the dashboard — your laptop, or a server | **hub** — `bash setup.sh hub --local` (or `hub`) | Serves the dashboard, holds the agent keys, tunnels out to the fleet |
| Each monitored server | **agent** — pushed there by `bash hub/enroll.sh user@host` from the hub | ~65 MB Node process on `127.0.0.1:3001`. No UI, no build, no open ports, **no change to your fail2ban config** |

You only ever run commands on the hub machine. `enroll.sh` does the server-side
work over SSH; `setup.sh agent` exists for installing one by hand.

Adding a server that **already runs fail2ban** is the common case and needs no
fail2ban changes at all — its existing jails simply appear. See
[`DEPLOY.md`](DEPLOY.md) → *Quick path for an already-configured live server*,
and *A7* for a clean rollback.

> **Deploying?** **[`DEPLOY.md`](DEPLOY.md)** is the start-to-finish, verified
> walkthrough: pre-flight, agents, hub, tunnels, systemd, SSH access — including
> which steps to **skip on a live server**.

---

## Features

- Fleet overview: every server's jail count, active bans and reachability in one table
- Drill into any server for its dashboard, logs, reports and banned IPs
- Ban/unban IPs on any server directly from the UI
- Real-time log viewer with filtering by level and text
- 7-day ban trend charts and country breakdown
- IP investigation: timeline across fail2ban + auth logs, geo lookup, plain-English explanation
- Per-server security posture checklist
- One offline server degrades to an "offline" row, never breaks the view
- Secure by default (see Security below)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 18+ | [nodejs.org](https://nodejs.org) — on the agents, and wherever the hub runs |
| npm 8+ | Comes with Node |
| fail2ban | `sudo apt install fail2ban` — on the monitored servers |
| SSH key access | From the machine running the hub to every agent, passwordless |
| Linux | Ubuntu 20.04+ / Debian 11+ for agents. The hub also runs on macOS |

---

## Quick Start

Everything here runs on **the machine you want the dashboard on** — your laptop
is the usual choice. You never log in to a monitored server to install anything.

**1. Set up the hub:**

```bash
git clone https://github.com/virgotex/fail2ban-dashboard.git
cd fail2ban-dashboard
bash setup.sh hub --local    # generates the hub key, builds the UI
```

**2. Enroll each server you want to monitor** — one command per server, run from
here, doing everything over SSH:

```bash
bash hub/enroll.sh --dry-run youruser@SERVER_IP    # pre-flight, changes nothing
bash hub/enroll.sh youruser@SERVER_IP              # install + register
```

It pre-flights the box, installs the agent and its service, grants it scoped
`sudo` for `fail2ban-client`, verifies it answers, and registers it in
`hub/servers.json` on the next free port — copying that agent's key across
directly, so the two can't disagree. Re-run it any time to update a server.

Two prerequisites per server: passwordless SSH (`ssh-copy-id youruser@SERVER_IP`),
and the hub's IP in that server's fail2ban `ignoreip` — otherwise the tool that
watches fail2ban eventually gets banned by it. See [`DEPLOY.md`](DEPLOY.md)
*Step 0*.

**3. Start it and open the dashboard:**

```bash
cd hub && npm start          # opens the tunnels and serves the dashboard
```

**http://127.0.0.1:3100** — not `localhost`, which can resolve to `::1` and hit a
stray `ssh -L` forward instead of the hub. A local hub needs no `ssh -L` of its
own.

On a shared hub instead, drop `--local`, run
`sudo TUNNEL_USER=$USER bash hub/install-tunnels.sh` for systemd tunnels, and
viewers reach it with `ssh -L 3100:127.0.0.1:3100 you@HUB_HOST`.

Prefer to install an agent by hand, or want to know exactly what `enroll.sh` does
to a production box? [`DEPLOY.md`](DEPLOY.md) Part A documents every step it
automates.

---

## Project Structure

```
fail2ban-dashboard/
├── backend/                   # THE AGENT — runs on each monitored server
│   ├── src/
│   │   ├── server.js          # API only: no UI, no WebSocket, no poll loop
│   │   ├── fail2banClient.js  # Talks to the fail2ban-client binary
│   │   └── cache.js           # TTL cache + coalescing, protects the host
│   ├── .env.example
│   └── package.json
├── hub/                       # THE HUB — runs on one management host
│   ├── src/
│   │   ├── hub.js             # Registry, fan-out, allowlisted proxy, serves the SPA
│   │   └── mapLimit.js        # Bounded-concurrency fan-out
│   ├── enroll.sh              # Install + register a server, over SSH, in one command
│   ├── servers.example.json   # Agent registry (copy to servers.json — holds secrets)
│   ├── install-tunnels.sh     # systemd SSH tunnels to every agent
│   ├── .env.example
│   └── README.md              # Hub reference: API, registry, load control
├── frontend/                  # THE UI — built on the hub, served by the hub
│   ├── src/
│   │   ├── App.jsx            # Fleet overview + per-server pages
│   │   ├── hooks/useApi.js    # Talks to the hub, never to an agent
│   │   └── …
│   └── vite.config.js
├── docs/SECURITY.md
├── DEPLOY.md                  # Full multi-server deployment walkthrough
├── setup.sh                   # bash setup.sh agent | hub
└── README.md
```

---

## Security

### What's built in

| Layer | Implementation |
|---|---|
| Loopback binding | Agents (`3001`) and hub (`3100`) bind to `127.0.0.1`; access is via SSH tunnel |
| Key separation | The browser holds only `HUB_API_SECRET`; each agent's key stays server-side in `servers.json` |
| Constant-time key check | `crypto.timingSafeEqual` on both hub and agents |
| Proxy allowlist | The hub proxies only known agent paths, per HTTP method — everything else is `404` |
| Secure HTTP headers | Helmet on both; agents use a deny-all CSP (they emit JSON only) |
| Rate limiting | Hub 300/min · agents 100/min, 20/min for writes (honours `trust proxy`) |
| Input validation | All parameters validated before use |
| No shell injection | fail2ban commands built as arg arrays — never string-interpolated |
| IP validation | Strict IPv4/IPv6/CIDR check before any ban/unban |
| Key transport | `X-API-Key` header only — never in URLs or access logs |
| Payload size limit | JSON body capped at 10KB |
| Log reads bounded | Only the last few MB of `fail2ban.log` and friends per request |
| Geo lookups proxied | IP intel goes through the agent (cached), so investigated IPs don't leak from your browser |
| Audit trail | Every ban/unban emits `[AUDIT] {…}` on the agent that executed it |

> **Auth scope:** `VITE_API_KEY` ships inside the React bundle — anyone who can
> load the dashboard holds the hub key. It gates non-browser callers; it does not
> authenticate end users. That's why the hub binds to loopback and you reach it
> over SSH. For multi-user access, put an authenticating reverse proxy (OIDC or
> session+password) in front of the hub — see [`docs/SECURITY.md`](docs/SECURITY.md).

### Load on your production servers

Because the servers being monitored are the ones you can least afford to slow
down, the polling path is bounded at every hop:

| Setting | Where | Default | Effect |
|---|---|---|---|
| `AGENT_CACHE_TTL_MS` | agent | `5000` | Reuse window for `fail2ban-client` reads; concurrent reads coalesce into one |
| `LOG_CACHE_TTL_MS` | agent | `10000` | Same, for log parsing |
| `HUB_OVERVIEW_TTL_MS` | hub | `10000` | The fleet overview is computed once per window and shared by all viewers |
| `HUB_FANOUT_CONCURRENCY` | hub | `4` | Agents queried at a time, so a big fleet isn't woken at once |

Extra operators are therefore free, and the UI stops polling entirely while its
tab is hidden.

---

## Development

The dev server proxies to the **hub** (`127.0.0.1:3100`) — the browser never
talks to an agent, in dev or in production.

```bash
# Terminal 1 — an agent (needs local fail2ban access)
cd backend && npm run dev

# Terminal 2 — the hub (needs hub/servers.json pointing at that agent)
cd hub && npm run dev

# Terminal 3 — the UI with HMR
cd frontend && npm run dev        # → http://localhost:5173

# Production build (this is what the hub serves)
cd frontend && npm run build

# Tests — the log parsers, against real fixture files. No fail2ban needed.
cd backend && npm test
```

The tests cover the surface where what the code sees depends on the filesystem:
logrotate having moved history into `fail2ban.log.1`, an archive being gzipped, a
byte budget slicing a line in half, and the level/text filters. CI runs them on
every branch.

---

## Hosting this on GitHub

The code is safe to publish. **Your configuration is not** — the split is by
design, so hosting the repo (public or private) needs no special handling beyond
leaving it in place.

### What never goes to git

| File | Why | Where it lives instead |
|---|---|---|
| `hub/servers.json` | Every agent's API key **plus your real hostnames/IPs** | only on the machine running the hub |
| `hub/.env` | `HUB_API_SECRET` | only on the hub machine |
| `backend/.env` | that server's `API_SECRET` | only on that server |
| `frontend/.env.local` | a copy of the hub secret | only on the hub machine |
| `frontend/dist/` | the built bundle, with `HUB_API_SECRET` baked in | rebuilt on the hub |

Committed instead: `servers.example.json` and the `.env.example` files, with
placeholders. Everything real is generated per install by `setup.sh`.

### Two locks

1. **`.gitignore`** covers all of the above — including `**/servers.json` at any
   depth and the `dist/` bundle.
2. **A pre-commit hook** inspects what's actually staged, because `.gitignore`
   can't stop `git add -f`, a rename, or a key pasted into a doc. Enable it once
   per clone (`setup.sh` does it for you):

   ```bash
   git config core.hooksPath .githooks
   ```

   It blocks: any file named `servers.json` / `.env` / `.env.local`, private key
   material, `frontend/dist/*`, and any staged diff containing a 32+ character
   hex string (the shape of every key this project generates) or a real-looking
   `"apiKey"` value.

### Verify before you push

```bash
git ls-files | grep -Ei 'servers\.json|\.env$|\.env\.local'      # expect: nothing
git grep -nE '[0-9a-f]{32,}' -- . ':!*package-lock.json'         # expect: nothing
```

### If a secret does get pushed

Deleting the file in a later commit is **not** enough — it stays in history and
in forks. Rotate the credential instead: generate a new key, update
`backend/.env` on that agent and `servers.json` on the hub, restart both. The
exposed key was only ever usable by someone who could already SSH to that host
(agents are loopback-only), so rotation plus checking that host's `auth.log` is
the proportionate response. See [`docs/SECURITY.md`](docs/SECURITY.md) §2.

### Public or private?

Either works. Public is fine — there are no credentials, no hostnames, and no
information about your fleet in the tree. Private adds a little obscurity about
which tooling you run, at the cost of `git clone` on each server needing a
deploy key or token. If you go private, a read-only deploy key per server is the
tidy option.

---

## License

MIT — do whatever you want, stay secure.
