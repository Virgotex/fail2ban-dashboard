/**
 * tunnels.js — the hub supervises its own SSH tunnels.
 *
 * On a server, tunnels are systemd units (see ../install-tunnels.sh): the init
 * system is right there and it does this job well. On a workstation there is no
 * root, possibly no systemd, and nobody wants to install units on their laptop
 * just to look at a dashboard. So when HUB_MANAGE_TUNNELS=true the hub spawns
 * one `ssh -N -L` child per registered server and keeps it alive itself.
 *
 * Deliberately modest: no daemonising, no PID files, no state on disk. The
 * children live and die with the hub process, which is exactly what you want
 * from something you started by typing `npm start`.
 *
 * Reconnection uses exponential backoff — a server that's down for an hour
 * shouldn't mean a reconnect attempt every second for an hour, and a laptop
 * that just closed its lid shouldn't come back to a thundering herd.
 */

const { spawn } = require('child_process');
const net = require('net');

const PROBE_INTERVAL_MS = 500;
const PROBE_ATTEMPTS    = 24;      // ~12s for the forward to come up
const BACKOFF_MIN_MS    = 2000;
const BACKOFF_MAX_MS    = 60000;
const STABLE_AFTER_MS   = 30000;   // up this long ⇒ reset the backoff

// Is 127.0.0.1:<port> accepting connections yet?
function probePort(port, timeoutMs = 1000) {
  return new Promise(resolve => {
    const sock = net.connect({ host: '127.0.0.1', port, timeout: timeoutMs });
    const done = ok => { sock.destroy(); resolve(ok); };
    sock.once('connect', () => done(true));
    sock.once('error',   () => done(false));
    sock.once('timeout', () => done(false));
  });
}

class TunnelSupervisor {
  /**
   * @param {Array} servers  registry entries; those without `ssh` are skipped
   * @param {object} opts    { agentPort, sshBin, log }
   */
  constructor(servers, { agentPort = 3001, sshBin = null, log = console.log } = {}) {
    this.log = log;
    this.agentPort = agentPort;
    this.sshBin = sshBin || process.env.HUB_SSH_BIN || 'ssh';
    this.stopping = false;
    this.tunnels = new Map();

    for (const s of servers) {
      if (!s.ssh) continue;
      const port = this.#localPortOf(s);
      if (!port) {
        this.log(`[tunnel] ${s.id}: baseUrl is not a loopback URL with a port — not managing a tunnel for it`);
        continue;
      }
      this.tunnels.set(s.id, {
        id: s.id, target: s.ssh, localPort: port,
        child: null, timer: null,
        state: 'stopped',       // stopped | starting | up | down
        restarts: 0, backoff: BACKOFF_MIN_MS,
        lastError: null, since: null,
      });
    }
  }

  // A tunnel only makes sense when the agent is addressed on loopback here.
  #localPortOf(server) {
    try {
      const u = new URL(server.baseUrl);
      const loopback = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(u.hostname);
      return loopback && u.port ? parseInt(u.port, 10) : null;
    } catch { return null; }
  }

  get managedIds() { return [...this.tunnels.keys()]; }

  status(id) {
    const t = this.tunnels.get(id);
    if (!t) return null;
    return {
      state: t.state, target: t.target, localPort: t.localPort,
      restarts: t.restarts, lastError: t.lastError,
      since: t.since ? new Date(t.since).toISOString() : null,
    };
  }

  statusAll() {
    const out = {};
    for (const id of this.tunnels.keys()) out[id] = this.status(id);
    return out;
  }

  start() {
    if (!this.tunnels.size) return;
    this.log(`[tunnel] managing ${this.tunnels.size} tunnel(s) with ${this.sshBin}`);
    for (const t of this.tunnels.values()) this.#spawn(t);
  }

  #spawn(t) {
    if (this.stopping) return;

    const args = [
      '-N',                                    // no remote command, just forward
      '-o', 'ExitOnForwardFailure=yes',        // fail loudly if the port is taken
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'BatchMode=yes',                   // never sit at a password prompt
      '-o', 'StrictHostKeyChecking=accept-new',
      '-L', `127.0.0.1:${t.localPort}:127.0.0.1:${this.agentPort}`,
      t.target,
    ];

    t.state = 'starting';
    t.since = Date.now();
    const child = spawn(this.sshBin, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    t.child = child;

    // ssh says useful things here — "Permission denied (publickey)",
    // "Address already in use" — worth keeping the last line of.
    child.stderr.on('data', chunk => {
      const line = String(chunk).trim().split('\n').filter(Boolean).pop();
      if (!line) return;
      t.lastError = line;
      this.log(`[tunnel] ${t.id}: ${line}`);
    });

    child.on('exit', (code, signal) => {
      if (this.stopping) return;
      t.child = null;
      t.state = 'down';
      const wasUpFor = Date.now() - (t.since || Date.now());
      if (wasUpFor >= STABLE_AFTER_MS) t.backoff = BACKOFF_MIN_MS;   // it was healthy; treat as a fresh failure
      this.log(`[tunnel] ${t.id} exited (${signal || `code ${code}`}), reconnecting in ${Math.round(t.backoff / 1000)}s`);
      t.timer = setTimeout(() => { t.restarts++; this.#spawn(t); }, t.backoff);
      if (t.timer.unref) t.timer.unref();
      t.backoff = Math.min(t.backoff * 2, BACKOFF_MAX_MS);
    });

    child.on('error', err => {
      t.lastError = err.message;
      this.log(`[tunnel] ${t.id}: failed to run ${this.sshBin} — ${err.message}`);
    });

    this.#waitForPort(t);
  }

  // The child being alive doesn't mean the forward works. Watch the port.
  async #waitForPort(t) {
    for (let i = 0; i < PROBE_ATTEMPTS; i++) {
      if (this.stopping || !t.child) return;
      if (await probePort(t.localPort)) {
        if (t.state !== 'up') {
          t.state = 'up';
          t.since = Date.now();
          t.lastError = null;
          this.log(`[tunnel] ${t.id} up — 127.0.0.1:${t.localPort} → ${t.target}:127.0.0.1:${this.agentPort}`);
        }
        return;
      }
      await new Promise(r => setTimeout(r, PROBE_INTERVAL_MS));
    }
    if (t.child && t.state === 'starting') {
      this.log(`[tunnel] ${t.id}: forward didn't come up within ${(PROBE_ATTEMPTS * PROBE_INTERVAL_MS) / 1000}s`);
    }
  }

  stopAll() {
    this.stopping = true;
    for (const t of this.tunnels.values()) {
      if (t.timer) clearTimeout(t.timer);
      if (t.child) { try { t.child.kill('SIGTERM'); } catch { /* already gone */ } }
      t.state = 'stopped';
    }
  }
}

module.exports = { TunnelSupervisor };
