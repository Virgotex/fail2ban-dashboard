/**
 * hub.js — Fail2Ban Dashboard multi-server hub
 *
 * The hub does NOT talk to fail2ban directly. Instead it fans out to the
 * per-server dashboard backends ("agents") — the exact same Express app you
 * already deploy on each server — and aggregates their responses.
 *
 *   Browser ──▶ Hub (this) ──▶ Agent A (127.0.0.1:410x via SSH tunnel) ──▶ fail2ban
 *                          └─▶ Agent B ...
 *                          └─▶ Agent C ...
 *
 * Security model (same spirit as the agent):
 *   - Hub binds to 127.0.0.1 by default; you reach it over an SSH tunnel.
 *   - Hub is authenticated with its own API key (constant-time compare).
 *   - Each agent stays loopback-only on its own host; the hub reaches it over
 *     an SSH tunnel to a distinct local port (see hub/install-tunnels.sh). The agent's
 *     API key is stored server-side in servers.json and injected by the hub —
 *     it never reaches the browser.
 *   - Per-server requests fan out concurrently with a timeout; one dead server
 *     degrades to an `online:false` entry instead of failing the whole view.
 */

require('dotenv').config();

const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan    = require('morgan');
const http      = require('http');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');

const { mapLimit } = require('./mapLimit');
const { TunnelSupervisor } = require('./tunnels');

const app    = express();
const server = http.createServer(app);

const PORT         = parseInt(process.env.HUB_PORT || '3100', 10);
const BIND_ADDRESS = process.env.HUB_BIND_ADDRESS || '127.0.0.1';
const API_SECRET   = process.env.HUB_API_SECRET || 'dev_hub_secret_change_me';
const IS_PROD      = process.env.NODE_ENV === 'production';
const AGENT_TIMEOUT = parseInt(process.env.AGENT_TIMEOUT_MS || '8000', 10);
const SERVERS_FILE = process.env.HUB_SERVERS_FILE || path.resolve(__dirname, '../servers.json');

// How many agents we query at once during a fleet fan-out. The point is not
// to protect the hub — it's to avoid waking every monitored server in the
// estate simultaneously, and to keep the hub's own socket/CPU use flat as the
// fleet grows. Raise it if your fleet is large and your agents are idle.
const FANOUT_CONCURRENCY = Math.max(1, parseInt(process.env.HUB_FANOUT_CONCURRENCY || '4', 10));

// The fleet overview is identical for every viewer, so it is computed at most
// once per window and shared. Ten browser tabs polling every 20s then cost the
// agents one round of queries per window, not ten.
const OVERVIEW_TTL_MS = parseInt(process.env.HUB_OVERVIEW_TTL_MS || '10000', 10);

// Workstation mode: the hub opens and supervises its own SSH tunnels instead of
// relying on systemd units. Lets someone run the whole dashboard on a laptop
// with `npm start` and no root. On a server, prefer install-tunnels.sh.
const MANAGE_TUNNELS = process.env.HUB_MANAGE_TUNNELS === 'true';
const AGENT_PORT     = parseInt(process.env.AGENT_PORT || '3001', 10);

// Only these agent API paths may be proxied through the hub, per HTTP method.
// Anchored so nothing outside the known agent surface is reachable.
const PROXY_ALLOW = [
  { method: 'GET',    re: /^status$/ },
  { method: 'GET',    re: /^jails$/ },
  { method: 'GET',    re: /^jails\/[a-zA-Z0-9_-]{1,64}$/ },
  { method: 'GET',    re: /^logs$/ },
  { method: 'GET',    re: /^reports$/ },
  { method: 'GET',    re: /^config$/ },
  { method: 'GET',    re: /^security$/ },
  { method: 'GET',    re: /^ip\/[^/]{2,45}\/details$/ },
  { method: 'GET',    re: /^ip\/[^/]{2,45}\/geo$/ },
  { method: 'POST',   re: /^jails\/[a-zA-Z0-9_-]{1,64}\/ban$/ },
  { method: 'DELETE', re: /^jails\/[a-zA-Z0-9_-]{1,64}\/ban\/[^/]{2,45}$/ },
];

// ─── Load + validate server registry ──────────────────────────────────────
// `fatal` separates the two callers. At startup a broken registry should stop
// the hub; on reload it must only be rejected, because a half-saved edit must
// not take a running dashboard down.
function loadServers({ fatal = true } = {}) {
  const fail = (...msgs) => {
    if (!fatal) throw new Error(msgs[0].replace(/^\[hub\] /, ''));
    for (const m of msgs) console.error(m);
    process.exit(1);
  };

  let raw;
  try {
    raw = fs.readFileSync(SERVERS_FILE, 'utf8');
  } catch (e) {
    fail(`[hub] Could not read ${SERVERS_FILE}: ${e.message}`,
         '[hub] Copy hub/servers.example.json to hub/servers.json and fill it in.');
  }
  let list;
  try {
    list = JSON.parse(raw);
  } catch (e) {
    fail(`[hub] ${SERVERS_FILE} is not valid JSON: ${e.message}`);
  }
  if (!Array.isArray(list) || list.length === 0) {
    fail('[hub] servers.json must be a non-empty JSON array.');
  }
  const seen = new Set();
  for (const s of list) {
    if (!s.id || !/^[a-zA-Z0-9_-]{1,64}$/.test(s.id)) {
      fail(`[hub] Each server needs an "id" matching [a-zA-Z0-9_-]{1,64}. Bad entry: ${JSON.stringify(s)}`);
    }
    if (seen.has(s.id)) fail(`[hub] Duplicate server id: ${s.id}`);
    seen.add(s.id);
    if (!s.baseUrl || !/^https?:\/\//.test(s.baseUrl)) {
      fail(`[hub] Server "${s.id}" needs a baseUrl starting with http:// or https://`);
    }
    // Normalise: drop any trailing slash so we can append cleanly.
    s.baseUrl = s.baseUrl.replace(/\/+$/, '');
    s.name = s.name || s.id;
    s.apiKey = s.apiKey || '';
    // Optional, and never used by the hub itself: install-tunnels.sh reads it
    // to build this agent's systemd tunnel unit. Validated here so a typo
    // surfaces at boot rather than at tunnel-install time.
    if (s.ssh !== undefined && (typeof s.ssh !== 'string' || !s.ssh.trim())) {
      fail(`[hub] Server "${s.id}": "ssh" must be a non-empty string like "user@host".`);
    }
    if (!s.apiKey) {
      console.warn(`[hub] WARNING: server "${s.id}" has no apiKey — the agent will reject its requests.`);
    }
    // Leftovers from servers.example.json. Left in, they produce a permanently
    // offline row and an endless tunnel-reconnect log — indistinguishable at a
    // glance from a real server being down. Refuse to start instead.
    if (/^PASTE_/.test(s.apiKey) || /\.example\.com(:|$)/.test(s.ssh || '')) {
      fail(`[hub] Server "${s.id}" is still an unedited example entry.`,
           '[hub] Delete the entries you do not use from servers.json, and fill in the rest.');
    }
    // An agent should be reached over a tunnel (loopback) or TLS. Plain http
    // to a remote host would put that agent's key on the wire in clear.
    if (/^http:\/\//.test(s.baseUrl) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|$)/.test(s.baseUrl)) {
      console.warn(`[hub] WARNING: server "${s.id}" uses plain http to a non-loopback host (${s.baseUrl}).`);
      console.warn('[hub]          Its API key travels unencrypted. Use an SSH tunnel to 127.0.0.1, or https.');
    }
  }
  return list;
}

// The registry is reloadable (see reloadServers), so these are `let` and must
// always be read live — never captured in a closure at startup.
let SERVERS = loadServers();
let SERVER_BY_ID = new Map(SERVERS.map(s => [s.id, s]));
// Public view of a server — never leak the agent apiKey to the browser.
const publicServer = s => ({ id: s.id, name: s.name });

// ─── Tunnels (workstation mode) ────────────────────────────────────────────
const tunnels = MANAGE_TUNNELS
  ? new TunnelSupervisor(SERVERS, { agentPort: AGENT_PORT, log: console.log })
  : null;

function warnMissingSsh() {
  if (!MANAGE_TUNNELS) return;
  const missing = SERVERS.filter(s => !s.ssh).map(s => s.id);
  if (missing.length) {
    console.warn(`[hub] HUB_MANAGE_TUNNELS is on but these servers have no "ssh" field: ${missing.join(', ')}`);
    console.warn('[hub] They will only work if something else is already forwarding their baseUrl port.');
  }
}
warnMissingSsh();

// ─── Reloading the registry without a restart ───────────────────────────────
// Enrolling a server appends to servers.json, and requiring a restart to see it
// meant every enrollment ended with dropping every healthy tunnel. Triggered by
// SIGHUP or by the file changing on disk.
//
// A bad edit must not take the hub down: loadServers() exits the process on
// invalid input, which is right at startup and wrong here, so validation runs
// against a copy first and a broken file leaves the running registry in place.
function reloadServers(reason) {
  let next;
  try {
    next = loadServers({ fatal: false });
  } catch (e) {
    console.error(`[hub] reload (${reason}) rejected, keeping the current ${SERVERS.length} server(s): ${e.message}`);
    return null;
  }

  const before = new Set(SERVERS.map(s => s.id));
  SERVERS = next;
  SERVER_BY_ID = new Map(SERVERS.map(s => [s.id, s]));
  overviewCache = null;                       // it summarises a fleet that just changed
  warnMissingSsh();

  const after = new Set(SERVERS.map(s => s.id));
  const added   = [...after].filter(id => !before.has(id));
  const removed = [...before].filter(id => !after.has(id));
  const sync = tunnels ? tunnels.sync(SERVERS) : { added: [], removed: [], changed: [] };

  const parts = [`${SERVERS.length} server(s)`];
  if (added.length)   parts.push(`+${added.join(',')}`);
  if (removed.length) parts.push(`-${removed.join(',')}`);
  if (sync.changed.length) parts.push(`~${sync.changed.join(',')} (tunnel re-pointed)`);
  console.log(`[hub] reloaded registry (${reason}): ${parts.join(' · ')}`);
  return { added, removed, changed: sync.changed };
}

process.on('SIGHUP', () => reloadServers('SIGHUP'));

// Watching the file is what makes `enroll.sh` feel finished: the new row appears
// without touching the hub. Debounced, because an editor's save is several
// events and a rewrite is briefly a truncated file.
if (process.env.HUB_WATCH_REGISTRY !== 'false') {
  let debounce = null;
  try {
    fs.watch(SERVERS_FILE, () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => reloadServers('servers.json changed'), 250);
      if (debounce.unref) debounce.unref();
    }).unref();
  } catch (e) {
    console.warn(`[hub] not watching ${SERVERS_FILE} (${e.message}) — reload with SIGHUP`);
  }
}

// ─── Call a single agent ───────────────────────────────────────────────────
async function agentFetch(srv, apiPath, { method = 'GET', body, query } = {}) {
  let url = `${srv.baseUrl}/api/${apiPath}`;
  if (query) url += (url.includes('?') ? '&' : '?') + query;
  const headers = { 'Accept': 'application/json' };
  if (srv.apiKey) headers['X-API-Key'] = srv.apiKey;
  const opts = { method, headers, signal: AbortSignal.timeout(AGENT_TIMEOUT) };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { status: res.status, ok: res.ok, data };
}

// Summarise one server for the fleet overview. Never throws — a dead server
// comes back as { online:false, error }.
async function summariseServer(srv) {
  try {
    const [statusRes, jailsRes] = await Promise.all([
      agentFetch(srv, 'status'),
      agentFetch(srv, 'jails'),
    ]);
    const online = statusRes.ok && !!(statusRes.data && statusRes.data.ok);
    const jails = (jailsRes.ok && jailsRes.data && Array.isArray(jailsRes.data.jails))
      ? jailsRes.data.jails : [];
    const currentlyBanned = jails.reduce((n, j) => n + (j.currentlyBanned || 0), 0);
    const totalBanned     = jails.reduce((n, j) => n + (j.totalBanned || 0), 0);
    return {
      ...publicServer(srv),
      online,
      reachable: statusRes.ok,
      jailCount: jails.length,
      currentlyBanned,
      totalBanned,
      error: online ? null : (statusRes.data && statusRes.data.error) || null,
      ...tunnelInfo(srv.id),
    };
  } catch (e) {
    return {
      ...publicServer(srv),
      online: false, reachable: false,
      jailCount: 0, currentlyBanned: 0, totalBanned: 0,
      error: e.name === 'TimeoutError' ? 'timeout' : e.message,
      ...tunnelInfo(srv.id),
    };
  }
}

// When the hub owns the tunnel it can say *why* a server is unreachable —
// "the tunnel is down" and "the agent is down" look identical from a failed
// fetch, and they need different fixes.
function tunnelInfo(id) {
  if (!tunnels) return {};
  const t = tunnels.status(id);
  if (!t) return {};
  return { tunnel: t.state, tunnelError: t.lastError || null };
}

// ─── Middleware ─────────────────────────────────────────────────────────────
const DIST_DIR = path.resolve(__dirname, '../../frontend/dist');
const SERVE_STATIC = fs.existsSync(path.join(DIST_DIR, 'index.html'));

app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));
app.use(express.json({ limit: '10kb' }));
app.use(morgan(IS_PROD ? 'combined' : 'dev'));
app.use(rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  max:      parseInt(process.env.RATE_LIMIT_MAX       || '300',   10),
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
}));

function constantTimeKeyEq(provided) {
  const a = Buffer.from(String(provided));
  const b = Buffer.from(API_SECRET);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}
function requireKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  if (!constantTimeKeyEq(key)) return res.status(403).json({ error: 'Invalid API key' });
  next();
}

// ─── Routes ───────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// Lets the SPA discover it's behind a hub (vs a single-server agent) without
// auth, mirroring the agent's /api/auth/me contract.
app.get('/api/mode', (req, res) => {
  res.json({ mode: 'hub', authMode: 'apikey', authenticated: true, serverCount: SERVERS.length });
});

app.get('/api/servers', requireKey, (req, res) => {
  res.json({ servers: SERVERS.map(publicServer) });
});

// ─── Fleet overview ─────────────────────────────────────────────────────────
// Fan out to every server with bounded concurrency, then cache the result for
// OVERVIEW_TTL_MS. Concurrent callers during a fan-out share the in-flight
// promise, so however many operators are watching, each agent sees at most one
// round of queries per window.
let overviewCache = null;      // { expiry, payload }
let overviewInflight = null;   // Promise

async function buildOverview() {
  const servers = await mapLimit(SERVERS, FANOUT_CONCURRENCY, summariseServer);
  const totals = servers.reduce((t, s) => ({
    servers:         t.servers + 1,
    online:          t.online + (s.online ? 1 : 0),
    offline:         t.offline + (s.online ? 0 : 1),
    currentlyBanned: t.currentlyBanned + s.currentlyBanned,
    totalBanned:     t.totalBanned + s.totalBanned,
    jailCount:       t.jailCount + s.jailCount,
  }), { servers: 0, online: 0, offline: 0, currentlyBanned: 0, totalBanned: 0, jailCount: 0 });
  return { totals, servers, generatedAt: new Date().toISOString() };
}

function getOverview() {
  const now = Date.now();
  if (overviewCache && overviewCache.expiry > now) return Promise.resolve(overviewCache.payload);
  if (overviewInflight) return overviewInflight;

  overviewInflight = buildOverview()
    .then(payload => {
      if (OVERVIEW_TTL_MS > 0) overviewCache = { expiry: Date.now() + OVERVIEW_TTL_MS, payload };
      return payload;
    })
    .finally(() => { overviewInflight = null; });
  return overviewInflight;
}

app.get('/api/overview', requireKey, async (req, res) => {
  try {
    res.json(await getOverview());
  } catch (e) {
    console.error('[hub] overview failed:', e && e.message);
    res.status(500).json({ error: IS_PROD ? 'Overview failed' : (e && e.message) });
  }
});

// Proxy a whitelisted agent endpoint for a specific server.
// /api/servers/:id/<agentPath>  →  <baseUrl>/api/<agentPath>
app.use('/api/servers/:id', requireKey, async (req, res) => {
  const srv = SERVER_BY_ID.get(req.params.id);
  if (!srv) return res.status(404).json({ error: 'Unknown server id' });

  const apiPath = req.params[0] !== undefined
    ? req.params[0]
    : req.url.replace(/^\//, '').split('?')[0];
  const clean = apiPath.replace(/^\/+/, '');

  const allowed = PROXY_ALLOW.some(rule => rule.method === req.method && rule.re.test(clean));
  if (!allowed) return res.status(404).json({ error: 'Not found' });

  const qs = req.url.includes('?') ? req.url.split('?').slice(1).join('?') : undefined;
  try {
    const out = await agentFetch(srv, clean, {
      method: req.method,
      body:   ['POST', 'PUT', 'PATCH'].includes(req.method) ? req.body : undefined,
      query:  qs,
    });
    // A ban/unban changes the fleet's banned counts — drop the cached overview
    // so the operator doesn't watch a stale total for up to a full window.
    if (out.ok && req.method !== 'GET') overviewCache = null;
    res.status(out.status).json(out.data);
  } catch (e) {
    const msg = e.name === 'TimeoutError' ? `Server "${srv.id}" timed out` : e.message;
    res.status(502).json({ error: IS_PROD ? `Upstream error for "${srv.id}"` : msg });
  }
});

// ─── Static SPA + fallback ──────────────────────────────────────────────────
if (SERVE_STATIC) {
  console.log(`[hub] Serving SPA from ${DIST_DIR}`);
  app.use(express.static(DIST_DIR, { maxAge: '1h', index: false }));
}
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  if (SERVE_STATIC && req.method === 'GET') return res.sendFile(path.join(DIST_DIR, 'index.html'));
  next();
});
app.use((err, req, res, _next) => {
  console.error('[hub][ERROR]', err && err.message);
  res.status(500).json({ error: IS_PROD ? 'Internal server error' : (err && err.message) });
});

// ─── Start ──────────────────────────────────────────────────────────────────
server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`\n🛡  Fail2Ban Dashboard HUB`);
  console.log(`   Listening on http://${BIND_ADDRESS}:${PORT}`);
  console.log(`   Servers:      ${SERVERS.length} (${SERVERS.map(s => s.id).join(', ')})`);
  console.log(`   Fan-out:      ${FANOUT_CONCURRENCY} at a time · ${AGENT_TIMEOUT}ms timeout`);
  console.log(`   Overview:     cached ${OVERVIEW_TTL_MS}ms, shared by all viewers`);
  console.log(`   Tunnels:      ${MANAGE_TUNNELS ? 'managed by this process' : 'external (systemd / already open)'}`);
  console.log(`   SPA serving:  ${SERVE_STATIC ? 'on' : 'off (run: cd ../frontend && npm run build)'}`);
  console.log(`   Environment:  ${process.env.NODE_ENV || 'development'}`);
  if (BIND_ADDRESS === '127.0.0.1') {
    console.log(`\n   → Open http://localhost:${PORT} (or forward this port over SSH)\n`);
  } else {
    console.log('');
  }
  if (API_SECRET === 'dev_hub_secret_change_me') {
    console.warn('[WARN] HUB_API_SECRET is the default value. Generate one before deploying.\n');
  }
  if (tunnels) tunnels.start();
});

function shutdown(sig) {
  console.log(`\n[${sig}] Shutting down hub…`);
  if (tunnels) tunnels.stopAll();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
