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
 *     an SSH tunnel to a distinct local port (see hub/tunnels.sh). The agent's
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

const app    = express();
const server = http.createServer(app);

const PORT         = parseInt(process.env.HUB_PORT || '3100', 10);
const BIND_ADDRESS = process.env.HUB_BIND_ADDRESS || '127.0.0.1';
const API_SECRET   = process.env.HUB_API_SECRET || 'dev_hub_secret_change_me';
const IS_PROD      = process.env.NODE_ENV === 'production';
const AGENT_TIMEOUT = parseInt(process.env.AGENT_TIMEOUT_MS || '8000', 10);
const SERVERS_FILE = process.env.HUB_SERVERS_FILE || path.resolve(__dirname, '../servers.json');

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
function loadServers() {
  let raw;
  try {
    raw = fs.readFileSync(SERVERS_FILE, 'utf8');
  } catch (e) {
    console.error(`[hub] Could not read ${SERVERS_FILE}: ${e.message}`);
    console.error('[hub] Copy hub/servers.example.json to hub/servers.json and fill it in.');
    process.exit(1);
  }
  let list;
  try {
    list = JSON.parse(raw);
  } catch (e) {
    console.error(`[hub] ${SERVERS_FILE} is not valid JSON: ${e.message}`);
    process.exit(1);
  }
  if (!Array.isArray(list) || list.length === 0) {
    console.error('[hub] servers.json must be a non-empty JSON array.');
    process.exit(1);
  }
  const seen = new Set();
  for (const s of list) {
    if (!s.id || !/^[a-zA-Z0-9_-]{1,64}$/.test(s.id)) {
      console.error(`[hub] Each server needs an "id" matching [a-zA-Z0-9_-]{1,64}. Bad entry: ${JSON.stringify(s)}`);
      process.exit(1);
    }
    if (seen.has(s.id)) { console.error(`[hub] Duplicate server id: ${s.id}`); process.exit(1); }
    seen.add(s.id);
    if (!s.baseUrl || !/^https?:\/\//.test(s.baseUrl)) {
      console.error(`[hub] Server "${s.id}" needs a baseUrl starting with http:// or https://`);
      process.exit(1);
    }
    // Normalise: drop any trailing slash so we can append cleanly.
    s.baseUrl = s.baseUrl.replace(/\/+$/, '');
    s.name = s.name || s.id;
    s.apiKey = s.apiKey || '';
  }
  return list;
}

const SERVERS = loadServers();
const SERVER_BY_ID = new Map(SERVERS.map(s => [s.id, s]));
// Public view of a server — never leak the agent apiKey to the browser.
const publicServer = s => ({ id: s.id, name: s.name });

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
    };
  } catch (e) {
    return {
      ...publicServer(srv),
      online: false, reachable: false,
      jailCount: 0, currentlyBanned: 0, totalBanned: 0,
      error: e.name === 'TimeoutError' ? 'timeout' : e.message,
    };
  }
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

// Fleet overview — concurrent fan-out to every server.
app.get('/api/overview', requireKey, async (req, res) => {
  const servers = await Promise.all(SERVERS.map(summariseServer));
  const totals = servers.reduce((t, s) => ({
    servers:         t.servers + 1,
    online:          t.online + (s.online ? 1 : 0),
    offline:         t.offline + (s.online ? 0 : 1),
    currentlyBanned: t.currentlyBanned + s.currentlyBanned,
    totalBanned:     t.totalBanned + s.totalBanned,
    jailCount:       t.jailCount + s.jailCount,
  }), { servers: 0, online: 0, offline: 0, currentlyBanned: 0, totalBanned: 0, jailCount: 0 });
  res.json({ totals, servers });
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
  console.log(`   SPA serving:  ${SERVE_STATIC ? 'on' : 'off'}`);
  console.log(`   Environment:  ${process.env.NODE_ENV || 'development'}\n`);
});

function shutdown(sig) {
  console.log(`\n[${sig}] Shutting down hub…`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
