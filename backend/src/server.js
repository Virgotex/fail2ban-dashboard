/**
 * server.js — Fail2Ban Dashboard AGENT
 *
 * One of these runs on every monitored server. It is an API only: it does not
 * serve a UI, hold a session, or open a WebSocket. The single client is the
 * hub (see ../../hub), which reaches it over an SSH tunnel and authenticates
 * with this agent's API_SECRET. Operators use the hub's UI, never this.
 *
 * Keeping the agent headless is deliberate — monitored servers are production
 * boxes, so the footprint here stays as small as it can be:
 *   - no static assets, no React build, no browser session state
 *   - no WebSocket server and no background poll loop
 *   - reads are cached + coalesced (see cache.js) so hub polling can't turn
 *     into a continuous stream of fail2ban-client subprocesses
 *
 * Security layers:
 *   1. Helmet — secure HTTP headers
 *   2. Binds to 127.0.0.1 — reachable only through the hub's SSH tunnel
 *   3. Rate limiting — 100 req/min per IP by default, 20/min for writes
 *   4. Input validation on every route that accepts parameters
 *   5. No shell interpolation — fail2ban commands built as argv arrays
 *   6. API-key auth (constant-time compare) on every route but /api/health
 *   7. Structured [AUDIT] line on every ban/unban
 */

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const morgan     = require('morgan');
const http       = require('http');
const crypto     = require('crypto');
const { query, param, validationResult } = require('express-validator');

const f2b = require('./fail2banClient');
const { cached, invalidate } = require('./cache');

const app    = express();
const server = http.createServer(app);

const PORT         = parseInt(process.env.PORT || '3001', 10);
const BIND_ADDRESS = process.env.BIND_ADDRESS || '127.0.0.1';
const API_SECRET   = process.env.API_SECRET || 'dev_secret_change_me';
const IS_PROD      = process.env.NODE_ENV === 'production';
const GEO_ENABLED  = process.env.GEO_LOOKUP !== 'false';
const GEO_TTL_MS   = parseInt(process.env.GEO_TTL_MS || '3600000', 10);  // 1h

// How long a fail2ban-client read is reused before we ask the daemon again.
// The hub polls on a fixed interval; this decides how much of that reaches
// fail2ban. Set to 0 to disable caching (every request hits the daemon).
const CACHE_TTL_MS     = parseInt(process.env.AGENT_CACHE_TTL_MS || '5000',  10);
// Log parsing (logs / reports / IP investigation) re-reads files from disk,
// so it gets its own, longer TTL.
const LOG_CACHE_TTL_MS = parseInt(process.env.LOG_CACHE_TTL_MS   || '10000', 10);

// Honour X-Forwarded-For only from loopback proxies. Agents normally sit
// behind nothing at all — the hub connects straight to the tunnel.
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');

// ─── Security middleware ──────────────────────────────────────────────────

// No SPA is served here, so the CSP can be maximally restrictive: this
// process only ever emits JSON.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(express.json({ limit: '10kb' }));

// Strip any apiKey query param before morgan sees it — we never accept auth
// in a URL, and this keeps a stray one out of the access log.
app.use((req, _res, next) => {
  if (req.query && req.query.apiKey) delete req.query.apiKey;
  next();
});

app.use(morgan(IS_PROD ? 'combined' : 'dev'));

const RATE_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_MAX       = parseInt(process.env.RATE_LIMIT_MAX       || '100',   10);

app.use(rateLimit({
  windowMs: RATE_WINDOW_MS,
  max:      RATE_MAX,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many requests, please slow down.' },
}));

const writeLimiter = rateLimit({
  windowMs: 60000,
  max: 20,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many write requests.' },
});

// ─── Auth ─────────────────────────────────────────────────────────────────
function constantTimeKeyEq(provided) {
  const a = Buffer.from(String(provided));
  const b = Buffer.from(API_SECRET);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}

// The agent's only caller is the hub, so there is one auth mode: the API key.
// User-level authentication (who is allowed to look at the fleet at all)
// belongs on the hub, in front of the UI.
function requireKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  if (!constantTimeKeyEq(key)) return res.status(403).json({ error: 'Invalid API key' });
  next();
}

// ─── Validation + error helpers ───────────────────────────────────────────
function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() });
    return false;
  }
  return true;
}

function sendError(res, err, status = 500, publicMsg = 'Internal server error') {
  const detail = err && err.message ? err.message : String(err);
  console.error('[ERROR]', detail);
  res.status(status).json({ error: IS_PROD ? publicMsg : detail });
}

function audit(req, action, target) {
  console.log('[AUDIT]', JSON.stringify({
    ts:     new Date().toISOString(),
    user:   'hub',           // the API key is the hub's; see hub/servers.json
    action,
    ip:     req.ip,
    ...target,
  }));
}

// ─── Routes ───────────────────────────────────────────────────────────────

// Unauthenticated liveness. `role` lets the hub (and you, over a tunnel) tell
// an agent apart from a hub without a key.
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', role: 'agent', time: new Date().toISOString() });
});

app.get('/api/security', requireKey, (req, res) => {
  res.json({
    runtime: {
      role:               'agent',
      bindAddress:        BIND_ADDRESS,
      port:               PORT,
      nodeEnv:            process.env.NODE_ENV || 'development',
      trustProxy:         app.get('trust proxy'),
      rateLimit:          { windowMs: RATE_WINDOW_MS, max: RATE_MAX, writeMax: 20 },
      geoLookupEnabled:   GEO_ENABLED,
      useSudo:            process.env.USE_SUDO !== 'false',
      jsonBodyLimit:      '10kb',
      cacheTtlMs:         CACHE_TTL_MS,
      logCacheTtlMs:      LOG_CACHE_TTL_MS,
      servesStaticSPA:    false,
      apiKeyTransport:    'X-API-Key header',
    },
    builtIn: [
      `Agent binds to ${BIND_ADDRESS} — reachable only via the hub's SSH tunnel`,
      'API only: no UI, no session, no WebSocket, no background poll loop',
      'Helmet security headers (deny-all CSP — this process emits JSON only)',
      'API-key auth (constant-time comparison) on every route but /api/health',
      'Strict IP/CIDR validation on every ban/unban',
      'fail2ban commands built as argv arrays (no shell)',
      `Reads cached ${CACHE_TTL_MS}ms and coalesced, so polling can't stampede fail2ban`,
      'Audit log on every ban/unban',
    ],
    operatorMustVerify: [
      'Host firewall blocking inbound traffic to port ' + PORT,
      'fail2ban-client sudoers rule scoped to the fail2ban-client binary',
      'Read access to /var/log/fail2ban.log for the dashboard user',
      'This agent\'s API_SECRET matches its entry in the hub\'s servers.json',
    ],
  });
});

app.get('/api/status', requireKey, async (req, res) => {
  try {
    res.json(await cached('status', CACHE_TTL_MS, () => f2b.ping()));
  } catch (e) { sendError(res, e); }
});

app.get('/api/jails', requireKey, async (req, res) => {
  try {
    const jails = await cached('jails', CACHE_TTL_MS, () => f2b.getAllJailStatuses());
    res.json({ jails });
  } catch (e) { sendError(res, e); }
});

app.get('/api/jails/:name',
  requireKey,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const jail = await cached(`jail:${req.params.name}`, CACHE_TTL_MS,
        () => f2b.getJailStatus(req.params.name));
      res.json(jail);
    } catch (e) { sendError(res, e); }
  }
);

app.post('/api/jails/:name/ban',
  requireKey,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const { ip } = req.body;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const result = await f2b.banIP(req.params.name, ip);
      invalidateJailReads();
      audit(req, 'ban', { jail: req.params.name, target: ip });
      res.json(result);
    } catch (e) {
      audit(req, 'ban_failed', { jail: req.params.name, target: ip, error: e.message });
      sendError(res, e);
    }
  }
);

app.delete('/api/jails/:name/ban/:ip',
  requireKey,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const result = await f2b.unbanIP(req.params.name, ip);
      invalidateJailReads();
      audit(req, 'unban', { jail: req.params.name, target: ip });
      res.json(result);
    } catch (e) {
      audit(req, 'unban_failed', { jail: req.params.name, target: ip, error: e.message });
      sendError(res, e);
    }
  }
);

// A ban/unban changes what every jail read would return — drop them all so
// the operator sees the effect on the next refresh instead of a stale count.
function invalidateJailReads() {
  invalidate('jails');
  invalidate('jail:');
  invalidate('status');
}

app.get('/api/ip/:ip/details',
  requireKey,
  param('ip').isString().isLength({ min: 2, max: 45 }),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const details = await cached(`ipdetails:${ip}`, LOG_CACHE_TTL_MS,
        () => f2b.getIPDetails(ip));
      res.json(details);
    } catch (e) { sendError(res, e); }
  }
);

const geoCache = new Map();
app.get('/api/ip/:ip/geo',
  requireKey,
  param('ip').isString().isLength({ min: 2, max: 45 }),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    if (!GEO_ENABLED) return res.json({ disabled: true });
    const now = Date.now();
    const hit = geoCache.get(ip);
    if (hit && hit.expiry > now) return res.json(hit.data);
    try {
      const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query`;
      const upstream = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!upstream.ok) throw new Error(`Geo upstream returned ${upstream.status}`);
      const data = await upstream.json();
      geoCache.set(ip, { data, expiry: now + GEO_TTL_MS });
      res.json(data);
    } catch (e) {
      sendError(res, e, 502, 'Geo lookup failed');
    }
  }
);

app.get('/api/reports', requireKey, async (req, res) => {
  try {
    res.json(await cached('reports', LOG_CACHE_TTL_MS, () => f2b.getReports()));
  } catch (e) { sendError(res, e); }
});

app.get('/api/config', requireKey, async (req, res) => {
  try {
    res.json(await cached('config', CACHE_TTL_MS, () => f2b.getGlobalConfig()));
  } catch (e) { sendError(res, e); }
});

app.get('/api/logs',
  requireKey,
  query('filter').optional().isString().isLength({ max: 100 }).trim(),
  query('level').optional().isIn(['', 'BAN', 'UNBAN', 'WARNING']),
  async (req, res) => {
    if (!validate(req, res)) return;
    const filter = req.query.filter || '';
    const level  = req.query.level  || '';
    try {
      const logs = await cached(`logs:${level}:${filter}`, LOG_CACHE_TTL_MS,
        () => f2b.getLogs(filter, level));
      res.json({ logs });
    } catch (e) { sendError(res, e); }
  }
);

// ─── 404 + error handler ──────────────────────────────────────────────────
// Everything here is JSON; there is no SPA fallback to fall through to.
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, _next) => sendError(res, err));

// ─── Start + graceful shutdown ────────────────────────────────────────────
server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`\n🛡  Fail2Ban Dashboard AGENT (API only)`);
  console.log(`   Listening on http://${BIND_ADDRESS}:${PORT}`);
  console.log(`   Read cache:   ${CACHE_TTL_MS}ms (logs ${LOG_CACHE_TTL_MS}ms)`);
  console.log(`   Environment:  ${process.env.NODE_ENV || 'development'}`);
  console.log(`   UI:           none — point a hub at this agent\n`);
  if (API_SECRET === 'dev_secret_change_me') {
    console.warn('[WARN] API_SECRET is the default value. Generate one before deploying.');
  }
});

function shutdown(signal) {
  console.log(`\n[${signal}] Shutting down…`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
