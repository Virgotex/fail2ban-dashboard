/**
 * server.js — Fail2Ban Dashboard Backend
 *
 * Security layers applied:
 *   1. Helmet — secure HTTP headers (XSS, HSTS, no-sniff, CSP)
 *   2. CORS   — only the configured frontend origin is allowed (when the
 *               backend is API-only; same-origin when it serves the SPA)
 *   3. Rate limiting — 100 req/min per IP by default, 20/min for writes
 *   4. Input validation on every route that accepts parameters
 *   5. No shell interpolation — fail2ban commands built as argv arrays
 *   6. WebSocket auth via Sec-WebSocket-Protocol — never a URL query param
 *   7. Authentication is pluggable:
 *        - API-key mode (default, dev) — X-API-Key header / WS subprotocol
 *        - OIDC mode (production)      — session cookie via express-openid-connect
 *   8. In OIDC mode write actions require OIDC_REQUIRED_GROUP membership and
 *      every ban/unban emits a structured [AUDIT] line.
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const morgan     = require('morgan');
const http       = require('http');
const path       = require('path');
const fs         = require('fs');
const { WebSocketServer } = require('ws');
const { query, param, validationResult } = require('express-validator');
const crypto     = require('crypto');
const { auth: oidcAuth } = require('express-openid-connect');

const f2b = require('./fail2banClient');

const app    = express();
const server = http.createServer(app);

const PORT           = parseInt(process.env.PORT || '3001', 10);
const BIND_ADDRESS   = process.env.BIND_ADDRESS || '127.0.0.1';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';
const API_SECRET     = process.env.API_SECRET || 'dev_secret_change_me';
const IS_PROD        = process.env.NODE_ENV === 'production';
const GEO_ENABLED    = process.env.GEO_LOOKUP !== 'false';
const GEO_TTL_MS     = parseInt(process.env.GEO_TTL_MS || '3600000', 10);  // 1h
const WS_SUBPROTOCOL = 'fail2ban-api-key';

const OIDC_ENABLED        = process.env.OIDC_ENABLED === 'true';
const OIDC_REQUIRED_GROUP = process.env.OIDC_REQUIRED_GROUP || '';
const OIDC_GROUPS_CLAIM   = process.env.OIDC_GROUPS_CLAIM   || 'groups';

// When the backend ships the built SPA, the frontend lives at the same
// origin as the API — no CORS preflight, no separate auth boundary.
const DIST_DIR = path.resolve(__dirname, '../../frontend/dist');
const SERVE_STATIC = fs.existsSync(path.join(DIST_DIR, 'index.html'));

// Honour X-Forwarded-For only from loopback proxies (Caddy / Nginx sidecar).
// Operators terminating TLS off-host should override with TRUST_PROXY=<value>.
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');

// ─── Security Middleware ──────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],   // inline boot script for theme
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// CORS is only meaningful when the SPA is served from a different origin.
// In static-serving mode everything is same-origin and CORS becomes a no-op.
if (!SERVE_STATIC) {
  app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    credentials: true,
  }));
}

app.use(express.json({ limit: '10kb' }));

// Strip the apiKey query param from the URL morgan sees, defence-in-depth
// in case an older client still sends one. We *don't* accept it for auth.
app.use((req, _res, next) => {
  if (req.query && req.query.apiKey) delete req.query.apiKey;
  next();
});

app.use(morgan(IS_PROD ? 'combined' : 'dev'));

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  max:      parseInt(process.env.RATE_LIMIT_MAX       || '100',   10),
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many requests, please slow down.' },
});
app.use(limiter);

const writeLimiter = rateLimit({
  windowMs: 60000,
  max: 20,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many write requests.' },
});

// ─── OIDC (optional) ──────────────────────────────────────────────────────
// When OIDC_ENABLED=true the library registers /login, /callback, /logout
// and decorates req.oidc on every request. It does NOT force authentication
// — the per-route middleware (requireRead/requireWrite) does that, which
// lets us emit JSON 401s for AJAX calls and HTML redirects for browsers.
if (OIDC_ENABLED) {
  const required = ['OIDC_ISSUER_BASE_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_BASE_URL', 'OIDC_SECRET'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error(`[OIDC] OIDC_ENABLED=true but missing env vars: ${missing.join(', ')}`);
    process.exit(1);
  }
  app.use(oidcAuth({
    authRequired:  false,
    auth0Logout:   false,
    issuerBaseURL: process.env.OIDC_ISSUER_BASE_URL,
    clientID:      process.env.OIDC_CLIENT_ID,
    clientSecret:  process.env.OIDC_CLIENT_SECRET,
    baseURL:       process.env.OIDC_BASE_URL,
    secret:        process.env.OIDC_SECRET,
    authorizationParams: {
      response_type: 'code',
      scope: ['openid', 'profile', 'email', OIDC_REQUIRED_GROUP ? 'groups' : null].filter(Boolean).join(' '),
    },
    routes: { login: '/login', logout: '/logout', callback: '/callback', postLogoutRedirect: '/' },
    session: { rolling: true, rollingDuration: 24 * 60 * 60 },
  }));
}

// ─── Auth helpers ─────────────────────────────────────────────────────────
function getUserId(req) {
  if (req.oidc && req.oidc.user) return req.oidc.user.sub || req.oidc.user.email || 'unknown';
  return 'apikey';
}

function userInGroup(req, group) {
  if (!group) return true;
  const claim = req.oidc && req.oidc.user && req.oidc.user[OIDC_GROUPS_CLAIM];
  if (Array.isArray(claim)) return claim.includes(group);
  if (typeof claim === 'string') return claim.split(/[,\s]+/).includes(group);
  return false;
}

function constantTimeKeyEq(provided) {
  const a = Buffer.from(String(provided));
  const b = Buffer.from(API_SECRET);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}

function checkApiKey(req, res) {
  const key = req.headers['x-api-key'];
  if (!key) {
    res.status(401).json({ error: 'Missing API key' });
    return false;
  }
  if (!constantTimeKeyEq(key)) {
    res.status(403).json({ error: 'Invalid API key' });
    return false;
  }
  return true;
}

function jsonOr(req) {
  // Treat as JSON client unless the Accept header preferred HTML.
  return req.accepts(['html', 'json']) !== 'html';
}

function requireRead(req, res, next) {
  if (OIDC_ENABLED) {
    if (req.oidc && req.oidc.isAuthenticated()) return next();
    if (jsonOr(req)) return res.status(401).json({ error: 'Not authenticated', login: '/login' });
    return res.oidc.login();
  }
  if (!checkApiKey(req, res)) return;
  next();
}

function requireWrite(req, res, next) {
  if (OIDC_ENABLED) {
    if (!req.oidc || !req.oidc.isAuthenticated()) {
      if (jsonOr(req)) return res.status(401).json({ error: 'Not authenticated', login: '/login' });
      return res.oidc.login();
    }
    if (OIDC_REQUIRED_GROUP && !userInGroup(req, OIDC_REQUIRED_GROUP)) {
      audit(req, 'write_denied', { reason: 'missing_group', requiredGroup: OIDC_REQUIRED_GROUP });
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    return next();
  }
  if (!checkApiKey(req, res)) return;
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
  const line = {
    ts:     new Date().toISOString(),
    user:   getUserId(req),
    action,
    ip:     req.ip,
    ...target,
  };
  console.log('[AUDIT]', JSON.stringify(line));
}

// ─── Routes ───────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Unauthenticated: lets the SPA discover auth mode without first triggering
// a redirect. Returns user identity if the caller is already logged in.
app.get('/api/auth/me', (req, res) => {
  const authed = !!(req.oidc && req.oidc.isAuthenticated());
  res.json({
    mode: OIDC_ENABLED ? 'oidc' : 'apikey',
    authenticated: authed || !OIDC_ENABLED,
    user: authed && req.oidc.user ? {
      sub:     req.oidc.user.sub,
      name:    req.oidc.user.name || req.oidc.user.email,
      email:   req.oidc.user.email,
      inGroup: OIDC_REQUIRED_GROUP ? userInGroup(req, OIDC_REQUIRED_GROUP) : null,
    } : null,
    requiredGroup: OIDC_REQUIRED_GROUP || null,
    loginUrl:  '/login',
    logoutUrl: '/logout',
  });
});

app.get('/api/security', requireRead, (req, res) => {
  res.json({
    runtime: {
      bindAddress:        BIND_ADDRESS,
      port:               PORT,
      allowedOrigin:      SERVE_STATIC ? 'same-origin (static)' : ALLOWED_ORIGIN,
      nodeEnv:            process.env.NODE_ENV || 'development',
      trustProxy:         app.get('trust proxy'),
      rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
        max:      parseInt(process.env.RATE_LIMIT_MAX       || '100',   10),
        writeMax: 20,
      },
      geoLookupEnabled:   GEO_ENABLED,
      useSudo:            process.env.USE_SUDO !== 'false',
      jsonBodyLimit:      '10kb',
      authMode:           OIDC_ENABLED ? 'oidc' : 'apikey',
      requiredGroup:      OIDC_ENABLED ? (OIDC_REQUIRED_GROUP || 'none') : null,
      servesStaticSPA:    SERVE_STATIC,
    },
    builtIn: [
      `Backend binds to ${BIND_ADDRESS}`,
      'Helmet security headers (XSS, HSTS, CSP, no-sniff)',
      SERVE_STATIC ? 'SPA + API same-origin (CORS not needed)' : 'CORS restricted to ALLOWED_ORIGIN',
      'Strict IP/CIDR validation on every ban/unban',
      'fail2ban commands built as argv arrays (no shell)',
      'WebSocket: origin check + per-connection auth on upgrade',
      'Auth tokens never travel in URLs or access logs',
      OIDC_ENABLED
        ? `OIDC authentication enforced${OIDC_REQUIRED_GROUP ? ` (writes require "${OIDC_REQUIRED_GROUP}" group)` : ''}`
        : 'API-key auth (constant-time comparison)',
      OIDC_ENABLED ? 'Audit log on every ban/unban' : 'Audit log on every ban/unban (apikey-attributed)',
    ],
    operatorMustVerify: [
      'TLS termination (reverse proxy with valid cert)',
      OIDC_ENABLED ? 'IdP redirect URI matches OIDC_BASE_URL + /callback' : 'OIDC enabled before exposing the dashboard beyond localhost',
      'Host firewall blocking inbound traffic to port ' + PORT,
      'fail2ban-client sudoers rule scoped to the four required verbs',
      'Read access to /var/log/fail2ban.log for the dashboard user',
    ],
  });
});

app.get('/api/status', requireRead, async (req, res) => {
  try {
    const ping = await f2b.ping();
    res.json(ping);
  } catch (e) { sendError(res, e); }
});

app.get('/api/jails', requireRead, async (req, res) => {
  try {
    const jails = await f2b.getAllJailStatuses();
    res.json({ jails });
  } catch (e) { sendError(res, e); }
});

app.get('/api/jails/:name',
  requireRead,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const jail = await f2b.getJailStatus(req.params.name);
      res.json(jail);
    } catch (e) { sendError(res, e); }
  }
);

app.post('/api/jails/:name/ban',
  requireWrite,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const { ip } = req.body;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const result = await f2b.banIP(req.params.name, ip);
      audit(req, 'ban', { jail: req.params.name, target: ip });
      res.json(result);
    } catch (e) {
      audit(req, 'ban_failed', { jail: req.params.name, target: ip, error: e.message });
      sendError(res, e);
    }
  }
);

app.delete('/api/jails/:name/ban/:ip',
  requireWrite,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const result = await f2b.unbanIP(req.params.name, ip);
      audit(req, 'unban', { jail: req.params.name, target: ip });
      res.json(result);
    } catch (e) {
      audit(req, 'unban_failed', { jail: req.params.name, target: ip, error: e.message });
      sendError(res, e);
    }
  }
);

app.get('/api/ip/:ip/details',
  requireRead,
  param('ip').isString().isLength({ min: 2, max: 45 }),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const details = await f2b.getIPDetails(ip);
      res.json(details);
    } catch (e) { sendError(res, e); }
  }
);

const geoCache = new Map();
app.get('/api/ip/:ip/geo',
  requireRead,
  param('ip').isString().isLength({ min: 2, max: 45 }),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    if (!GEO_ENABLED) return res.json({ disabled: true });
    const now = Date.now();
    const cached = geoCache.get(ip);
    if (cached && cached.expiry > now) return res.json(cached.data);
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

app.get('/api/reports', requireRead, async (req, res) => {
  try {
    const reports = await f2b.getReports();
    res.json(reports);
  } catch (e) { sendError(res, e); }
});

app.get('/api/config', requireRead, async (req, res) => {
  try {
    const config = await f2b.getGlobalConfig();
    res.json(config);
  } catch (e) { sendError(res, e); }
});

app.get('/api/logs',
  requireRead,
  query('filter').optional().isString().isLength({ max: 100 }).trim(),
  query('level').optional().isIn(['', 'BAN', 'UNBAN', 'WARNING']),
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const logs = await f2b.getLogs(req.query.filter || '', req.query.level || '');
      res.json({ logs });
    } catch (e) { sendError(res, e); }
  }
);

// ─── WebSocket ticket endpoint (OIDC mode only) ───────────────────────────
// In OIDC mode the browser doesn't hold the API secret. Instead it asks
// the backend (with its session cookie) for a one-shot ticket and uses that
// as the WS subprotocol value. Tickets expire after 60s and are deleted on
// first use.
const wsTickets = new Map(); // ticket -> expiry ms
const WS_TICKET_TTL = 60 * 1000;

app.post('/api/ws-ticket', requireRead, (req, res) => {
  // House-keep
  const now = Date.now();
  for (const [t, exp] of wsTickets) if (exp < now) wsTickets.delete(t);
  const ticket = crypto.randomBytes(24).toString('hex');
  wsTickets.set(ticket, now + WS_TICKET_TTL);
  res.json({ ticket, expiresIn: WS_TICKET_TTL / 1000 });
});

// ─── Static SPA serving (production) ──────────────────────────────────────
if (SERVE_STATIC) {
  console.log(`[static] Serving SPA from ${DIST_DIR}`);
  app.use(express.static(DIST_DIR, { maxAge: '1h', index: false }));
}

// ─── 404 + SPA fallback ───────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  if (SERVE_STATIC && req.method === 'GET') {
    return res.sendFile(path.join(DIST_DIR, 'index.html'));
  }
  next();
});

app.use((err, req, res, _next) => {
  sendError(res, err);
});

// ─── WebSocket for real-time log streaming ────────────────────────────────
const wss = new WebSocketServer({
  noServer: true,
  handleProtocols: () => WS_SUBPROTOCOL,
});

function rejectUpgrade(socket, status, reason) {
  console.warn(`[WS] Rejected: ${reason}`);
  socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws' && !req.url.startsWith('/ws?')) {
    return rejectUpgrade(socket, 404, 'Not Found');
  }
  // Origin check only applies when CORS is meaningful — in static-serving
  // mode the SPA shares an origin with the API so the origin is whatever the
  // operator's reverse proxy says.
  const origin = req.headers.origin;
  if (!SERVE_STATIC && origin && origin !== ALLOWED_ORIGIN) {
    return rejectUpgrade(socket, 403, 'Forbidden origin');
  }
  const offered = (req.headers['sec-websocket-protocol'] || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (offered.length !== 2 || offered[0] !== WS_SUBPROTOCOL) {
    return rejectUpgrade(socket, 401, 'Unauthorized');
  }

  let ok = false;
  if (OIDC_ENABLED) {
    const ticket = offered[1];
    const expiry = wsTickets.get(ticket);
    if (expiry && expiry >= Date.now()) {
      wsTickets.delete(ticket);
      ok = true;
    }
  } else {
    ok = constantTimeKeyEq(offered[1]);
  }
  if (!ok) return rejectUpgrade(socket, 403, 'Forbidden');

  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`[WS] Client connected. Total: ${clients.size}`);
  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[WS] Client disconnected. Total: ${clients.size}`);
  });
  ws.on('error', (err) => {
    console.error('[WS] Error:', err.message);
    clients.delete(ws);
  });
  sendStatusUpdate();
});

function broadcast(data) {
  const msg = JSON.stringify(data);
  clients.forEach(ws => { if (ws.readyState === ws.OPEN) ws.send(msg); });
}

async function sendStatusUpdate() {
  try {
    const [ping, jails] = await Promise.all([f2b.ping(), f2b.getAllJailStatuses()]);
    broadcast({ type: 'status', data: { daemon: ping, jails } });
  } catch (e) {
    broadcast({ type: 'error', message: 'status update failed' });
    console.error('[WS] status update failed:', e.message);
  }
}

const pollTimer = setInterval(() => {
  if (clients.size > 0) sendStatusUpdate();
}, 10000);

// ─── Start + graceful shutdown ────────────────────────────────────────────
server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`\n🛡  Fail2Ban Dashboard API`);
  console.log(`   Listening on http://${BIND_ADDRESS}:${PORT}`);
  console.log(`   Auth mode:    ${OIDC_ENABLED ? 'OIDC' + (OIDC_REQUIRED_GROUP ? ` (writes require "${OIDC_REQUIRED_GROUP}")` : '') : 'API key'}`);
  console.log(`   SPA serving:  ${SERVE_STATIC ? 'on (' + DIST_DIR + ')' : 'off'}`);
  console.log(`   Environment:  ${process.env.NODE_ENV || 'development'}\n`);
});

function shutdown(signal) {
  console.log(`\n[${signal}] Shutting down…`);
  clearInterval(pollTimer);
  wss.clients.forEach(ws => ws.terminate());
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
