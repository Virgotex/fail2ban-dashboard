/**
 * server.js — Fail2Ban Dashboard Backend
 *
 * Security layers applied:
 *   1. Helmet — sets secure HTTP headers (XSS, HSTS, no-sniff, etc.)
 *   2. CORS   — only your frontend origin is allowed
 *   3. Rate limiting — 100 req/min per IP by default
 *   4. Input validation on every route that accepts parameters
 *   5. No shell interpolation — all fail2ban commands built as arg arrays
 *   6. WebSocket upgrade restricted to same-origin token holders
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const morgan     = require('morgan');
const http       = require('http');
const { WebSocketServer } = require('ws');
const { query, param, validationResult } = require('express-validator');
const crypto     = require('crypto');

const f2b = require('./fail2banClient');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 3001;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';
const API_SECRET     = process.env.API_SECRET || 'dev_secret_change_me';

// ─── Security Middleware ──────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'", 'ws://localhost:3001'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: false,
}));

app.use(express.json({ limit: '10kb' })); // prevent oversized payloads

app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  max:      parseInt(process.env.RATE_LIMIT_MAX       || '100',   10),
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many requests, please slow down.' },
});
app.use(limiter);

// Stricter limiter for write operations
const writeLimiter = rateLimit({
  windowMs: 60000,
  max: 20,
  message: { error: 'Too many write requests.' },
});

// ─── Simple API key auth middleware ───────────────────────────────────────
// In production swap this for proper JWT / OIDC
function requireAuth(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.apiKey;
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  // Constant-time comparison to prevent timing attacks
  const provided = Buffer.from(String(key));
  const expected = Buffer.from(API_SECRET);
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  next();
}

// ─── Validation helper ────────────────────────────────────────────────────
function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() });
    return false;
  }
  return true;
}

// ─── Routes ───────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Ping fail2ban daemon
app.get('/api/status', requireAuth, async (req, res) => {
  try {
    const ping = await f2b.ping();
    res.json(ping);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// All jails summary
app.get('/api/jails', requireAuth, async (req, res) => {
  try {
    const jails = await f2b.getAllJailStatuses();
    res.json({ jails });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Single jail status
app.get('/api/jails/:name',
  requireAuth,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const jail = await f2b.getJailStatus(req.params.name);
      res.json(jail);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Ban an IP
app.post('/api/jails/:name/ban',
  requireAuth,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const { ip } = req.body;
    if (!f2b.validateIP(ip)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }
    try {
      const result = await f2b.banIP(req.params.name, ip);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Unban an IP
app.delete('/api/jails/:name/ban/:ip',
  requireAuth,
  writeLimiter,
  param('name').matches(/^[a-zA-Z0-9_-]{1,64}$/),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }
    try {
      const result = await f2b.unbanIP(req.params.name, ip);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Full IP investigation — log timeline + jail history
app.get('/api/ip/:ip/details',
  requireAuth,
  param('ip').isString().isLength({ min: 2, max: 45 }),
  async (req, res) => {
    if (!validate(req, res)) return;
    const ip = req.params.ip;
    if (!f2b.validateIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    try {
      const details = await f2b.getIPDetails(ip);
      res.json(details);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Reports — parsed from real log file, no mock data
app.get('/api/reports', requireAuth, async (req, res) => {
  try {
    const reports = await f2b.getReports();
    res.json(reports);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Global config
app.get('/api/config', requireAuth, async (req, res) => {
  try {
    const config = await f2b.getGlobalConfig();
    res.json(config);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Read logs
app.get('/api/logs',
  requireAuth,
  query('filter').optional().isString().isLength({ max: 100 }).trim().escape(),
  query('level').optional().isIn(['', 'BAN', 'UNBAN', 'WARNING']),
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const logs = await f2b.getLogs(req.query.filter || '', req.query.level || '');
      res.json({ logs });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// ─── WebSocket for real-time log streaming ───────────────────────────────
const wss = new WebSocketServer({ server, path: '/ws' });

// Track connected clients
const clients = new Set();

wss.on('connection', (ws, req) => {
  // Origin check — only allow connections from the frontend
  const origin = req.headers.origin;
  if (origin && origin !== ALLOWED_ORIGIN) {
    ws.terminate();
    console.warn(`[WS] Rejected connection from disallowed origin: ${origin}`);
    return;
  }

  // API key check via query param
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const key = url.searchParams.get('apiKey');
  if (!key || key !== API_SECRET) {
    ws.terminate();
    console.warn('[WS] Rejected unauthenticated WebSocket connection');
    return;
  }

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

  // Send initial status burst
  sendStatusUpdate();
});

// Broadcast helpers
function broadcast(data) {
  const msg = JSON.stringify(data);
  clients.forEach(ws => {
    if (ws.readyState === ws.OPEN) ws.send(msg);
  });
}

async function sendStatusUpdate() {
  try {
    const [ping, jails] = await Promise.all([f2b.ping(), f2b.getAllJailStatuses()]);
    broadcast({ type: 'status', data: { daemon: ping, jails } });
  } catch (e) {
    broadcast({ type: 'error', message: e.message });
  }
}

// Poll for updates every 10 seconds if anyone is connected
setInterval(() => {
  if (clients.size > 0) sendStatusUpdate();
}, 10000);

// ─── 404 / error handlers ─────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────
server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n🛡  Fail2Ban Dashboard API`);
  console.log(`   Listening on http://127.0.0.1:${PORT}`);
  console.log(`   Allowed origin: ${ALLOWED_ORIGIN}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}\n`);
});
