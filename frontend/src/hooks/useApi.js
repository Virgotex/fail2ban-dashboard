/**
 * useApi.js — thin fetch wrapper, works against a single-server agent OR a hub.
 *
 * Context is detected once at boot via GET /api/mode:
 *   - Hub responds { mode: 'hub' } → server-scoped calls are routed through
 *     /api/servers/<id>/… and the hub fans out to each agent.
 *   - A single-server agent has no /api/mode (404) → we fall back to its
 *     /api/auth/me contract and talk to /api/… directly, exactly as before.
 *
 * Auth: the X-API-Key header carries whatever secret matches the server that
 * built + served this bundle (the agent's API_SECRET in single mode, the
 * HUB_API_SECRET in hub mode). WebSocket live-updates exist only in
 * single-server apikey mode; the hub uses polling.
 */

const API_KEY = import.meta.env.VITE_API_KEY || 'dev_secret_change_me'
const BASE    = '/api'
const WS_SUBPROTOCOL = 'fail2ban-api-key'

let _mode     = 'single'   // 'single' | 'hub'
let _authMode = 'apikey'   // single-server only: 'apikey' | 'oidc'
let _serverId = null       // hub only: which server server-scoped calls target

export function getMode()   { return _mode }
export function setMode(m)  { _mode = (m === 'hub') ? 'hub' : 'single' }
export function setAuthMode(mode) { _authMode = (mode === 'oidc') ? 'oidc' : 'apikey' }
export function getAuthMode() { return _authMode }
export function setServer(id) { _serverId = id || null }
export function getServer()   { return _serverId }

// Route a server-scoped path through the hub when we're in hub mode with a
// selected server; otherwise hit the path directly.
function scoped(path) {
  if (_mode === 'hub' && _serverId) return `/servers/${encodeURIComponent(_serverId)}${path}`
  return path
}

async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  if (_authMode === 'apikey') headers['X-API-Key'] = API_KEY

  const res = await fetch(`${BASE}${path}`, { credentials: 'same-origin', ...options, headers })

  if (res.status === 401) {
    const body = await res.json().catch(() => ({}))
    if (body.login) { window.location.href = body.login; throw new Error('Redirecting to login') }
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json()
}

// Detect whether we're behind a hub. Never throws — defaults to single-server.
export async function detectMode() {
  try {
    const res = await fetch(`${BASE}/mode`, { credentials: 'same-origin' })
    if (res.ok) {
      const data = await res.json().catch(() => ({}))
      if (data.mode === 'hub') { _mode = 'hub'; return 'hub' }
    }
  } catch { /* fall through */ }
  _mode = 'single'
  return 'single'
}

export const api = {
  // ── hub-level (no server scope) ──
  servers:   ()              => apiFetch('/servers'),
  overview:  ()              => apiFetch('/overview'),

  // ── single-server discovery ──
  me:        ()              => apiFetch('/auth/me'),

  // ── server-scoped (routed via hub when applicable) ──
  status:    ()              => apiFetch(scoped('/status')),
  jails:     ()              => apiFetch(scoped('/jails')),
  jail:      (name)          => apiFetch(scoped(`/jails/${encodeURIComponent(name)}`)),
  banIP:     (jail, ip)      => apiFetch(scoped(`/jails/${encodeURIComponent(jail)}/ban`),
                                 { method: 'POST', body: JSON.stringify({ ip }) }),
  unbanIP:   (jail, ip)      => apiFetch(scoped(`/jails/${encodeURIComponent(jail)}/ban/${encodeURIComponent(ip)}`),
                                 { method: 'DELETE' }),
  logs:      (filter, level) => apiFetch(scoped(`/logs?filter=${encodeURIComponent(filter || '')}&level=${encodeURIComponent(level || '')}`)),
  reports:   ()              => apiFetch(scoped('/reports')),
  config:    ()              => apiFetch(scoped('/config')),
  security:  ()              => apiFetch(scoped('/security')),
  ipDetails: (ip)            => apiFetch(scoped(`/ip/${encodeURIComponent(ip)}/details`)),
  ipGeo:     (ip)            => apiFetch(scoped(`/ip/${encodeURIComponent(ip)}/geo`)),
  wsTicket:  ()              => apiFetch('/ws-ticket', { method: 'POST' }),
}

export async function createWebSocket(onMessage, onError) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const secret = _authMode === 'oidc' ? (await api.wsTicket()).ticket : API_KEY
  const ws = new WebSocket(`${proto}//${window.location.host}/ws`, [WS_SUBPROTOCOL, secret])
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onerror   = onError
  ws.onclose   = () => console.log('[WS] Connection closed')
  return ws
}
