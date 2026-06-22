/**
 * useApi.js — thin fetch wrapper
 *
 * Two auth modes are supported, selected by the backend:
 *   - 'apikey' (dev / single-user): X-API-Key header is sent on every call;
 *     WebSocket auth is the API key via Sec-WebSocket-Protocol.
 *   - 'oidc'   (production): the session cookie travels automatically;
 *     no header is sent. WebSocket auth uses a short-lived ticket obtained
 *     via POST /api/ws-ticket.
 *
 * On a 401 with `login` in the response body, the SPA navigates to that URL
 * to trigger the OIDC redirect flow.
 */

const API_KEY = import.meta.env.VITE_API_KEY || 'dev_secret_change_me'
const BASE    = '/api'
const WS_SUBPROTOCOL = 'fail2ban-api-key'

// Auth mode is discovered once at boot via /api/auth/me.
let _authMode = 'apikey'
export function setAuthMode(mode) { _authMode = (mode === 'oidc') ? 'oidc' : 'apikey' }
export function getAuthMode() { return _authMode }

async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }
  if (_authMode === 'apikey') headers['X-API-Key'] = API_KEY

  const res = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    ...options,
    headers,
  })

  if (res.status === 401) {
    const body = await res.json().catch(() => ({}))
    if (body.login) {
      window.location.href = body.login
      throw new Error('Redirecting to login')
    }
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  me:        ()              => apiFetch('/auth/me'),
  status:    ()              => apiFetch('/status'),
  jails:     ()              => apiFetch('/jails'),
  jail:      (name)          => apiFetch(`/jails/${encodeURIComponent(name)}`),
  banIP:     (jail, ip)      => apiFetch(`/jails/${encodeURIComponent(jail)}/ban`,
                                 { method: 'POST', body: JSON.stringify({ ip }) }),
  unbanIP:   (jail, ip)      => apiFetch(`/jails/${encodeURIComponent(jail)}/ban/${encodeURIComponent(ip)}`,
                                 { method: 'DELETE' }),
  logs:      (filter, level) => apiFetch(`/logs?filter=${encodeURIComponent(filter || '')}&level=${encodeURIComponent(level || '')}`),
  reports:   ()              => apiFetch('/reports'),
  config:    ()              => apiFetch('/config'),
  security:  ()              => apiFetch('/security'),
  ipDetails: (ip)            => apiFetch(`/ip/${encodeURIComponent(ip)}/details`),
  ipGeo:     (ip)            => apiFetch(`/ip/${encodeURIComponent(ip)}/geo`),
  wsTicket:  ()              => apiFetch('/ws-ticket', { method: 'POST' }),
}

export async function createWebSocket(onMessage, onError) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const secret = _authMode === 'oidc'
    ? (await api.wsTicket()).ticket
    : API_KEY
  const ws = new WebSocket(`${proto}//${window.location.host}/ws`, [WS_SUBPROTOCOL, secret])
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onerror   = onError
  ws.onclose   = () => console.log('[WS] Connection closed')
  return ws
}
