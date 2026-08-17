/**
 * useApi.js — thin fetch wrapper. The dashboard talks to ONE thing: the hub.
 *
 * The hub is the only web-facing service in this architecture. Agents run on
 * the monitored servers with no UI, and the browser never contacts them
 * directly — every server-scoped call goes to /api/servers/<id>/… and the hub
 * proxies it to that agent using the agent's own key, held server-side.
 *
 * Auth: X-API-Key carries HUB_API_SECRET, baked into this bundle at build
 * time. Whoever can load the page holds it — the hub is meant to be reached
 * over an SSH tunnel, not published.
 *
 * There is no WebSocket. Live updates are polled, so that N open tabs cost the
 * fleet a bounded, shared number of queries: the hub caches and coalesces its
 * fan-out, and each agent caches its own fail2ban reads.
 */

const API_KEY = import.meta.env.VITE_API_KEY || 'dev_hub_secret_change_me'
const BASE    = '/api'

let _serverId = null       // which server the server-scoped calls target

export function setServer(id) { _serverId = id || null }
export function getServer()   { return _serverId }

// Server-scoped paths always route through the hub. Calling one with no server
// selected is a caller bug, not a request worth sending.
function scoped(path) {
  if (!_serverId) throw new Error('No server selected')
  return `/servers/${encodeURIComponent(_serverId)}${path}`
}

async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
    ...(options.headers || {}),
  }

  const res = await fetch(`${BASE}${path}`, { credentials: 'same-origin', ...options, headers })

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // ── hub-level (no server scope) ──
  mode:      ()              => apiFetch('/mode'),
  servers:   ()              => apiFetch('/servers'),
  overview:  ()              => apiFetch('/overview'),

  // ── server-scoped (proxied by the hub to one agent) ──
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
}
