/**
 * useApi.js — thin fetch wrapper
 * All requests automatically attach the API key from the environment.
 * The key comes from VITE_API_KEY in frontend/.env.local (gitignored).
 */

const API_KEY = import.meta.env.VITE_API_KEY || 'dev_secret_change_me'
const BASE    = '/api'

async function apiFetch(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...(options.headers || {}),
    },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  status:  ()              => apiFetch('/status'),
  jails:   ()              => apiFetch('/jails'),
  jail:    (name)          => apiFetch(`/jails/${encodeURIComponent(name)}`),
  banIP:   (jail, ip)      => apiFetch(`/jails/${encodeURIComponent(jail)}/ban`,
                               { method: 'POST', body: JSON.stringify({ ip }) }),
  unbanIP: (jail, ip)      => apiFetch(`/jails/${encodeURIComponent(jail)}/ban/${encodeURIComponent(ip)}`,
                               { method: 'DELETE' }),
  logs:    (filter, level) => apiFetch(`/logs?filter=${encodeURIComponent(filter || '')}&level=${encodeURIComponent(level || '')}`),
  reports: ()              => apiFetch('/reports'),
  config:  ()              => apiFetch('/config'),
  ipDetails: (ip)          => apiFetch(`/ip/${encodeURIComponent(ip)}/details`),
}

export function createWebSocket(onMessage, onError) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${window.location.host}/ws?apiKey=${API_KEY}`)
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onerror   = onError
  ws.onclose   = () => console.log('[WS] Connection closed')
  return ws
}
