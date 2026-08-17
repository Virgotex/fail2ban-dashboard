/**
 * cache.js — tiny TTL cache with in-flight coalescing.
 *
 * The agent is polled continuously by the hub (and the hub by every open
 * browser tab). Without this, each poll would spawn one `fail2ban-client`
 * process per jail and re-read the tail of fail2ban.log — on a busy box with
 * a dozen jails that's real load, repeated forever.
 *
 * Two properties matter here:
 *   1. TTL      — a result is reused for ttlMs, so poll frequency is decoupled
 *                 from how often we actually touch fail2ban.
 *   2. Coalesce — concurrent callers for the same key share ONE in-flight
 *                 promise, so a burst of requests can't stampede the daemon.
 *
 * Writes (ban/unban) call invalidate() so the next read is fresh.
 */

const store    = new Map();   // key -> { expiry, value }
const inflight = new Map();   // key -> Promise

// Bound the store so per-IP keys can't grow without limit on a long-running
// process. Well above the number of live keys any real dashboard produces.
const MAX_ENTRIES = 500;

function sweep() {
  const now = Date.now();
  for (const [k, v] of store) if (v.expiry <= now) store.delete(k);
  if (store.size > MAX_ENTRIES) {
    // Oldest-inserted first — Map preserves insertion order.
    const excess = store.size - MAX_ENTRIES;
    let i = 0;
    for (const k of store.keys()) { if (i++ >= excess) break; store.delete(k); }
  }
}

/**
 * Return a cached value for `key`, or compute it with `fn`.
 * ttlMs <= 0 disables caching entirely (pass-through).
 */
function cached(key, ttlMs, fn) {
  if (!(ttlMs > 0)) return Promise.resolve().then(fn);

  const hit = store.get(key);
  if (hit && hit.expiry > Date.now()) return Promise.resolve(hit.value);

  const pending = inflight.get(key);
  if (pending) return pending;

  const p = Promise.resolve().then(fn)
    .then(value => {
      store.set(key, { expiry: Date.now() + ttlMs, value });
      if (store.size > MAX_ENTRIES) sweep();
      return value;
    })
    .finally(() => inflight.delete(key));

  inflight.set(key, p);
  return p;
}

/** Drop every cached entry whose key starts with `prefix`. */
function invalidate(prefix) {
  for (const k of store.keys()) if (k.startsWith(prefix)) store.delete(k);
}

function stats() {
  return { entries: store.size, inflight: inflight.size };
}

module.exports = { cached, invalidate, stats };
