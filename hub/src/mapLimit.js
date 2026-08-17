/**
 * mapLimit — run `fn` over `items` with at most `limit` in flight.
 *
 * The fleet fan-out uses this so that adding servers doesn't mean hitting the
 * whole estate at once: with 40 agents and a limit of 4, the hub walks the
 * fleet in waves instead of opening 40 simultaneous connections and waking
 * every monitored box in the same instant.
 *
 * Results keep input order. This never rejects — callers pass a `fn` that
 * absorbs its own errors (see summariseServer).
 */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

module.exports = { mapLimit };
