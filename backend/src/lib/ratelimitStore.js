/**
 * Rate limit stores.
 *
 * The limiter needs one atomic operation: increment a counter for a key inside a
 * window and report when the window ends. The memory store serves a single
 * process. The Redis store makes the same decision across every instance that
 * points at the same Redis database.
 *
 * Key naming is explicit and namespaced: `${prefix}${policy}:${identity}`.
 */
import { createClient } from 'redis';

const EVAL_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {current, redis.call('PTTL', KEYS[1])}
`;

export class RateLimitStoreError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'RateLimitStoreError';
    this.cause = cause;
  }
}

/** Bounded in-process store. Also used as the fallback when Redis is unavailable. */
export function memoryStore({ maxKeys = 10_000 } = {}) {
  const buckets = new Map();
  return {
    kind: 'memory',
    async hit(key, windowMs) {
      const now = Date.now();
      let entry = buckets.get(key);
      if (!entry || now >= entry.resetAt) {
        entry = { count: 0, resetAt: now + windowMs };
        buckets.set(key, entry);
      }
      entry.count += 1;
      if (buckets.size > maxKeys) {
        for (const [candidate, value] of buckets) {
          if (now >= value.resetAt) buckets.delete(candidate);
        }
        // Still full of live keys: drop the oldest insert to keep memory bounded.
        if (buckets.size > maxKeys) buckets.delete(buckets.keys().next().value);
      }
      return { count: entry.count, resetAt: entry.resetAt };
    },
    async reset() { buckets.clear(); },
    async close() { buckets.clear(); },
    size: () => buckets.size,
  };
}

/**
 * Redis store. One EVAL keeps increment and expiry in a single round trip, so two
 * instances cannot both decide that they own the first increment.
 */
export function redisStore({ url, prefix = 'sf:ratelimit:', client: provided = null, connectTimeoutMs = 2000 } = {}) {
  let client = provided;
  let connecting = null;

  const build = () => createClient({
    url,
    socket: {
      connectTimeout: connectTimeoutMs,
      reconnectStrategy: (retries) => Math.min(50 * 2 ** retries, 2000),
    },
  });

  async function getClient() {
    if (!client) client = build();
    if (client.isOpen) return client;
    if (!connecting) {
      client.on('error', () => { /* the limiter reports failures per request */ });
      connecting = client.connect().finally(() => { connecting = null; });
    }
    await connecting;
    return client;
  }

  return {
    kind: 'redis',
    async hit(key, windowMs) {
      try {
        const active = await getClient();
        const reply = await active.eval(EVAL_SCRIPT, {
          keys: [`${prefix}${key}`],
          arguments: [String(windowMs)],
        });
        const count = Number(reply?.[0] ?? 0);
        const ttl = Number(reply?.[1] ?? -1);
        return { count, resetAt: Date.now() + (ttl > 0 ? ttl : windowMs) };
      } catch (err) {
        throw new RateLimitStoreError(`Redis rate limit store failed: ${err.message}`, err);
      }
    },
    async reset() {
      if (!client?.isOpen) return;
      try {
        const keys = await client.keys(`${prefix}*`);
        if (keys.length) await client.del(keys);
      } catch { /* reset is best effort */ }
    },
    async close() {
      if (client?.isOpen) await client.quit().catch(() => {});
    },
    ping: async () => {
      const active = await getClient();
      return active.ping();
    },
  };
}

/** Choose the store once at startup. Redis only when a URL is configured. */
export function createRateLimitStore(env = process.env) {
  if (env.SF_REDIS_URL) {
    return redisStore({ url: env.SF_REDIS_URL, prefix: env.SF_RATE_LIMIT_PREFIX || 'sf:ratelimit:' });
  }
  return memoryStore();
}
