import { tooMany } from './http.js';

const buckets = new Map();

/** Small in-memory limiter. Good enough for a single node process; swap for Redis when scaling out. */
export function rateLimit({ windowMs, max, keyPrefix = '', message }) {
  return (req, _res, next) => {
    const identity = req.user?.id ?? req.ip ?? 'anonymous';
    const key = `${keyPrefix}:${identity}`;
    const now = Date.now();
    let entry = buckets.get(key);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      buckets.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      return next(tooMany(message ?? `Too many requests. Try again in ${Math.ceil((entry.resetAt - now) / 1000)} seconds.`));
    }
    if (buckets.size > 5000) {
      for (const [k, v] of buckets) if (now > v.resetAt) buckets.delete(k);
    }
    return next();
  };
}

export function resetLimits() {
  buckets.clear();
}
