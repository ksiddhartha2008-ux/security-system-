import { tooMany } from './http.js';
import { memoryStore, RateLimitStoreError } from './ratelimitStore.js';

/**
 * Shared rate limiter.
 *
 * Identity is the authenticated user when there is one, otherwise the client IP
 * as resolved by Express (which honours SF_TRUST_PROXY). A policy can override
 * that with `key(req)` for API keys or organization scoped buckets.
 *
 * The counter lives in the configured store. When the store fails:
 * - `failMode: 'local'` (default) falls back to a bounded in-process bucket, so a
 *   single instance still limits the caller and the outage is visible in the
 *   RateLimit-Store header.
 * - `failMode: 'closed'` refuses the request with 503 for policies where an
 *   unlimited window is worse than an outage (login, MFA, registration).
 */
let activeStore = memoryStore();
let fallbackStore = memoryStore({ maxKeys: 5000 });

export function setRateLimitStore(store) {
  activeStore = store ?? memoryStore();
}

export function getRateLimitStore() {
  return activeStore;
}

export function resetLimits() {
  activeStore.reset?.();
  fallbackStore = memoryStore({ maxKeys: 5000 });
}

export function rateLimit({
  windowMs = 60_000,
  max = 100,
  keyPrefix = 'default',
  message,
  key,
  failMode = process.env.SF_RATE_LIMIT_FAIL_MODE === 'closed' ? 'closed' : 'local',
  store = null,
  skip,
} = {}) {
  return async (req, res, next) => {
    if (skip?.(req)) return next();
    const identity = key
      ? key(req)
      : req.user?.id
        ? `user:${req.user.id}`
        : `ip:${req.ip ?? req.socket?.remoteAddress ?? 'unknown'}`;
    if (!identity) return next();
    const bucketKey = `${keyPrefix}:${identity}`;
    const now = Date.now();
    let outcome;
    let degraded = false;

    try {
      outcome = await (store ?? activeStore).hit(bucketKey, windowMs);
    } catch (err) {
      if (!(err instanceof RateLimitStoreError)) throw err;
      if (failMode === 'closed') {
        res.setHeader('Retry-After', '5');
        return next(Object.assign(new Error('Rate limiting is temporarily unavailable'), {
          status: 503, code: 'rate_limit_unavailable',
        }));
      }
      degraded = true;
      outcome = await fallbackStore.hit(bucketKey, windowMs);
    }

    const resetSeconds = Math.max(0, Math.ceil((outcome.resetAt - now) / 1000));
    const remaining = Math.max(0, max - outcome.count);
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(resetSeconds));
    res.setHeader('RateLimit-Policy', `${max};w=${Math.ceil(windowMs / 1000)}`);
    if (degraded) res.setHeader('RateLimit-Store', 'local-fallback');

    if (outcome.count > max) {
      res.setHeader('Retry-After', String(resetSeconds || 1));
      return next(tooMany(message ?? `Too many requests. Try again in ${resetSeconds || 1} seconds.`));
    }
    return next();
  };
}
