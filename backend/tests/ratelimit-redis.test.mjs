import test from 'node:test';
import assert from 'node:assert/strict';
import { redisStore } from '../src/lib/ratelimitStore.js';
import { rateLimit } from '../src/lib/ratelimit.js';

const url = process.env.SF_REDIS_URL;
const prefix = `sf:test:${Date.now()}:`;

/**
 * Runs only when a Redis server is configured. CI starts one and sets
 * SF_REDIS_URL; a local run without Redis skips instead of failing.
 */
test('two limiter instances share one Redis counter', { skip: !url && 'SF_REDIS_URL is not set' }, async () => {
  const storeA = redisStore({ url, prefix });
  const storeB = redisStore({ url, prefix });
  try {
    const limiterA = rateLimit({ windowMs: 30_000, max: 3, keyPrefix: 'shared', store: storeA });
    const limiterB = rateLimit({ windowMs: 30_000, max: 3, keyPrefix: 'shared', store: storeB });
    const req = { user: { id: 'usr_redis_test' }, ip: '203.0.113.20', headers: {} };
    const res = { headers: {}, setHeader(k, v) { this.headers[k] = String(v); }, getHeader(k) { return this.headers[k]; } };
    const call = (middleware) => new Promise((resolve) => { middleware(req, res, (err) => resolve(err)); });

    assert.equal(await call(limiterA), undefined);
    assert.equal(await call(limiterB), undefined);
    assert.equal(await call(limiterA), undefined);
    const fourth = await call(limiterB);
    assert.equal(fourth?.status, 429, 'the fourth request is refused no matter which instance answers');
    assert.ok(Number(res.headers['Retry-After']) >= 1);
  } finally {
    await storeA.reset();
    await storeA.close();
    await storeB.close();
  }
});

test('the Redis store expires a window and reports a TTL', { skip: !url && 'SF_REDIS_URL is not set' }, async () => {
  const store = redisStore({ url, prefix: `${prefix}ttl:` });
  try {
    const first = await store.hit('key', 1200);
    assert.equal(first.count, 1);
    assert.ok(first.resetAt > Date.now());
    const second = await store.hit('key', 1200);
    assert.equal(second.count, 2);
    await new Promise((resolve) => setTimeout(resolve, 1400));
    const third = await store.hit('key', 1200);
    assert.equal(third.count, 1, 'the counter restarts after the window');
  } finally {
    await store.reset();
    await store.close();
  }
});
