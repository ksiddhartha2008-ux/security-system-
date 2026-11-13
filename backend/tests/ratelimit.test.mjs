import test from 'node:test';
import assert from 'node:assert/strict';
import { rateLimit, setRateLimitStore, resetLimits } from '../src/lib/ratelimit.js';
import { memoryStore, RateLimitStoreError } from '../src/lib/ratelimitStore.js';

function harness({ user = null, ip = '203.0.113.10', headers = {} } = {}) {
  const res = {
    headers: {},
    setHeader(name, value) { this.headers[name] = String(value); },
    getHeader(name) { return this.headers[name]; },
  };
  const req = { user, ip, headers, socket: { remoteAddress: ip } };
  const run = (middleware) => new Promise((resolve) => {
    middleware(req, res, (err) => resolve({ err, res }));
  });
  return { req, res, run };
}

test('allows requests up to the limit and refuses the next one with a retry hint', async () => {
  resetLimits();
  const limiter = rateLimit({ windowMs: 60_000, max: 2, keyPrefix: 'unit-basic' });
  const { run } = harness();
  assert.equal((await run(limiter)).err, undefined);
  const second = await run(limiter);
  assert.equal(second.err, undefined);
  assert.equal(second.res.headers['RateLimit-Limit'], '2');
  assert.equal(second.res.headers['RateLimit-Remaining'], '0');
  const third = await run(limiter);
  assert.equal(third.err?.status, 429);
  assert.equal(third.err?.code, 'rate_limited');
  assert.ok(Number(third.res.headers['Retry-After']) >= 1);
});

test('authenticated users get separate buckets even behind one IP', async () => {
  resetLimits();
  const limiter = rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'unit-users' });
  const one = harness({ user: { id: 'usr_one' }, ip: '198.51.100.7' });
  const two = harness({ user: { id: 'usr_two' }, ip: '198.51.100.7' });
  assert.equal((await one.run(limiter)).err, undefined);
  assert.equal((await two.run(limiter)).err, undefined);
  assert.equal((await one.run(limiter)).err?.status, 429, 'the first user is limited independently');
});

test('a custom key isolates API keys from user and IP buckets', async () => {
  resetLimits();
  const limiter = rateLimit({
    windowMs: 60_000, max: 1, keyPrefix: 'unit-api-key', key: (req) => `key:${req.headers['x-api-key']}`,
  });
  const first = harness({ headers: { 'x-api-key': 'a' } });
  const second = harness({ headers: { 'x-api-key': 'b' } });
  assert.equal((await first.run(limiter)).err, undefined);
  assert.equal((await second.run(limiter)).err, undefined);
  assert.equal((await first.run(limiter)).err?.status, 429);
});

test('two app instances that share one store enforce one combined limit', async () => {
  const shared = memoryStore();
  const instanceA = rateLimit({ windowMs: 60_000, max: 2, keyPrefix: 'unit-shared', store: shared });
  const instanceB = rateLimit({ windowMs: 60_000, max: 2, keyPrefix: 'unit-shared', store: shared });
  const caller = harness({ user: { id: 'usr_shared' } });
  assert.equal((await caller.run(instanceA)).err, undefined);
  assert.equal((await caller.run(instanceB)).err, undefined);
  const third = await caller.run(instanceA);
  assert.equal(third.err?.status, 429, 'switching instances does not reset the counter');
});

test('the window expires and the caller is allowed again', async () => {
  resetLimits();
  const limiter = rateLimit({ windowMs: 40, max: 1, keyPrefix: 'unit-expiry' });
  const caller = harness();
  assert.equal((await caller.run(limiter)).err, undefined);
  assert.equal((await caller.run(limiter)).err?.status, 429);
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal((await caller.run(limiter)).err, undefined);
});

test('a store outage falls back to a bounded local bucket instead of removing the limit', async () => {
  resetLimits();
  const broken = {
    kind: 'redis',
    async hit() { throw new RateLimitStoreError('connection refused'); },
  };
  const limiter = rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'unit-degraded', store: broken, failMode: 'local' });
  const caller = harness({ user: { id: 'usr_degraded' } });
  assert.equal((await caller.run(limiter)).err, undefined);
  const second = await caller.run(limiter);
  assert.equal(second.err?.status, 429, 'the local fallback keeps enforcing the limit');
  assert.equal(second.res.headers['RateLimit-Store'], 'local-fallback');
});

test('fail closed refuses the request when the shared store is unavailable', async () => {
  resetLimits();
  const broken = {
    kind: 'redis',
    async hit() { throw new RateLimitStoreError('connection refused'); },
  };
  const limiter = rateLimit({ windowMs: 60_000, max: 5, keyPrefix: 'unit-closed', store: broken, failMode: 'closed' });
  const caller = harness();
  const outcome = await caller.run(limiter);
  assert.equal(outcome.err?.status, 503);
  assert.equal(outcome.err?.code, 'rate_limit_unavailable');
});

test('reset clears every counter for the active store', async () => {
  resetLimits();
  setRateLimitStore(memoryStore());
  const limiter = rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'unit-reset' });
  const caller = harness();
  assert.equal((await caller.run(limiter)).err, undefined);
  assert.equal((await caller.run(limiter)).err?.status, 429);
  resetLimits();
  assert.equal((await caller.run(limiter)).err, undefined);
});
