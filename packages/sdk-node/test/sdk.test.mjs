import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { inspect } from 'node:util';
import { SecureFlow } from '../src/index.js';

const KEY = `sfk_abcdefghijkl_${'A'.repeat(43)}`;
const PEPPER = 'a-test-pepper-with-enough-bytes';

async function startIngest(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let parsed = null;
      try { parsed = JSON.parse(body); } catch { parsed = null; }
      requests.push({ headers: req.headers, body: parsed, raw: body });
      const decision = handler ? handler(requests.length, req, res) : { status: 202, body: { accepted: 1, duplicates: 0, rejected: [], dropped_fields: 0 } };
      res.writeHead(decision.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(decision.body ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    endpoint: `http://127.0.0.1:${port}/v1/ingest/website-events`,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const makeSdk = (endpoint, overrides = {}) => new SecureFlow({
  apiKey: KEY,
  endpoint,
  actorPepper: PEPPER,
  allowInsecureEndpoint: true,
  flushIntervalMs: 3_600_000,
  heartbeatIntervalMs: 3_600_000,
  retryBaseMs: 5,
  maxRetryAttempts: 2,
  ...overrides,
});

test('construction rejects unsafe configuration', () => {
  assert.throws(() => new SecureFlow({ apiKey: 'nope', endpoint: 'https://example.com', actorPepper: PEPPER }), /apiKey/);
  assert.throws(() => new SecureFlow({ apiKey: KEY, endpoint: 'http://example.com', actorPepper: PEPPER }), /https/);
  assert.throws(() => new SecureFlow({ apiKey: KEY, endpoint: 'https://example.com', actorIdMode: 'hash', actorPepper: 'short' }), /actorPepper/);
  assert.throws(() => new SecureFlow({ apiKey: KEY, endpoint: 'https://example.com', actorIdMode: 'weird', actorPepper: PEPPER }), /actorIdMode/);
  const sdk = makeSdk('http://127.0.0.1:9/x');
  assert.equal(sdk.queued, 0);
  void sdk.shutdown({ timeoutMs: 10 });
});

test('track sends a validated envelope and strips unsafe input', async () => {
  const ingest = await startIngest();
  const sdk = makeSdk(ingest.endpoint);
  sdk.track({
    type: 'auth.login_failed',
    actor: { id: 'victim@example.com' },
    client: { ip: '203.0.113.45', user_agent: 'Mozilla/5.0\u0000evil' },
    request: { host: 'SHOP.example.com', method: 'POST', path: '/login?next=/admin#frag', status: 401 },
    attributes: { reason: 'bad_password', password: 'never-send-this', nested: { a: 1 } },
    body: { secret: 'never-send-this-either' },
  });
  await sdk.flush();
  assert.equal(ingest.requests.length, 1);
  const [request] = ingest.requests;
  assert.equal(request.headers.authorization, `Bearer ${KEY}`);
  assert.equal(request.body.schema_version, 1);
  assert.equal(request.body.sdk.name, 'secureflow-sdk-node');
  const [event] = request.body.events;
  assert.match(event.event_id, /^[0-9a-f-]{36}$/);
  assert.equal(event.request.path, '/login');
  assert.equal(event.request.host, 'shop.example.com');
  assert.equal(event.client.user_agent, 'Mozilla/5.0evil');
  assert.equal(event.attributes.password, undefined);
  assert.equal(event.attributes.nested, undefined);
  assert.equal(event.attributes.reason, 'bad_password');
  assert.equal(event.actor.id_mode, 'hash');
  assert.match(event.actor.id, /^[0-9a-f]{64}$/);
  assert.notEqual(event.actor.id, 'victim@example.com');
  assert.equal(JSON.stringify(event).includes('victim@example.com'), false);
  assert.equal(JSON.stringify(event).includes('never-send-this'), false);
  await sdk.shutdown({ timeoutMs: 500 });
  await ingest.close();
});

test('queue overflow drops the oldest event and counts it', async () => {
  const sdk = makeSdk('http://127.0.0.1:9/x', { maxQueueSize: 3, maxBatchSize: 50 });
  for (let index = 0; index < 5; index += 1) {
    sdk.track({ type: 'sdk.heartbeat', attributes: { index } });
  }
  assert.equal(sdk.queued, 3);
  assert.equal(sdk.dropped, 2);
  await sdk.shutdown({ timeoutMs: 10 });
});

test('retries a 5xx response and then succeeds', async () => {
  const ingest = await startIngest((attempt) => (attempt === 1 ? { status: 500, body: {} } : { status: 202, body: { accepted: 1 } }));
  const sdk = makeSdk(ingest.endpoint);
  sdk.track({ type: 'auth.login_failed', client: { ip: '203.0.113.10' } });
  await sdk.flush();
  assert.equal(ingest.requests.length, 2);
  assert.equal(sdk.queued, 0);
  await sdk.shutdown({ timeoutMs: 500 });
  await ingest.close();
});

test('does not retry a 4xx response and reports it', async () => {
  const ingest = await startIngest(() => ({ status: 400, body: { error: { code: 'invalid_batch' } } }));
  const errors = [];
  const sdk = makeSdk(ingest.endpoint, { onError: (error) => errors.push(error.message) });
  sdk.track({ type: 'auth.login_failed', client: { ip: '203.0.113.10' } });
  await sdk.flush();
  assert.equal(ingest.requests.length, 1);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /400/);
  await sdk.shutdown({ timeoutMs: 500 });
  await ingest.close();
});

test('a dead endpoint never throws into the host', async () => {
  const errors = [];
  const sdk = makeSdk('http://127.0.0.1:9/v1/ingest/website-events', { onError: (error) => errors.push(error.message) });
  sdk.track({ type: 'auth.login_failed', client: { ip: '203.0.113.10' } });
  await sdk.flush();
  assert.ok(errors.length >= 1);
  sdk.track({ type: 'sdk.heartbeat' });
  assert.equal(sdk.queued, 1);
  await sdk.shutdown({ timeoutMs: 200 });
});

test('shutdown flushes within the deadline', async () => {
  const ingest = await startIngest();
  const sdk = makeSdk(ingest.endpoint);
  sdk.track({ type: 'auth.signup', client: { ip: '198.51.100.7' } });
  await sdk.shutdown({ timeoutMs: 2000 });
  assert.equal(ingest.requests.length, 1);
  assert.equal(ingest.requests[0].body.events[0].type, 'auth.signup');
  await ingest.close();
});

test('the API key never appears in string forms', async () => {
  const sdk = makeSdk('http://127.0.0.1:9/x');
  const secret = KEY.slice(KEY.indexOf('_', 4) + 1);
  for (const text of [String(sdk), JSON.stringify(sdk), inspect(sdk), `${sdk}`]) {
    assert.equal(text.includes(secret), false);
  }
  await sdk.shutdown({ timeoutMs: 10 });
});

test('testConnection reports the HTTP result without throwing', async () => {
  const ingest = await startIngest(() => ({ status: 202, body: { accepted: 1 } }));
  const sdk = makeSdk(ingest.endpoint);
  const result = await sdk.testConnection();
  assert.deepEqual(result, { ok: true, status: 202 });
  assert.equal(ingest.requests[0].body.events[0].type, 'sdk.connectivity_test');
  await sdk.shutdown({ timeoutMs: 200 });
  await ingest.close();

  const dead = makeSdk('http://127.0.0.1:9/x');
  const failed = await dead.testConnection();
  assert.deepEqual(failed, { ok: false, status: 0 });
  await dead.shutdown({ timeoutMs: 10 });
});

test('the heartbeat reports dropped and queued counts', async () => {
  const ingest = await startIngest();
  const sdk = makeSdk(ingest.endpoint, { heartbeatIntervalMs: 40, maxQueueSize: 2, maxBatchSize: 100 });
  for (let index = 0; index < 4; index += 1) sdk.track({ type: 'sdk.heartbeat' });
  await new Promise((resolve) => setTimeout(resolve, 120));
  await sdk.flush();
  const heartbeat = ingest.requests.at(-1)?.body.events.find((event) => event.type === 'sdk.heartbeat');
  assert.ok(heartbeat, 'a heartbeat event was sent');
  assert.equal(typeof heartbeat.attributes.dropped, 'number');
  assert.equal(typeof heartbeat.attributes.queued, 'number');
  await sdk.shutdown({ timeoutMs: 500 });
  await ingest.close();
});

test('track is synchronous and does not block the request path', async () => {
  const sdk = makeSdk('http://127.0.0.1:9/x', {
    maxQueueSize: 5000,
    maxBatchSize: 100,
    fetchImpl: async () => ({ ok: true, status: 202, headers: { get: () => null } }),
  });
  const started = Date.now();
  for (let index = 0; index < 2000; index += 1) {
    sdk.track({ type: 'sdk.heartbeat', attributes: { index } });
  }
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 500, `track must stay fast, took ${elapsed}ms`);
  await sdk.shutdown({ timeoutMs: 500 });
});

test('an oversized event is dropped and reported', async () => {
  const errors = [];
  const sdk = makeSdk('http://127.0.0.1:9/x', { onError: (error) => errors.push(error.message) });
  sdk.track({ type: 'app.error', event_id: 'x'.repeat(20_000), request: { path: '/boom' }, attributes: { error_class: 'RuntimeError' } });
  assert.equal(sdk.queued, 0);
  assert.match(errors[0], /16 KiB/);
  await sdk.shutdown({ timeoutMs: 10 });
});

test('unknown event types are dropped rather than sent', async () => {
  const errors = [];
  const sdk = makeSdk('http://127.0.0.1:9/x', { onError: (error) => errors.push(error.message) });
  sdk.track({ type: 'made.up' });
  assert.equal(sdk.queued, 0);
  assert.match(errors[0], /unsupported event type/);
  await sdk.shutdown({ timeoutMs: 10 });
});
