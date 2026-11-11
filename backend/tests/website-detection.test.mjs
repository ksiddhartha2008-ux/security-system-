import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer, login, DEMO } from './helpers.mjs';

const dnsFile = join(tmpdir(), `sf-detection-dns-${process.pid}-${Date.now()}.json`);
let server;
let admin;
let benign;
let attack;
let key;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const event = (type, overrides = {}) => ({
  event_id: randomUUID(),
  type,
  occurred_at: new Date().toISOString(),
  ...overrides,
});

const envelope = (events) => ({ schema_version: 1, sdk: { name: 'labeled-corpus', version: '1.0.0' }, sent_at: new Date().toISOString(), events });

async function send(siteKey, events) {
  const response = await fetch(`${server.base}/v1/ingest/website-events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${siteKey}` },
    body: JSON.stringify(envelope(events)),
  });
  const body = await response.json();
  assert.equal(response.status, 202, JSON.stringify(body));
  return body;
}

async function waitForDetections(siteId, minimum = 1, timeout = 8000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const response = await admin.get(`/v1/websites/${siteId}/detections?limit=100`);
    if (response.body.meta.total >= minimum) return response.body.data;
    await sleep(100);
  }
  const response = await admin.get(`/v1/websites/${siteId}/detections?limit=100`);
  return response.body.data;
}

before(async () => {
  writeFileSync(dnsFile, JSON.stringify({ records: {}, errors: {} }));
  server = await startServer({ SF_ALLOW_TEST_HOSTNAMES: 'true', SF_DNS_FAKE_FILE: dnsFile, SF_WEBSITE_PROTECTION: 'true' });
  admin = await login(server.base, ...DEMO.admin);
  await admin.post('/auth/step-up', { password: DEMO.admin[1] });

  const created = [];
  for (const [hostname, name] of [['benign.example.test', 'Benign corpus'], ['attack.example.test', 'Attack corpus']]) {
    const siteResponse = await admin.post('/v1/websites', { url: `https://${hostname}`, display_name: name, criticality: 3 });
    assert.equal(siteResponse.status, 201, siteResponse.text);
    const site = siteResponse.body.data.site;
    writeFileSync(dnsFile, JSON.stringify({ records: { [site.dns.fullName]: [site.dns.value] }, errors: {} }));
    const verified = await admin.post(`/v1/websites/${site.id}/verify`, {});
    assert.equal(verified.body.data.status, 'verified', verified.text);
    const keyResponse = await admin.post(`/v1/websites/${site.id}/keys`, { label: 'labeled corpus' });
    assert.equal(keyResponse.status, 201, keyResponse.text);
    created.push({ site, key: keyResponse.body.data.apiKey });
  }
  benign = created[0];
  attack = created[1];
  key = created[1].key;
}, { timeout: 60_000 });

after(() => {
  server?.stop();
  try { rmSync(dnsFile, { force: true }); } catch { /* ignore */ }
});

test('benign traffic produces no detection', async () => {
  const events = [];
  // A user fails three times then succeeds.
  for (let index = 0; index < 3; index += 1) {
    events.push(event('auth.login_failed', { actor: { id: 'user_near_miss' }, client: { ip: '203.0.113.70' }, request: { host: 'benign.example.test', path: '/login', method: 'POST', status: 401 } }));
  }
  events.push(event('auth.login_succeeded', { actor: { id: 'user_near_miss' }, client: { ip: '203.0.113.70' }, request: { host: 'benign.example.test', path: '/login', method: 'POST', status: 200 } }));
  // Fifty different users succeed from one office address.
  for (let index = 0; index < 50; index += 1) {
    events.push(event('auth.login_succeeded', { actor: { id: `office_${index}` }, client: { ip: '203.0.113.71' }, request: { host: 'benign.example.test', path: '/login', method: 'POST', status: 200 } }));
  }
  // Fourteen distinct suspicious paths, one below the scanning threshold.
  for (let index = 0; index < 14; index += 1) {
    events.push(event('request.suspicious', { client: { ip: '203.0.113.72' }, request: { host: 'benign.example.test', path: `/page-${index}`, method: 'GET', status: 200 }, attributes: { category: 'scanner' } }));
  }
  // Application errors with no security meaning.
  for (let index = 0; index < 20; index += 1) {
    events.push(event('app.error', { client: { ip: '203.0.113.73' }, request: { host: 'benign.example.test', path: '/checkout', method: 'POST', status: 500 }, attributes: { error_class: 'TimeoutError' } }));
  }
  for (let index = 0; index < 5; index += 1) events.push(event('sdk.heartbeat', { attributes: { dropped: 0, queued: 0 } }));

  const result = await send(benign.key, events);
  assert.equal(result.accepted, events.length);
  await sleep(1200);
  const detections = (await admin.get(`/v1/websites/${benign.site.id}/detections?limit=100`)).body.data;
  assert.equal(detections.length, 0, `benign corpus produced ${detections.map((row) => row.ruleKey).join(', ')}`);
  const incidents = await admin.get(`/v1/websites/${benign.site.id}/incidents`);
  assert.equal(incidents.body.meta.total, 0);
});

test('the attack corpus is detected with measured precision and recall', async () => {
  const host = 'attack.example.test';
  const events = [];
  for (let index = 0; index < 60; index += 1) {
    events.push(event('auth.login_failed', {
      actor: { id: `user_${String(index % 25).padStart(2, '0')}` },
      client: { ip: '203.0.113.60' },
      request: { host, path: '/login', method: 'POST', status: 401 },
    }));
  }
  events.push(event('auth.login_succeeded', {
    actor: { id: 'user_07' }, client: { ip: '203.0.113.60' },
    request: { host, path: '/login', method: 'POST', status: 200 },
  }));
  for (let index = 0; index < 12; index += 1) {
    events.push(event('access.denied', {
      actor: { id: 'user_07' }, client: { ip: '203.0.113.60' },
      request: { host, path: `/admin/settings/${index}`, method: 'GET', status: 403 },
    }));
  }
  for (let index = 0; index < 4; index += 1) {
    events.push(event('request.suspicious', {
      client: { ip: '203.0.113.60' },
      request: { host, path: '/search', method: 'GET', status: 200 },
      attributes: { category: 'sqli' },
    }));
  }

  const result = await send(key, events);
  assert.equal(result.accepted, events.length);
  assert.equal(result.rejected.length, 0);

  const detections = await waitForDetections(attack.site.id, 4);
  const rules = new Set(detections.map((row) => row.ruleKey));
  const expected = ['w-auth-001', 'w-auth-003', 'w-acc-001', 'w-req-003'];
  const truePositives = expected.filter((rule) => rules.has(rule)).length;
  const falseNegatives = expected.length - truePositives;
  const benignDetections = (await admin.get(`/v1/websites/${benign.site.id}/detections?limit=100`)).body.data.length;
  const falsePositives = benignDetections;
  const precision = truePositives / (truePositives + falsePositives);
  const recall = truePositives / (truePositives + falseNegatives);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  // Measured on 93 benign and 77 labelled attack events in this synthetic corpus.
  // These numbers describe this corpus only; they are not a claim of field accuracy.
  console.log(`[detection-quality] benign=${93} attack=${events.length} tp=${truePositives} fp=${falsePositives} fn=${falseNegatives} precision=${precision.toFixed(3)} recall=${recall.toFixed(3)} f1=${f1.toFixed(3)} rules=${[...rules].join(',')}`);
  assert.equal(falsePositives, 0);
  assert.equal(falseNegatives, 0);
  assert.equal(precision, 1);
  assert.equal(recall, 1);

  const incidents = await admin.get(`/v1/websites/${attack.site.id}/incidents`);
  assert.equal(incidents.body.meta.total, 1, 'all attack detections share one incident');
  const incident = incidents.body.data[0];
  assert.equal(incident.severity, 'critical');
  assert.equal(incident.priority, 'P2');

  const detail = await admin.get(`/v1/websites/${attack.site.id}`);
  const throttled = detail.body.data.notifications.filter((row) => row.status === 'suppressed');
  assert.ok(detail.body.data.notifications.length >= 1);
  assert.ok(throttled.every((row) => row.suppressionReason), 'every suppressed notification records a reason');
});
