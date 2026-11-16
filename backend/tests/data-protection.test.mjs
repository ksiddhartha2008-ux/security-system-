import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer, client, login, DEMO } from './helpers.mjs';

/**
 * Credential and database protection, end to end: the real ingestion endpoint,
 * the deterministic rules, and the summary the dashboard reads.
 */
const dnsFile = join(tmpdir(), `sf-dataprot-dns-${process.pid}-${Date.now()}.json`);
let server;
let admin;
let site;
let apiKey;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const event = (type, overrides = {}) => ({
  event_id: randomUUID(),
  type,
  occurred_at: new Date().toISOString(),
  client: { ip: '198.51.100.55' },
  ...overrides,
});

async function send(events) {
  const response = await fetch(`${server.base}/v1/ingest/website-events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ schema_version: 1, sdk: { name: 'protection-test', version: '1.0.0' }, sent_at: new Date().toISOString(), events }),
  });
  const body = await response.json();
  assert.equal(response.status, 202, JSON.stringify(body));
  return body;
}

async function waitForDetections(minimum, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const response = await admin.get(`/v1/websites/${site.id}/detections?limit=100`);
    if (response.body.meta.total >= minimum) return response.body.data;
    await sleep(150);
  }
  const response = await admin.get(`/v1/websites/${site.id}/detections?limit=100`);
  return response.body.data;
}

before(async () => {
  writeFileSync(dnsFile, JSON.stringify({ records: {}, errors: {} }));
  server = await startServer({ SF_ALLOW_TEST_HOSTNAMES: 'true', SF_DNS_FAKE_FILE: dnsFile, SF_WEBSITE_PROTECTION: 'true' });
  admin = await login(server.base, ...DEMO.admin);
  await admin.post('/auth/step-up', { password: DEMO.admin[1] });
  const siteResponse = await admin.post('/v1/websites', { url: 'https://shop.example.test', display_name: 'Shop protection', criticality: 4 });
  assert.equal(siteResponse.status, 201, siteResponse.text);
  site = siteResponse.body.data.site;
  writeFileSync(dnsFile, JSON.stringify({ records: { [site.dns.fullName]: [site.dns.value] }, errors: {} }));
  const verified = await admin.post(`/v1/websites/${site.id}/verify`, {});
  assert.equal(verified.body.data.status, 'verified', verified.text);
  const keyResponse = await admin.post(`/v1/websites/${site.id}/keys`, { label: 'protection' });
  assert.equal(keyResponse.status, 201, keyResponse.text);
  apiKey = keyResponse.body.data.apiKey;
}, { timeout: 60_000 });

after(() => {
  server?.stop();
  try { rmSync(dnsFile, { force: true }); } catch { /* ignore */ }
});

test('secrets in metadata are dropped before storage', async () => {
  const result = await send([
    event('auth.login_failed', { actor: { id: 'cust_1' }, attributes: { password: 'hunter2', reason: 'bad_password' } }),
  ]);
  assert.equal(result.accepted, 1);
  assert.ok(result.dropped_fields >= 1, 'the password attribute must be dropped');
});

test('credential and database attacks produce deterministic detections', async () => {
  const dbFailures = Array.from({ length: 6 }, () => event('database.auth_failed', { attributes: { db_user: 'app' } }));
  const exportEvent = event('database.bulk_export', { attributes: { records: 1200, table: 'customers' } });
  const schemaChanges = Array.from({ length: 3 }, () => event('database.schema_changed', { attributes: { operation: 'ALTER_TABLE' } }));
  const privileged = Array.from({ length: 10 }, () => event('database.privileged_operation', { attributes: { operation: 'GRANT' } }));
  const denials = Array.from({ length: 25 }, () => event('access.denied', { request: { host: 'shop.example.test', path: '/api/orders', method: 'GET', status: 403 } }));

  await send([...dbFailures, exportEvent, ...schemaChanges, ...privileged, ...denials]);
  const detections = await waitForDetections(5);
  const rules = detections.map((row) => row.ruleKey ?? row.rule_key ?? row.ruleId);
  assert.ok(rules.includes('w-db-001'), `expected database auth failures, got ${rules.join(',')}`);
  assert.ok(rules.includes('w-db-002'), `expected a bulk export detection, got ${rules.join(',')}`);
  assert.ok(rules.includes('w-db-003'), `expected a schema change detection, got ${rules.join(',')}`);
  assert.ok(rules.includes('w-db-004'), `expected privileged operation detection, got ${rules.join(',')}`);
  assert.ok(rules.includes('w-api-001'), `expected API denial burst detection, got ${rules.join(',')}`);
});

test('the protection summary reports the same evidence for the tenant', async () => {
  const response = await admin.get('/data-protection/overview');
  assert.equal(response.status, 200, response.text);
  const body = response.body.data;
  assert.ok(body.credential.events24h >= 1);
  assert.ok(body.credential.denials24h >= 25, 'the demo workspace already has some seeded denials');
  assert.equal(body.database.authFailures24h, 6);
  assert.equal(body.database.exports24h, 1);
  assert.equal(body.database.exportedRecords24h, 1200);
  assert.equal(body.database.schemaChanges24h, 3);
  assert.equal(body.sites.verified, 1);
  assert.equal(body.audit.ok, true);
  assert.ok(body.credential.topSources.length >= 1);
  assert.ok(body.credential.topSources.every((row) => row.address.endsWith('.xxx')));
  assert.ok(body.credential.detections.some((row) => row.ruleId === 'w-auth-001') === false, 'no credential stuffing fixture was sent');
  assert.ok(body.database.detections.some((row) => row.ruleId === 'w-db-002'));
});

test('another workspace sees zeros, not this tenant evidence', async () => {
  const other = client(server.base);
  const email = `prot-${Date.now()}@example.test`;
  const registered = await other.post('/auth/register', { name: 'Other Owner', email, password: 'Anchor#2026', organizationName: 'Other Workspace' });
  assert.equal(registered.status, 201, registered.text);
  const response = await other.get('/data-protection/overview');
  assert.equal(response.status, 200);
  assert.equal(response.body.data.credential.events24h, 0);
  assert.equal(response.body.data.database.events24h, 0);
  assert.equal(response.body.data.sites.total, 0);
  assert.equal(response.body.data.credential.detections.length, 0);
});
