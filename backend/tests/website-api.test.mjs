import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer, login, client, DEMO } from './helpers.mjs';

const dnsFile = join(tmpdir(), `sf-website-dns-${process.pid}-${Date.now()}.json`);
let server;
let admin;
let adminNoStep;
let analyst;

const writeDns = (records = {}, errors = {}) => {
  writeFileSync(dnsFile, JSON.stringify({ records, errors }), 'utf8');
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(check, { timeout = 8000, label = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const siteUrl = (hostname) => `https://${hostname}/`;

async function createSite(c, url, extra = {}) {
  const response = await c.post('/v1/websites', { url, ...extra });
  assert.equal(response.status, 201, `create ${url}: ${response.text}`);
  return response.body.data.site;
}

async function publishAndVerify(c, site, value = null, hostnameOverride = null) {
  const record = site.dns?.fullName ?? `_secureflow-challenge.${hostnameOverride ?? site.hostname}`;
  writeDns({ [record]: [value ?? site.dns.value] });
  return c.post(`/v1/websites/${site.id}/verify`, {});
}

async function ingest(key, payload, extraHeaders = {}) {
  const headers = { 'content-type': 'application/json', ...extraHeaders };
  if (key) headers.authorization = `Bearer ${key}`;
  const response = await fetch(`${server.base}/v1/ingest/website-events`, {
    method: 'POST',
    headers,
    body: typeof payload === 'string' ? payload : JSON.stringify(payload),
  });
  let body = null;
  try { body = await response.json(); } catch { body = null; }
  return { status: response.status, body, headers: response.headers };
}

const envelope = (events) => ({
  schema_version: 1,
  sdk: { name: 'secureflow-sdk-node', version: '0.1.0' },
  sent_at: new Date().toISOString(),
  events,
});

let counter = 0;
const event = (overrides = {}) => {
  counter += 1;
  return {
    event_id: randomUUID(),
    type: 'auth.login_failed',
    occurred_at: new Date().toISOString(),
    actor: { id: `user_${String(counter % 12).padStart(2, '0')}`, id_mode: 'raw' },
    client: { ip: '203.0.113.45', user_agent: 'Mozilla/5.0 (example)' },
    request: { host: 'shop.example.test', method: 'POST', path: '/login?next=/admin', status: 401 },
    ...overrides,
  };
};

before(async () => {
  writeDns();
  server = await startServer({
    SF_ALLOW_TEST_HOSTNAMES: 'true',
    SF_DNS_FAKE_FILE: dnsFile,
    SF_WEBSITE_PROTECTION: 'true',
  });
  admin = await login(server.base, ...DEMO.admin);
  const step = await admin.post('/auth/step-up', { password: DEMO.admin[1] });
  assert.equal(step.status, 200, step.text);
  adminNoStep = await login(server.base, ...DEMO.admin);
  analyst = await login(server.base, ...DEMO.analyst);
}, { timeout: 60_000 });

after(() => {
  server?.stop();
  try { rmSync(dnsFile, { force: true }); } catch { /* ignore */ }
});

test('only an admin can register a website and input is validated', async () => {
  const denied = await analyst.post('/v1/websites', { url: siteUrl('nope.example.test') });
  assert.equal(denied.status, 403);

  const badIp = await admin.post('/v1/websites', { url: 'https://10.20.30.40/' });
  assert.equal(badIp.status, 400);
  assert.equal(badIp.body.error.code, 'ip_address_not_allowed');

  const badSuffix = await admin.post('/v1/websites', { url: 'https://co.uk/' });
  assert.equal(badSuffix.status, 400);
  assert.equal(badSuffix.body.error.code, 'public_suffix_not_allowed');

  const site = await createSite(admin, 'https://Shop.Example.Test./login?x=1', { display_name: 'Shop', criticality: 3 });
  assert.equal(site.hostname, 'shop.example.test');
  assert.equal(site.status, 'pending_verification');
  assert.equal(site.scope, 'host');
  assert.equal(site.dns.type, 'TXT');
  assert.equal(site.dns.fullName, '_secureflow-challenge.shop.example.test');
  assert.equal(site.dns.value.startsWith('secureflow-site-verification='), true);
  assert.equal(site.dns.value.split('=')[1].length, 43);

  const again = await admin.post('/v1/websites', { url: 'https://shop.example.test' });
  assert.equal(again.status, 201);
  assert.equal(again.body.data.reused, true);
  assert.equal(again.body.data.site.id, site.id);

  const list = await analyst.get('/v1/websites');
  assert.equal(list.status, 200);
  assert.equal(Array.isArray(list.body.data), true);
  assert.equal(list.body.data.some((row) => row.id === site.id), true);

  const detail = await analyst.get(`/v1/websites/${site.id}`);
  assert.equal(detail.status, 200);
  assert.equal('apiKey' in detail.body.data, false);
});

test('verification distinguishes missing, mismatched, resolver failure and success', async () => {
  const site = await createSite(admin, siteUrl('verify.example.test'));

  writeDns({});
  const missing = await admin.post(`/v1/websites/${site.id}/verify`, {});
  assert.equal(missing.status, 200);
  assert.equal(missing.body.data.result, 'not_found');
  assert.equal(missing.body.data.status, 'pending_verification');

  writeDns({ [site.dns.fullName]: ['secureflow-site-verification=wrong'] });
  const mismatch = await admin.post(`/v1/websites/${site.id}/verify`, {});
  assert.equal(mismatch.body.data.result, 'mismatch');

  writeDns({}, { [site.dns.fullName]: 'ESERVFAIL' });
  const resolverError = await admin.post(`/v1/websites/${site.id}/verify`, {});
  assert.equal(resolverError.body.data.result, 'resolver_error');
  assert.equal(resolverError.body.data.status, 'pending_verification');

  const partial = await publishAndVerify(admin, site, `secureflow-site-verification=${site.dns.value.split('=')[1]}extra`);
  assert.equal(partial.body.data.result, 'mismatch');

  const verified = await publishAndVerify(admin, site);
  assert.equal(verified.status, 200, verified.text);
  assert.equal(verified.body.data.status, 'verified');
  assert.equal(verified.body.data.result, 'ok');

  const detail = await admin.get(`/v1/websites/${site.id}`);
  assert.equal(detail.body.data.status, 'verified');
  assert.ok(detail.body.data.assetId);
  assert.equal(detail.body.data.dns, null);
  assert.equal(detail.body.data.connection.state, 'suspended');
});

test('key creation needs a recent password confirmation and returns the secret once', async () => {
  const sites = await admin.get('/v1/websites');
  const verified = sites.body.data.find((row) => row.hostname === 'verify.example.test');
  assert.ok(verified);

  const fresh = await createSite(admin, siteUrl('keys.example.test'));
  const notVerified = await admin.post(`/v1/websites/${fresh.id}/keys`, { label: 'nope' });
  assert.equal(notVerified.status, 403);
  assert.equal(notVerified.body.error.code, 'site_not_verified');

  const needsAuth = await adminNoStep.post(`/v1/websites/${verified.id}/keys`, { label: 'nope' });
  assert.equal(needsAuth.status, 403);
  assert.equal(needsAuth.body.error.code, 'recent_auth_required');

  const analystDenied = await analyst.post(`/v1/websites/${verified.id}/keys`, { label: 'nope' });
  assert.equal(analystDenied.status, 403);

  const first = await admin.post(`/v1/websites/${verified.id}/keys`, { label: 'primary' });
  assert.equal(first.status, 201, first.text);
  assert.match(first.body.data.apiKey, /^sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}$/);
  assert.equal(first.headers.get('cache-control'), 'no-store');
  assert.equal(first.body.data.last4, first.body.data.apiKey.slice(-4));

  const second = await admin.post(`/v1/websites/${verified.id}/keys`, { label: 'rotation' });
  assert.equal(second.status, 201);

  const third = await admin.post(`/v1/websites/${verified.id}/keys`, { label: 'third' });
  assert.equal(third.status, 409);
  assert.equal(third.body.error.code, 'key_limit_reached');

  const metadata = await admin.get(`/v1/websites/${verified.id}/keys`);
  assert.equal(metadata.status, 200);
  assert.equal(metadata.body.data.length, 2);
  const serialized = JSON.stringify(metadata.body);
  assert.equal(serialized.includes(first.body.data.apiKey), false);
  assert.equal(serialized.includes('secret_hash'), false);
  assert.equal(serialized.includes('secretHash'), false);

  globalThis.__websiteTest = { siteId: verified.id, key: first.body.data.apiKey, keyId: first.body.data.keyId, second: second.body.data.apiKey };
});

test('ingestion refuses cookies, query string keys and invalid envelopes', async () => {
  const { siteId, key } = globalThis.__websiteTest;
  assert.ok(siteId && key);

  const cookieOnly = await ingest(null, envelope([event()]), { cookie: admin.cookie });
  assert.equal(cookieOnly.status, 401);
  assert.equal(cookieOnly.body.error.code, 'invalid_api_key');

  const malformed = await ingest('sfk_abcdefghijkl_' + 'A'.repeat(43), envelope([event()]));
  assert.equal(malformed.status, 401);

  const queryKey = await fetch(`${server.base}/v1/ingest/website-events?api_key=${encodeURIComponent(key)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(envelope([event()])),
  });
  assert.equal(queryKey.status, 401);

  const wrongType = await ingest(key, envelope([event()]), { 'content-type': 'text/plain' });
  assert.equal(wrongType.status, 415);

  const unknownEnvelopeField = await ingest(key, { ...envelope([event()]), extra: true });
  assert.equal(unknownEnvelopeField.status, 400);
  assert.equal(unknownEnvelopeField.body.error.code, 'invalid_batch');

  const polluted = JSON.parse(JSON.stringify(envelope([event()])).replace('"schema_version":1', '"schema_version":1,"__proto__":{"admin":true}'));
  const pollutedResponse = await ingest(key, polluted);
  assert.equal(pollutedResponse.status, 400);

  const tooMany = await ingest(key, envelope(Array.from({ length: 101 }, () => event())));
  assert.equal(tooMany.status, 400);

  const old = new Date(Date.now() - 8 * 24 * 3600_000).toISOString();
  const rejects = envelope([
    event({ type: 'made.up' }),
    event({ occurred_at: old }),
    event({ request: { host: 'other.example.test', method: 'GET', path: '/x', status: 200 } }),
    { event_id: randomUUID(), type: 'auth.login_failed', occurred_at: new Date().toISOString(), client: {} },
  ]);
  const rejectResponse = await ingest(key, rejects);
  assert.equal(rejectResponse.status, 202);
  assert.equal(rejectResponse.body.accepted, 0);
  assert.deepEqual(rejectResponse.body.rejected.map((row) => row.code), [
    'unknown_event_type', 'timestamp_out_of_range', 'host_mismatch', 'missing_field',
  ]);

  const oversized = await ingest(key, 'x'.repeat(300 * 1024));
  assert.equal(oversized.status, 413);
  assert.equal(oversized.body.error.code, 'payload_too_large');
});

test('a real batch produces one detection, one incident and is idempotent on replay', async () => {
  const { siteId, key } = globalThis.__websiteTest;
  const host = 'verify.example.test';

  const events = Array.from({ length: 25 }, (_, index) => event({
    actor: { id: `user_${String(index % 12).padStart(2, '0')}`, id_mode: 'raw' },
    request: { host, method: 'POST', path: '/login', status: 401 },
  }));
  const batch = envelope(events);
  const accepted = await ingest(key, batch);
  assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
  assert.equal(accepted.body.accepted, 25);
  assert.equal(accepted.body.rejected.length, 0);

  const detection = await waitFor(async () => {
    const response = await admin.get(`/v1/websites/${siteId}/detections`);
    return response.body.data.find((row) => row.ruleKey === 'w-auth-001');
  }, { label: 'w-auth-001 detection' });
  assert.equal(detection.severity, 'high');
  assert.ok(detection.riskScore >= 70);

  let incidents = await admin.get(`/v1/websites/${siteId}/incidents`);
  assert.equal(incidents.body.meta.total, 1);
  assert.equal(incidents.body.data[0].priority, 'P3');
  assert.equal(incidents.body.data[0].severity, 'high');
  assert.match(incidents.body.data[0].title, /against Shop|against verify/);

  const success = await ingest(key, envelope([event({
    type: 'auth.login_succeeded',
    actor: { id: 'user_00', id_mode: 'raw' },
    request: { host, method: 'POST', path: '/login', status: 200 },
  })]));
  assert.equal(success.body.accepted, 1);

  const escalated = await waitFor(async () => {
    const response = await admin.get(`/v1/websites/${siteId}/detections`);
    return response.body.data.find((row) => row.ruleKey === 'w-auth-003');
  }, { label: 'w-auth-003 detection' });
  assert.equal(escalated.severity, 'critical');

  await waitFor(async () => {
    const response = await admin.get(`/v1/websites/${siteId}/incidents`);
    const incident = response.body.data[0];
    return incident && incident.severity === 'critical' && incident.priority === 'P2' ? incident : null;
  }, { label: 'incident escalation' });

  incidents = await admin.get(`/v1/websites/${siteId}/incidents`);
  assert.equal(incidents.body.meta.total, 1, 'both detections share one incident');

  const before = await admin.get(`/v1/websites/${siteId}`);
  const replay = await ingest(key, batch);
  assert.equal(replay.body.accepted, 0);
  assert.equal(replay.body.duplicates, 25);
  await sleep(600);
  const after = await admin.get(`/v1/websites/${siteId}`);
  assert.equal(after.body.data.stats.events24h, before.body.data.stats.events24h, 'replay does not add events');
  assert.equal(after.body.data.stats.incidents, 1);
});

test('duplicate ids inside one batch are counted, not stored twice', async () => {
  const { key } = globalThis.__websiteTest;
  const single = event({ request: { host: 'verify.example.test', method: 'GET', path: '/', status: 200 } });
  const response = await ingest(key, envelope([single, { ...single }]));
  assert.equal(response.status, 202);
  assert.equal(response.body.accepted, 1);
  assert.equal(response.body.duplicates, 1);
});

test('another organization cannot read, change or verify the website', async () => {
  const { siteId } = globalThis.__websiteTest;
  const other = client(server.base);
  const email = `owner-${Date.now()}@example.test`;
  const registered = await other.post('/auth/register', {
    name: 'Other Owner', email, password: 'CorrectHorse#2026', organizationName: `Other ${Date.now()}`,
  });
  assert.equal(registered.status, 201, registered.text);
  const step = await other.post('/auth/step-up', { password: 'CorrectHorse#2026' });
  assert.equal(step.status, 200);

  assert.equal((await other.get(`/v1/websites/${siteId}`)).status, 404);
  assert.equal((await other.patch(`/v1/websites/${siteId}`, { display_name: 'stolen' })).status, 404);
  assert.equal((await other.post(`/v1/websites/${siteId}/verify`, {})).status, 404);
  assert.equal((await other.get(`/v1/websites/${siteId}/keys`)).status, 404);
  assert.equal((await other.del(`/v1/websites/${siteId}/keys/anything`)).status, 404);
  assert.equal((await other.get(`/v1/websites/${siteId}/events`)).status, 404);
  assert.equal((await other.get(`/v1/websites/${siteId}/detections`)).status, 404);
  assert.equal((await other.get(`/v1/websites/${siteId}/incidents`)).status, 404);
  assert.equal((await other.del(`/v1/websites/${siteId}`)).status, 404);

  const list = await other.get('/v1/websites');
  assert.equal(list.body.data.length, 0);

  const conflict = await other.post('/v1/websites', { url: siteUrl('verify.example.test') });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error.code, 'site_conflict');

  globalThis.__otherOrg = other;
});

test('concurrent verification of one hostname has exactly one winner', async () => {
  const stamp = Date.now();
  const hostname = `race-${stamp}.example.test`;
  const orgA = client(server.base);
  const orgB = client(server.base);
  const password = 'CorrectHorse#2026';
  for (const [org, label] of [[orgA, 'a'], [orgB, 'b']]) {
    const email = `race-${label}-${stamp}@example.test`;
    const registered = await org.post('/auth/register', {
      name: `Race ${label}`, email, password, organizationName: `Race ${label} ${stamp}`,
    });
    assert.equal(registered.status, 201, registered.text);
    await org.post('/auth/step-up', { password });
  }

  const siteA = await createSite(orgA, siteUrl(hostname));
  const siteB = await createSite(orgB, siteUrl(hostname));
  writeDns({ [`_secureflow-challenge.${hostname}`]: [siteA.dns.value, siteB.dns.value] });

  const results = await Promise.all([
    orgA.post(`/v1/websites/${siteA.id}/verify`, {}),
    orgB.post(`/v1/websites/${siteB.id}/verify`, {}),
  ]);
  const statuses = results.map((row) => row.status).sort();
  assert.deepEqual(statuses, [200, 409], JSON.stringify(results.map((row) => row.body)));

  const detailA = await orgA.get(`/v1/websites/${siteA.id}`);
  const detailB = await orgB.get(`/v1/websites/${siteB.id}`);
  const siteStatuses = [detailA.body.data.status, detailB.body.data.status].sort();
  assert.deepEqual(siteStatuses, ['expired', 'verified']);
});

test('domain scope blocks a later subdomain claim from another organization', async () => {
  const stamp = Date.now();
  const domain = `overlap-${stamp}.test`;
  const owner = client(server.base);
  const claimant = client(server.base);
  const password = 'CorrectHorse#2026';
  for (const [org, label] of [[owner, 'owner'], [claimant, 'claimant']]) {
    const registered = await org.post('/auth/register', {
      name: label, email: `${label}-${stamp}@example.test`, password, organizationName: `${label} ${stamp}`,
    });
    assert.equal(registered.status, 201, registered.text);
    await org.post('/auth/step-up', { password });
  }

  const site = await createSite(owner, siteUrl(domain), { scope: 'domain' });
  assert.equal(site.dns.fullName, `_secureflow-challenge.${domain}`);
  const verified = await publishAndVerify(owner, site);
  assert.equal(verified.status, 200, verified.text);
  assert.equal(verified.body.data.status, 'verified');

  const child = await createSite(claimant, siteUrl(`shop.${domain}`), { scope: 'host' });
  const recordName = `_secureflow-challenge.shop.${domain}`;
  writeDns({ [recordName]: [child.dns.value] });
  const conflict = await claimant.post(`/v1/websites/${child.id}/verify`, {});
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error.code, 'site_conflict');
  const detail = await claimant.get(`/v1/websites/${child.id}`);
  assert.equal(detail.body.data.status, 'expired');
});

test('host mismatch, private addresses and query strings are handled as specified', async () => {
  const { siteId, key } = globalThis.__websiteTest;
  const host = 'verify.example.test';

  const mismatch = await ingest(key, envelope([event({
    request: { host: 'evil.example.test', method: 'GET', path: '/', status: 200 },
  })]));
  assert.equal(mismatch.body.rejected[0].code, 'host_mismatch');

  for (let index = 0; index < 5; index += 1) {
    await ingest(key, envelope([event({ request: { host: 'evil.example.test', method: 'GET', path: '/', status: 200 } })]));
  }
  const warned = await admin.get(`/v1/websites/${siteId}`);
  assert.equal(warned.body.data.healthWarnings.some((row) => row.code === 'host_mismatch'), true);

  const privateIp = await ingest(key, envelope([event({
    client: { ip: '10.1.2.3', user_agent: 'x' },
    request: { host, method: 'GET', path: '/account?token=abc#frag', status: 200 },
  })]));
  assert.equal(privateIp.body.accepted, 1);
  const events = await admin.get(`/v1/websites/${siteId}/events?page=1&limit=5`);
  const stored = events.body.data[0];
  assert.equal(stored.path, '/account', 'query string and fragment are stripped');
  assert.equal(stored.ipClass, 'private');

  // The website pages filter by the SDK event name, which is stored in the raw payload
  // while event_type holds the normalised class. Both spellings must match.
  const byRawType = await admin.get(`/v1/websites/${siteId}/events?type=auth.login_failed&limit=20`);
  assert.equal(byRawType.status, 200, byRawType.text);
  assert.ok(byRawType.body.meta.total > 0, 'filtering by the SDK event name returns stored rows');
  assert.ok(byRawType.body.data.every((row) => row.type === 'auth.login_failed'));
  const noMatch = await admin.get(`/v1/websites/${siteId}/events?type=app.error`);
  assert.equal(noMatch.body.meta.total, 0, 'a type that was not ingested returns no rows');

  const sql = await ingest(key, envelope([event({
    request: { host, method: 'GET', path: "/search' OR 1=1--", status: 200 },
  })]));
  assert.equal(sql.body.accepted, 1, 'a hostile path is stored as data, not executed');
});

test('revocation takes effect immediately and the audit chain stays valid', async () => {
  const { siteId, key, keyId } = globalThis.__websiteTest;
  const before = await ingest(key, envelope([event({ request: { host: 'verify.example.test', method: 'GET', path: '/', status: 200 } })]));
  assert.equal(before.body.accepted, 1);

  const revoked = await admin.del(`/v1/websites/${siteId}/keys/${keyId}`);
  assert.equal(revoked.status, 200, revoked.text);

  const afterRevoke = await ingest(key, envelope([event()]));
  assert.equal(afterRevoke.status, 401);
  assert.equal(afterRevoke.body.error.code, 'invalid_api_key');

  const keys = await admin.get(`/v1/websites/${siteId}/keys`);
  assert.equal(keys.body.data.find((row) => row.keyId === keyId).status, 'revoked');

  const verify = await admin.get('/settings/audit-logs/verify');
  assert.equal(verify.status, 200);
  assert.equal(verify.body.data.ok, true, JSON.stringify(verify.body.data));

  const audit = await admin.get('/settings/audit-logs?limit=200');
  const actions = audit.body.data.map((row) => row.action);
  assert.ok(actions.includes('website.created'));
  assert.ok(actions.includes('website.verified'));
  assert.ok(actions.includes('website.key_created'));
  assert.ok(actions.includes('website.key_revoked'));
  assert.ok(actions.includes('website.key_rejected'), 'a revoked key presented again is recorded once');
  const serialized = JSON.stringify(audit.body);
  assert.equal(serialized.includes(key), false, 'audit metadata never contains a key');
  assert.equal(serialized.includes('secureflow-site-verification='), false, 'audit metadata never contains a token');
});

test('export is tenant scoped and deletion is verifiable', async () => {
  const { siteId } = globalThis.__websiteTest;
  const exported = await admin.get(`/v1/websites/${siteId}/export`);
  assert.equal(exported.status, 200);
  assert.ok(exported.body.data.counts.events > 0);
  const serialized = JSON.stringify(exported.body);
  assert.equal(serialized.includes('sfk_'), false);
  assert.equal(serialized.includes('secret_hash'), false);

  const wrong = await admin.post(`/v1/websites/${siteId}/data-deletion`, { confirm: 'wrong.example.test' });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error.code, 'confirmation_mismatch');

  const deleted = await admin.post(`/v1/websites/${siteId}/data-deletion`, { confirm: 'verify.example.test' });
  assert.equal(deleted.status, 200, deleted.text);
  assert.ok(deleted.body.data.events > 0);

  const events = await admin.get(`/v1/websites/${siteId}/events`);
  assert.equal(events.body.meta.total, 0);

  const audit = await admin.get('/settings/audit-logs?limit=50');
  assert.ok(audit.body.data.some((row) => row.action === 'website.data_deleted'));
});

test('verification attempts are rate limited per site', async () => {
  const site = await createSite(admin, siteUrl(`limit-${Date.now()}.example.test`));
  writeDns({});
  let limited = null;
  for (let attempt = 0; attempt < 7; attempt += 1) {
    const response = await admin.post(`/v1/websites/${site.id}/verify`, {});
    if (response.status === 429) { limited = response; break; }
  }
  assert.ok(limited, 'the seventh attempt inside an hour is refused');
  assert.equal(limited.body.error.code, 'verification_rate_limited');
  assert.ok(Number(limited.headers.get('retry-after') ?? 0) >= 0);
});

test('ingestion limits, sensitive attributes and control characters', async () => {
  const stamp = Date.now();
  const site = await createSite(admin, siteUrl(`limits-${stamp}.example.test`));
  writeDns({ [site.dns.fullName]: [site.dns.value] });
  const verified = await publishAndVerify(admin, site);
  assert.equal(verified.body.data.status, 'verified');
  const created = await admin.post(`/v1/websites/${site.id}/keys`, { label: 'limits' });
  assert.equal(created.status, 201);
  const key = created.body.data.apiKey;
  const host = `limits-${stamp}.example.test`;

  for (let batch = 0; batch < 6; batch += 1) {
    const response = await ingest(key, envelope(Array.from({ length: 100 }, () => event({
      request: { host, method: 'GET', path: '/', status: 200 },
    }))));
    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.equal(response.body.accepted, 100);
  }
  const limited = await ingest(key, envelope([event({ request: { host, method: 'GET', path: '/', status: 200 } })]));
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error.code, 'rate_limited');
  assert.ok(Number(limited.headers.get('retry-after')) >= 1);

  const attributeSite = await createSite(admin, siteUrl(`attrs-${stamp}.example.test`));
  writeDns({ [attributeSite.dns.fullName]: [attributeSite.dns.value] });
  await publishAndVerify(admin, attributeSite);
  const attrKey = (await admin.post(`/v1/websites/${attributeSite.id}/keys`, {})).body.data.apiKey;
  const dropped = await ingest(attrKey, envelope([event({
    request: { host: `attrs-${stamp}.example.test`, method: 'POST', path: '/login', status: 401 },
    attributes: { ['pass' + 'word']: 'must-not-be-stored', reason: 'bad_password' },
  })]));
  assert.equal(dropped.status, 202);
  assert.equal(dropped.body.dropped_fields, 1);
  const stored = await admin.get(`/v1/websites/${attributeSite.id}/events`);
  assert.equal(stored.body.data[0].attributes.password, undefined);
  assert.equal(stored.body.data[0].attributes.reason, 'bad_password');

  const control = await ingest(attrKey, envelope([event({
    actor: { id: 'user\u0000name' },
    request: { host: `attrs-${stamp}.example.test`, method: 'POST', path: '/login', status: 401 },
  })]));
  assert.equal(control.body.rejected[0].code, 'invalid_actor');
});

test('pending websites are capped per organization', async () => {
  const pending = (await admin.get('/v1/websites?status=pending_verification')).body.data.length;
  for (let index = pending; index < 10; index += 1) {
    const response = await admin.post('/v1/websites', { url: siteUrl(`pending-${index}-${Date.now()}.example.test`) });
    assert.equal(response.status, 201, response.text);
  }
  const blocked = await admin.post('/v1/websites', { url: siteUrl(`pending-extra-${Date.now()}.example.test`) });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error.code, 'too_many_pending_sites');
});
