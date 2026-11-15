import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { startServer, client, login, DEMO } from './helpers.mjs';

/**
 * The Cloudflare connector is configured through the environment so the approval
 * gate is exercised with a real connector contract. The credentials are fake, so
 * any outbound call fails and must be reported as a failure, never as success.
 */
let server;
before(async () => {
  server = await startServer({
    SF_CLOUDFLARE_API_TOKEN: 'test-token-not-valid',
    SF_CLOUDFLARE_ACCOUNT_ID: '0123456789abcdef0123456789abcdef',
    TRISHIELD_FIREWALL_APPLY: 'true',
  });
}, { timeout: 60_000 });
after(() => server?.stop());

function openDb() {
  return new DatabaseSync(join(server.dir, 'test.db'));
}

async function secondWorkspace() {
  const c = client(server.base);
  const email = `tri-owner-${Date.now()}-${Math.floor(Math.random() * 1000)}@example.test`;
  const response = await c.post('/auth/register', {
    name: 'Tri Owner', email, password: 'Anchor#2026', organizationName: 'Tri Second Workspace',
  });
  assert.equal(response.status, 201, response.text);
  return { client: c, orgId: response.body.data.user.orgId };
}

test('the overview reports each layer separately and never claims an unconfigured layer is active', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const response = await viewer.get('/trishield/overview');
  assert.equal(response.status, 200);
  const body = response.body.data;
  assert.deepEqual(body.layers.map((layer) => layer.key), ['perimeter', 'application', 'endpoint']);
  const endpointLayer = body.layers.find((layer) => layer.key === 'endpoint');
  assert.notEqual(endpointLayer.status, 'VERIFIED', 'no endpoint agent or scanner is configured in the test environment');
  assert.equal(body.endpoints.total, 0);
  assert.ok(Array.isArray(body.firewall.providers) && body.firewall.providers.length >= 2);
  for (const provider of body.firewall.providers) {
    assert.ok(['NOT CONFIGURED', 'CONFIGURED', 'CONNECTED', 'VERIFIED', 'DEGRADED', 'ERROR', 'UNAVAILABLE'].includes(provider.status), provider.status);
    if (provider.status === 'VERIFIED') assert.equal(provider.available, true, 'a provider cannot be verified while unavailable');
  }
  assert.equal(typeof body.infra.fingerprintConfigured, 'boolean');
  assert.equal(typeof body.origin.reverseProxyConfigured, 'boolean');
  assert.match(body.note, /VERIFIED only after a real check/i);
});

test('privileged TriShield routes are closed to viewers and analysts', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const analyst = await login(server.base, ...DEMO.analyst);
  const policy = (await viewer.get('/trishield/policies')).body.data[0];

  assert.equal((await viewer.get('/trishield/actions')).status, 200, 'viewers may read the approval queue');
  assert.equal((await viewer.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '93.184.216.34', reason: 'viewer attempt',
  })).status, 403);
  assert.equal((await viewer.patch(`/trishield/policies/${policy.id}`, { enabled: true })).status, 403);
  assert.equal((await viewer.post('/trishield/collectors', { kind: 'suricata', name: 'viewer collector' })).status, 403);
  assert.equal((await viewer.post('/trishield/firewall/health')).status, 403);
  assert.equal((await viewer.post('/trishield/ip/discover', { includePublic: false })).status, 403);

  assert.equal((await analyst.patch(`/trishield/policies/${policy.id}`, { enabled: true })).status, 403);
  assert.equal((await analyst.post('/trishield/firewall/health')).status, 403);
  assert.equal((await analyst.get('/trishield/policies')).status, 200);
});

test('a proposed block validates the address, refuses internal ranges and needs an administrator to approve', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);

  const invalid = await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: 'not-an-address', reason: 'invalid address attempt',
  });
  assert.equal(invalid.status, 400);

  const privateRange = await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '10.20.30.40', reason: 'internal range attempt',
  });
  assert.equal(privateRange.status, 400);
  assert.match(privateRange.body.error.message, /public/i);

  assert.equal((await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '127.0.0.1', reason: 'loopback attempt',
  })).status, 400);
  assert.equal((await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '169.254.169.254', reason: 'metadata endpoint attempt',
  })).status, 400);
  assert.equal((await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '93.184.216.34', reason: 'x',
  })).status, 400, 'the reason must be meaningful');
  assert.equal((await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '93.184.216.34', reason: 'permanent attempt', permanent: true,
  })).status, 400, 'only an administrator may propose a permanent block');

  const proposed = await analyst.post('/trishield/actions', {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '93.184.216.34', reason: 'Confirmed credential stuffing source',
  });
  assert.equal(proposed.status, 201, proposed.text);
  const action = proposed.body.data.action;
  assert.equal(action.status, 'awaiting_approval');
  assert.equal(action.approvalRequired, true);
  assert.equal(action.riskClass, 'restricted');

  assert.equal((await analyst.post(`/trishield/actions/${action.id}/approve`)).status, 403);
  assert.equal((await analyst.post(`/trishield/actions/${action.id}/execute`)).status, 403);

  const admin = await login(server.base, ...DEMO.admin);
  const approved = await admin.post(`/trishield/actions/${action.id}/approve`);
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.body.data.status, 'approved');

  const executed = await admin.post(`/trishield/actions/${action.id}/execute`);
  // Invalid credentials mean the provider cannot confirm the change. The API must
  // report a failure (409) and leave no verified rule behind.
  assert.equal(executed.status, 409, executed.text);
  const rules = await admin.get('/trishield/firewall/rules');
  assert.ok(!rules.body.data.rules.some((rule) => rule.cidr === '93.184.216.34/32' && rule.state === 'active'));
  const after = (await admin.get('/trishield/actions')).body.data.find((row) => row.id === action.id);
  assert.equal(after.status, 'failed');
  assert.match(after.error, /Cloudflare|not confirm|failed/i);
});

test('a duplicate proposal is rejected as idempotent instead of creating a second action', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);
  const body = {
    providerKey: 'cloudflare', type: 'block_ip', targetIp: '203.0.113.9', reason: 'Idempotency probe',
    expiresMinutes: 30,
  };
  const first = await analyst.post('/trishield/actions', body);
  // 203.0.113.0/24 is reserved, so the address is refused; use a public one.
  if (first.status === 400) {
    const publicBody = { ...body, targetIp: '93.184.216.35' };
    const a = await analyst.post('/trishield/actions', publicBody);
    const b = await analyst.post('/trishield/actions', publicBody);
    assert.equal(a.status, 201);
    assert.equal(b.status, 201);
    assert.equal(b.body.data.duplicate, true);
    assert.equal(a.body.data.action.id, b.body.data.action.id);
    return;
  }
  assert.fail('reserved address should have been refused');
});

test('an unavailable provider is refused instead of silently simulated', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const status = (await admin.get('/trishield/firewall/status')).body.data;
  const nft = status.providers.find((provider) => provider.key === 'nftables');
  const response = await admin.post('/trishield/actions', {
    providerKey: 'nftables', type: 'block_ip', targetIp: '93.184.216.36', reason: 'provider availability check',
  });
  if (nft.available) {
    assert.equal(response.status, 201);
  } else {
    assert.equal(response.status, 409);
    assert.match(response.body.error.message, /not available/i);
  }
});

test('collector tokens are per organization and cannot inject into another tenant', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const other = await secondWorkspace();

  const created = await admin.post('/trishield/collectors', { kind: 'suricata', name: 'API collector' });
  assert.equal(created.status, 201);
  const { id, token } = created.body.data;
  assert.match(token, /^tsk_/);

  const record = {
    timestamp: '2026-11-15T10:00:00Z', event_type: 'alert', src_ip: '198.51.100.44', dest_ip: '10.0.0.5',
    dest_port: 443, proto: 'TCP', alert: { signature: 'API test', signature_id: 10, severity: 1 },
  };
  const accepted = await fetch(`${server.base}/trishield/ingest/suricata`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify([record, record]),
  });
  assert.equal(accepted.status, 201);
  const payload = await accepted.json();
  assert.equal(payload.data.accepted, 1);
  assert.equal(payload.data.duplicates, 1);

  const wrongKind = await fetch(`${server.base}/trishield/ingest/wazuh`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify([record]),
  });
  assert.equal(wrongKind.status, 403);

  const forged = await fetch(`${server.base}/trishield/ingest/suricata`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer tsk_not-a-real-token' },
    body: JSON.stringify([record]),
  });
  assert.equal(forged.status, 401);

  const missing = await fetch(`${server.base}/trishield/ingest/suricata`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify([record]),
  });
  assert.equal(missing.status, 401);

  const session = await admin.get('/trishield/network/events?limit=50');
  assert.equal(session.status, 200);
  assert.ok(session.body.data.some((row) => row.srcIp === '198.51.100.44'));

  const otherEvents = await other.client.get('/trishield/network/events?limit=50');
  assert.equal(otherEvents.status, 200);
  assert.equal(otherEvents.body.data.length, 0, 'collector events must not leak across tenants');

  assert.equal((await admin.del(`/trishield/collectors/${id}`)).status, 200);
  const afterRevoke = await fetch(`${server.base}/trishield/ingest/suricata`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify([record]),
  });
  assert.equal(afterRevoke.status, 401);
});

test('another workspace cannot read or approve a firewall action, allowlist entry or address', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const other = await secondWorkspace();

  const db = openDb();
  const demoOrg = db.prepare('SELECT id FROM organizations WHERE slug = ?').get('secureflow-demo')
    ?? db.prepare("SELECT id FROM organizations WHERE id = (SELECT org_id FROM users WHERE email = 'admin@secureflow.dev')").get();
  assert.ok(demoOrg?.id, 'the demo organization should exist after seeding');
  const ts = new Date().toISOString();
  db.prepare(`INSERT INTO firewall_actions (id, org_id, provider_key, type, target_ip, cidr, reason, risk_class, status,
      approval_required, requested_by, idempotency_key, expires_at, permanent, verification, metadata, created_at, updated_at)
      VALUES (?, ?, 'cloudflare', 'block_ip', '198.51.100.77', '198.51.100.77/32', 'tenant isolation fixture', 'restricted',
      'awaiting_approval', 1, NULL, ?, ?, 0, '{}', '{}', ?, ?)`)
    .run('fwa_isolation_fixture', demoOrg.id, `fixture:${ts}`, new Date(Date.now() + 600_000).toISOString(), ts, ts);
  db.prepare('INSERT INTO trishield_allowlist (id, org_id, address, note, created_by, created_at) VALUES (?, ?, ?, ?, NULL, ?)')
    .run('alw_isolation_fixture', demoOrg.id, '198.51.100.88', 'fixture', ts);
  db.close();

  const demoActions = await admin.get('/trishield/actions');
  assert.ok(demoActions.body.data.some((action) => action.id === 'fwa_isolation_fixture'));

  const otherActions = await other.client.get('/trishield/actions');
  assert.equal(otherActions.body.data.length, 0);
  assert.equal((await other.client.post('/trishield/actions/fwa_isolation_fixture/approve')).status, 404);
  assert.equal((await other.client.post('/trishield/actions/fwa_isolation_fixture/execute')).status, 404);
  assert.equal((await other.client.post('/trishield/actions/fwa_isolation_fixture/reject')).status, 404);

  const otherAllowlist = await other.client.get('/trishield/firewall/allowlist');
  assert.equal(otherAllowlist.body.data.length, 0);
  assert.equal((await other.client.del('/trishield/firewall/allowlist/alw_isolation_fixture')).status, 404);

  const addresses = (await admin.get('/trishield/ip/addresses')).body.data;
  assert.ok(addresses.addresses.every((address) => !('address' in address)), 'raw addresses must never be listed');
  assert.ok(addresses.addresses.every((address) => typeof address.masked === 'string'));
});

test('permanent changes and IP reveal demand an administrator and a reason', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const analyst = await login(server.base, ...DEMO.analyst);

  assert.equal((await analyst.post('/trishield/ip/any/reveal', { reason: 'should be forbidden' })).status, 403);
  assert.equal((await admin.post('/trishield/ip/any/reveal', { reason: '' })).status, 400);
  assert.equal((await admin.post('/trishield/ip/any/reveal', { reason: 'investigating origin reachability' })).status, 404);

  assert.equal((await admin.post('/trishield/firewall/allowlist', { address: '198.51.100.200', note: 'partner range' })).status, 201);
  assert.equal((await admin.post('/trishield/firewall/allowlist', { address: '198.51.100.200' })).status, 409);
  assert.equal((await admin.post('/trishield/firewall/allowlist', { address: 'not-an-ip' })).status, 400);
});
