import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';

/**
 * Integration health API. No provider credentials are present, so this suite
 * exercises the read model, the role gate and a real check that legitimately
 * returns NOT CONFIGURED without touching the network.
 */
let server;
before(async () => { server = await startServer({ SF_CLOUDFLARE_API_TOKEN: '', SF_CLOUDFLARE_ACCOUNT_ID: '', CLAMAV_HOST: '', WAZUH_API_URL: '' }); }, { timeout: 60_000 });
after(() => server?.stop());

test('the health read model lists every integration with setup and requirements', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const response = await viewer.get('/trishield/health');
  assert.equal(response.status, 200);
  const { integrations, counts } = response.body.data;
  assert.equal(integrations.length, 6);
  assert.deepEqual(integrations.map((card) => card.key).sort(), ['clamav', 'cloudflare', 'nftables', 'suricata', 'waf', 'wazuh']);
  const allowed = ['NOT CONFIGURED', 'CONFIGURED', 'CONNECTED', 'VERIFIED', 'DEGRADED', 'ERROR', 'UNAVAILABLE'];
  for (const card of integrations) {
    assert.ok(allowed.includes(card.state), `${card.key}: ${card.state}`);
    assert.ok(card.setup.windows.length > 0);
    assert.ok(card.setup.linux.length > 0);
    assert.ok(card.setup.cloud.length > 0);
    assert.ok(Array.isArray(card.missing));
    assert.ok(card.nextAction.length > 0);
    assert.ok(card.lastCheckedAt === null || typeof card.lastCheckedAt === 'string');
  }
  assert.equal(counts.total, 6);
  assert.ok(!integrations.some((card) => card.state === 'VERIFIED'));
});

test('only an administrator can run an integration check', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const analyst = await login(server.base, ...DEMO.analyst);
  assert.equal((await viewer.post('/trishield/health/clamav/check')).status, 403);
  assert.equal((await analyst.post('/trishield/health/clamav/check')).status, 403);
  assert.equal((await viewer.post('/trishield/health/nope/check')).status, 403);
});

test('a check with no scanner reports NOT CONFIGURED and is recorded', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  assert.equal((await admin.post('/trishield/health/nope/check')).status, 404);

  const response = await admin.post('/trishield/health/clamav/check');
  assert.equal(response.status, 200, response.text);
  assert.equal(response.body.data.result.state, 'NOT CONFIGURED');
  assert.match(response.body.data.result.detail, /CLAMAV_HOST/);

  const health = (await admin.get('/trishield/health')).body.data.integrations;
  const clamav = health.find((card) => card.key === 'clamav');
  assert.ok(clamav.lastCheckedAt);
  assert.equal(clamav.history.length >= 1, true);
  assert.equal(clamav.history[0].state, 'NOT CONFIGURED');
});

test('a recorded check appears in the audit trail', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  await admin.post('/trishield/health/waf/check');
  const logs = await admin.get('/settings/audit-logs?limit=50');
  assert.equal(logs.status, 200);
  const rows = logs.body.data;
  assert.ok(rows.some((row) => row.action === 'trishield.integration.checked'));
});
