import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'sf-health-'));
process.env.SF_DB_PATH = join(dir, 'health.db');

const dbmod = await import('../src/db.js');
dbmod.migrate();
const ORG = 'org_health_test';
dbmod.run(
  `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at)
   VALUES (?, 'Health Test', 'health-test', 'team', '{}', ?, ?)`,
  ORG, dbmod.nowIso(), dbmod.nowIso(),
);

const health = await import('../src/services/trishieldHealth.js');
const { parseVersionReply } = await import('../src/lib/clamav.js');
const { createWazuhClient } = await import('../src/lib/wazuh.js');

after(() => {
  try { dbmod.db.close(); } catch { /* closed */ }
  rmSync(dir, { recursive: true, force: true });
});

function cards(env = {}) {
  return health.integrationHealth(ORG, { env: { ...process.env, ...env } });
}
function card(key, env = {}) {
  return cards(env).find((entry) => entry.key === key);
}

test('the card list never reports VERIFIED from configuration alone', () => {
  const list = cards({ SF_CLOUDFLARE_API_TOKEN: '', SF_CLOUDFLARE_ACCOUNT_ID: '', CLAMAV_HOST: '' });
  const cloudflare = list.find((entry) => entry.key === 'cloudflare');
  assert.equal(cloudflare.state, 'NOT CONFIGURED');
  assert.ok(cloudflare.missing.includes('SF_CLOUDFLARE_API_TOKEN'));
  assert.equal(list.find((entry) => entry.key === 'clamav').state, 'NOT CONFIGURED');
  assert.equal(list.find((entry) => entry.key === 'suricata').state, 'NOT CONFIGURED');
  assert.ok(list.every((entry) => entry.state !== 'VERIFIED'));
});

test('nftables is UNAVAILABLE off Linux and never runs a command', async () => {
  const result = await health.checkIntegration(ORG, 'nftables', { env: process.env, deps: { platform: 'win32' } });
  assert.equal(result.state, 'UNAVAILABLE');
  assert.match(result.detail, /Linux host/i);
  const stored = card('nftables');
  assert.equal(stored.state, 'UNAVAILABLE');
  assert.equal(stored.lastCheckedAt !== null, true);
});

test('a Linux nftables check distinguishes unprovisioned from verified', async () => {
  const degraded = await health.checkIntegration(ORG, 'nftables', {
    env: { TRISHIELD_FIREWALL_APPLY: 'true' },
    deps: {
      platform: 'linux',
      providerConnector: () => ({ health: async () => ({ ok: false, code: 'unprovisioned', detail: 'table inet secureflow exists but is missing blocked_v6' }) }),
    },
  });
  assert.equal(degraded.state, 'DEGRADED');
  assert.match(degraded.detail, /missing blocked_v6/);

  const verified = await health.checkIntegration(ORG, 'nftables', {
    env: { TRISHIELD_FIREWALL_APPLY: 'true' },
    deps: {
      platform: 'linux',
      providerConnector: () => ({ health: async () => ({ ok: true, detail: 'table inet secureflow with both drop rules is present' }) }),
    },
  });
  assert.equal(verified.state, 'VERIFIED');
  // The read only card follows the host platform: UNAVAILABLE on Windows, the
  // recorded state on a Linux host where nft can actually run.
  assert.equal(card('nftables').state, process.platform === 'linux' ? 'VERIFIED' : 'UNAVAILABLE');
  assert.ok(card('nftables').lastSuccessAt);
});

test('apply disabled turns a reachable connector into DEGRADED, not VERIFIED', async () => {
  const result = await health.checkIntegration(ORG, 'nftables', {
    env: { TRISHIELD_FIREWALL_APPLY: 'false' },
    deps: {
      platform: 'linux',
      providerConnector: () => ({ health: async () => ({ ok: true, detail: 'table present' }) }),
    },
  });
  assert.equal(result.state, 'DEGRADED');
  assert.match(result.detail, /apply is disabled|TRISHIELD_FIREWALL_APPLY/i);
});

test('a ClamAV VERSION reply becomes a verified engine and signature record', async () => {
  assert.deepEqual(parseVersionReply('ClamAV 1.4.1/27480/Wed Nov 12 06:31:22 2026'), {
    engine: '1.4.1', signatures: 27480, signatureDate: 'Wed Nov 12 06:31:22 2026',
  });
  assert.equal(parseVersionReply('not a version'), null);

  const verified = await health.checkIntegration(ORG, 'clamav', {
    env: { CLAMAV_HOST: 'clamav.internal:3310' },
    deps: {
      readVersion: async () => ({ ok: true, engine: '1.4.1', signatures: 27480, signatureDate: 'Wed Nov 12 06:31:22 2026', detail: 'signatures' }),
    },
  });
  assert.equal(verified.state, 'VERIFIED');
  assert.match(verified.version, /ClamAV 1\.4\.1/);
  assert.match(verified.detail, /27480 signatures/);
});

test('a failing scanner is ERROR and never clean', async () => {
  const result = await health.checkIntegration(ORG, 'clamav', {
    env: { CLAMAV_HOST: '127.0.0.1:3999' },
    deps: { readVersion: async () => ({ ok: false, detail: 'connect ECONNREFUSED' }) },
  });
  assert.equal(result.state, 'ERROR');
  assert.match(result.detail, /ECONNREFUSED/);
  assert.equal(card('clamav').state, 'ERROR');
});

test('Wazuh reports ERROR when the manager refuses, VERIFIED when it answers', async () => {
  const env = { WAZUH_API_URL: 'https://wazuh.test:55000', WAZUH_API_USER: 'api', WAZUH_API_PASSWORD: 'secret' };
  const failed = await health.checkIntegration(ORG, 'wazuh', {
    env,
    deps: {
      createWazuhClient: () => ({ health: async () => ({ ok: false, detail: 'Wazuh HTTP 401: invalid credentials', latencyMs: 12 }) }),
    },
  });
  assert.equal(failed.state, 'ERROR');
  assert.match(failed.detail, /401/);

  const ok = await health.checkIntegration(ORG, 'wazuh', {
    env,
    deps: {
      createWazuhClient: () => ({
        health: async () => ({ ok: true, detail: 'Manager answered in 8 ms', version: '4.9.0', latencyMs: 8 }),
        agents: async () => [{ id: '001', name: 'host-1', status: 'active' }],
      }),
    },
  });
  assert.equal(ok.state, 'VERIFIED');
  assert.equal(ok.version, 'Wazuh 4.9.0');
  assert.match(ok.detail, /1 agent record/);
});

test('the Wazuh client authenticates with basic auth and reads manager info', async () => {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/security/user/authenticate')) {
      return new Response(JSON.stringify({ data: { token: 'jwt-token' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ data: { affected_items: [{ version: '4.9.0' }] } }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const client = createWazuhClient({ baseUrl: 'https://wazuh.test:55000', username: 'api', password: 'secret', fetchImpl });
  const result = await client.health();
  assert.equal(result.ok, true);
  assert.equal(result.version, '4.9.0');
  assert.match(calls[0].options.headers.authorization, /^Basic /);
  assert.equal(calls[1].options.headers.authorization, 'Bearer jwt-token');
});

test('a revoked collector feed is UNAVAILABLE, not configured', async () => {
  const created = await import('../src/services/trishieldIngest.js').then((mod) => mod.createCollector(ORG, { kind: 'suricata', name: 'health feed' }));
  assert.equal(card('suricata').state, 'CONFIGURED', 'a fresh token without events is configured only');
  await import('../src/services/trishieldIngest.js').then((mod) => mod.revokeCollector(ORG, created.id));
  assert.equal(card('suricata').state, 'UNAVAILABLE');
});

test('history is bounded and exposes the last success and failure', async () => {
  for (let i = 0; i < 7; i += 1) {
    health.recordHealthCheck(ORG, 'cloudflare', { state: i % 2 ? 'ERROR' : 'VERIFIED', ok: i % 2 === 0, latencyMs: 10 + i, detail: `run ${i}`, version: null });
  }
  const stored = card('cloudflare');
  assert.equal(stored.history.length, 5);
  assert.ok(stored.lastSuccessAt);
  assert.ok(stored.lastFailureAt);
});

test('two checks recorded in the same millisecond resolve to the newest row', () => {
  const ts = dbmod.nowIso();
  dbmod.run(
    `INSERT INTO trishield_health_checks (id, org_id, integration, state, ok, latency_ms, detail, version, checked_at)
     VALUES (?, ?, 'cloudflare', 'DEGRADED', 0, 12, 'first of the pair', NULL, ?)`,
    'thc_tie_a', ORG, ts,
  );
  dbmod.run(
    `INSERT INTO trishield_health_checks (id, org_id, integration, state, ok, latency_ms, detail, version, checked_at)
     VALUES (?, ?, 'cloudflare', 'ERROR', 0, 15, 'second of the pair', NULL, ?)`,
    'thc_tie_b', ORG, ts,
  );
  const stored = card('cloudflare');
  assert.equal(stored.state, 'ERROR');
  assert.equal(stored.detail, 'second of the pair');
});
