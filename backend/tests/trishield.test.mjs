import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'sf-tri-'));
process.env.SF_DB_PATH = join(dir, 'tri.db');
process.env.SF_IP_HMAC_KEY = Buffer.alloc(32, 11).toString('base64');
process.env.SF_IP_VAULT_KEY = Buffer.alloc(32, 22).toString('base64');
process.env.SF_IP_KEY_VERSION = 'v1';
process.env.SF_CLOUDFLARE_API_TOKEN = 'test-token';
process.env.SF_CLOUDFLARE_ACCOUNT_ID = 'test-account';
process.env.TRISHIELD_FIREWALL_APPLY = 'true';

const dbmod = await import('../src/db.js');
const { migrate, run, get, newId, nowIso, db } = dbmod;
migrate();
const ORG = 'org_tri_test';
run(
  `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at)
   VALUES (?, 'Tri Test', 'tri-test', 'team', '{}', ?, ?)`,
  ORG, nowIso(), nowIso(),
);

const infra = await import('../src/services/infraAddresses.js');
const firewall = await import('../src/services/firewall.js');
const policy = await import('../src/services/trishieldPolicy.js');
const ingest = await import('../src/services/trishieldIngest.js');

after(() => {
  try { db.close(); } catch { /* closed */ }
  rmSync(dir, { recursive: true, force: true });
});

test('address classification and masking handle IPv4 and IPv6', () => {
  assert.equal(infra.classifyAddress('192.168.1.45').scope, 'private');
  assert.equal(infra.classifyAddress('127.0.0.1').scope, 'loopback');
  assert.equal(infra.classifyAddress('2001:db8::1').scope, 'reserved');
  assert.equal(infra.classifyAddress('8.8.8.8').scope, 'public');
  assert.equal(infra.maskAddress('192.168.1.45'), '192.168.1.xxx');
  assert.notEqual(infra.maskAddress('2001:db8:1:2::5'), '2001:db8:1:2::5');
  assert.equal(infra.classifyAddress('not-an-ip'), null);
});

test('HMAC fingerprints are stable per key version and change with the key', () => {
  const a = infra.fingerprintAddress('8.8.8.8');
  const b = infra.fingerprintAddress('8.8.8.8');
  assert.equal(a.fingerprint, b.fingerprint);
  assert.match(a.fingerprint, /^ipfp_[0-9a-f]{32}$/);
  const other = infra.fingerprintAddress('8.8.8.8', { env: { ...process.env, SF_IP_HMAC_KEY: Buffer.alloc(32, 33).toString('base64') } });
  assert.notEqual(a.fingerprint, other.fingerprint);
});

test('the IP vault encrypts, decrypts and rejects tampering', () => {
  const sealed = infra.encryptAddress('8.8.4.4');
  const record = { key_version: sealed.keyVersion, nonce: sealed.nonce, ciphertext: sealed.ciphertext, tag: sealed.tag };
  assert.equal(infra.decryptAddress(record), '8.8.4.4');
  record.ciphertext = Buffer.from('tampered').toString('base64');
  assert.throws(() => infra.decryptAddress(record));
});

test('protected addresses cannot be blocked', () => {
  assert.equal(infra.addressIsProtected(ORG, '127.0.0.1').protected, true);
  assert.equal(infra.addressIsProtected(ORG, '10.0.0.5').protected, true);
  assert.equal(infra.addressIsProtected(ORG, '8.8.8.8').protected, false);
});

/** Tiny stateful nft emulator: tracks set elements and the input chain rules. */
function nftEmulator({ withDropRules = true } = {}) {
  const state = { elements: new Set(), chain: withDropRules ? 'chain input { type filter hook input priority 0; policy accept; }' : '' };
  const calls = [];
  const run = async (_bin, args) => {
    calls.push(args);
    const joined = args.join(' ');
    if (joined.startsWith('-j list set')) {
      const elem = [...state.elements].map((value) => ({ elem: { val: value } }));
      return { stdout: JSON.stringify({ nftables: [{ set: { elem } }] }) };
    }
    if (joined.startsWith('list chain')) return { stdout: state.chain };
    if (joined.startsWith('list table')) {
      return { stdout: withDropRules
        ? 'table inet secureflow { set blocked_v4 {} set blocked_v6 {} chain input { ip saddr @blocked_v4 drop comment "secureflow-block-v4" ip6 saddr @blocked_v6 drop comment "secureflow-block-v6" } }'
        : 'table inet secureflow { }' };
    }
    if (joined.startsWith('add rule') && joined.includes('secureflow-block-v4')) state.chain += ' ip saddr @blocked_v4 drop comment "secureflow-block-v4"';
    if (joined.startsWith('add rule') && joined.includes('secureflow-block-v6')) state.chain += ' ip6 saddr @blocked_v6 drop comment "secureflow-block-v6"';
    if (joined.startsWith('add element')) {
      const ip = args[args.indexOf('{') + 1];
      if (args.includes('timeout')) {
        const timeout = args[args.indexOf('timeout') + 1];
        assert.match(timeout, /^\d+s$/);
      }
      state.elements.add(ip);
    }
    if (joined.startsWith('delete element')) state.elements.delete(args[args.indexOf('{') + 1]);
    return { stdout: '' };
  };
  return { run, calls, state };
}

test('nftables installs the drop rules, blocks, verifies and removes an element', async () => {
  const nftables = nftEmulator();
  const nft = firewall.createNftConnector({ platform: 'linux', applyEnabled: true, run: nftables.run });
  await nft.block('1.1.1.1', { expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const joined = nftables.calls.map((args) => args.join(' '));
  assert.ok(joined.some((cmd) => cmd.startsWith('add table inet secureflow')));
  assert.ok(joined.some((cmd) => cmd.startsWith('add set inet secureflow blocked_v4')), 'the IPv4 block set is provisioned');
  assert.ok(joined.some((cmd) => cmd.startsWith('add chain inet secureflow input')), 'the base chain is provisioned');
  assert.ok(joined.some((cmd) => cmd.includes('add rule') && cmd.includes('@blocked_v4 drop')), 'the drop rule makes the set effective');
  assert.ok(joined.some((cmd) => cmd.startsWith('add element')));
  assert.equal((await nft.verify('1.1.1.1')).verified, true);
  await nft.unblock('1.1.1.1');
  assert.ok(nftables.calls.some((args) => args.join(' ').startsWith('delete element')));
  assert.equal((await nft.verify('1.1.1.1')).verified, false);
});

test('nftables verification fails when the drop rule is missing even if the element exists', async () => {
  const nftables = nftEmulator({ withDropRules: false });
  const nft = firewall.createNftConnector({ platform: 'linux', applyEnabled: true, run: nftables.run });
  await nft.block('1.1.1.1');
  // The emulator never had the chain; block() will install the rules, so remove them again.
  nftables.state.chain = '';
  const result = await nft.verify('1.1.1.1');
  assert.equal(result.verified, false);
  assert.match(result.detail, /drop rule is missing/);
});

test('nftables health reports an unprovisioned table instead of claiming it is active', async () => {
  const unprovisioned = nftEmulator({ withDropRules: false });
  const nft = firewall.createNftConnector({ platform: 'linux', applyEnabled: true, run: unprovisioned.run });
  const health = await nft.health();
  assert.equal(health.ok, false);
  assert.equal(health.code, 'unprovisioned');
  assert.match(health.detail, /missing/);
});

test('nftables refuses to apply when the apply flag is off', async () => {
  const nft = firewall.createNftConnector({ platform: 'linux', applyEnabled: false, run: async () => ({ stdout: '' }) });
  await assert.rejects(nft.block('1.1.1.1'), /apply is disabled/i);
});

test('Cloudflare connector creates, verifies and deletes an access rule', async () => {
  let rules = [];
  const fetchImpl = async (_url, options = {}) => {
    if (options.method === 'POST') {
      rules = [{ id: 'cf1', configuration: { value: JSON.parse(options.body).configuration.value }, mode: 'block' }];
      return new Response(JSON.stringify({ success: true, result: { id: 'cf1' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (options.method === 'DELETE') {
      rules = [];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ success: true, result: rules }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const cf = firewall.createCloudflareConnector({ token: 't', accountId: 'a', fetchImpl, applyEnabled: true });
  const created = await cf.block('1.1.1.1', { notes: 'test' });
  assert.equal(created.providerRef, 'cf1');
  assert.equal((await cf.verify('1.1.1.1')).verified, true);
  await cf.unblock('1.1.1.1', 'cf1');
  assert.equal((await cf.verify('1.1.1.1')).verified, false);
});

test('firewall actions require approval, verify, and roll back', async () => {
  let rules = [];
  const fetchImpl = async (_url, options = {}) => {
    if (options.method === 'POST') {
      rules = [{ id: 'cf1', configuration: { value: '1.1.1.1' }, mode: 'block' }];
      return new Response(JSON.stringify({ success: true, result: { id: 'cf1' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (options.method === 'DELETE') {
      rules = [];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ success: true, result: rules }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const options = { fetchImpl, token: 't', accountId: 'a', applyEnabled: true };
  const proposed = firewall.proposeAction({
    orgId: ORG, user: { id: 'usr_admin', role: 'admin' }, providerKey: 'cloudflare', type: 'block_ip',
    targetIp: '1.1.1.1', reason: 'Unit test block', expiresAt: new Date(Date.now() + 120_000).toISOString(),
  });
  assert.equal(proposed.action.status, 'awaiting_approval');
  await assert.rejects(firewall.executeAction(ORG, proposed.action.id, { id: 'usr_admin', role: 'admin' }, { connectorOptions: options }), /not approved/i);
  firewall.approveAction(ORG, proposed.action.id, { id: 'usr_admin', role: 'admin' });
  const executed = await firewall.executeAction(ORG, proposed.action.id, { id: 'usr_admin', role: 'admin' }, { connectorOptions: options });
  assert.equal(executed.status, 'succeeded');
  assert.equal(get('SELECT state FROM firewall_rules WHERE org_id = ? AND cidr = ?', ORG, '1.1.1.1/32').state, 'active');
  const rolled = await firewall.rollbackAction(ORG, proposed.action.id, { id: 'usr_admin', role: 'admin' }, { connectorOptions: options });
  assert.equal(rolled.status, 'rolled_back');
});

test('the same proposal is idempotent', () => {
  const expiresAt = new Date(Date.now() + 300_000).toISOString();
  const first = firewall.proposeAction({ orgId: ORG, user: { id: 'usr_admin', role: 'admin' }, providerKey: 'cloudflare', type: 'block_ip', targetIp: '1.1.1.2', reason: 'idem', expiresAt });
  const second = firewall.proposeAction({ orgId: ORG, user: { id: 'usr_admin', role: 'admin' }, providerKey: 'cloudflare', type: 'block_ip', targetIp: '1.1.1.2', reason: 'idem', expiresAt });
  assert.equal(second.duplicate, true);
  assert.equal(first.action.id, second.action.id);
});

test('policy evaluation can propose but never auto-applies without the explicit flag', async () => {
  policy.ensurePolicies(ORG);
  const row = get("SELECT * FROM trishield_policies WHERE org_id = ? AND key = 'firewall.auto_block'", ORG);
  run('UPDATE trishield_policies SET enabled = 1, mode = \'auto\' WHERE id = ?', row.id);
  const result = await policy.evaluateEventForBlock({
    orgId: ORG,
    event: { srcIp: '1.1.1.3', severity: 'critical', category: 'network', eventType: 'suricata.alert', title: 'test', dedupeKey: 'policy-test-1' },
    env: { ...process.env, TRISHIELD_AUTO_APPLY: 'false', TRISHIELD_PROVIDER: 'cloudflare' },
  });
  assert.equal(result.decision, 'awaiting_approval');
  assert.equal(result.reason, 'auto_apply_disabled');
});

test('synthetic demo events never reach a real provider', async () => {
  const result = await policy.evaluateEventForBlock({
    orgId: ORG,
    event: { srcIp: '1.1.1.3', severity: 'critical', category: 'network', eventType: 'suricata.alert', title: 'seeded', dedupeKey: 'synthetic-1', synthetic: true },
    env: { ...process.env, TRISHIELD_AUTO_APPLY: 'true', TRISHIELD_FIREWALL_APPLY: 'true', TRISHIELD_PROVIDER: 'cloudflare' },
  });
  assert.equal(result.decision, 'skipped');
  assert.equal(result.reason, 'synthetic_event');
});

test('Suricata, Wazuh and WAF records normalize safely', () => {
  const eve = ingest.parseSuricataRecord({ timestamp: '2026-11-15T10:00:00Z', event_type: 'alert', src_ip: '1.1.1.1', dest_ip: '10.0.0.5', src_port: 50000, dest_port: 443, proto: 'TCP', alert: { signature: 'Test', signature_id: 1, category: 'Test', severity: 1 } });
  assert.equal(eve.severity, 'critical');
  assert.equal(eve.category, 'network');
  assert.equal(ingest.parseWazuhRecord({ timestamp: '2026-11-15T10:00:00Z', agent: { id: '001', name: 'host', ip: '10.0.0.5' }, rule: { id: '1', level: 12, description: 'Alert' } }).severity, 'critical');
  assert.equal(ingest.parseWafRecord({ provider: 'cloudflare', category: 'sqli', action: 'blocked', sourceIp: '1.1.1.1', observedAt: '2026-11-15T10:00:00Z' }).severity, 'critical');
  assert.throws(() => ingest.parseWafRecord({ category: 'unknown' }));
});

test('collector ingestion deduplicates and keeps tenant scope', async () => {
  const collector = ingest.createCollector(ORG, { kind: 'suricata', name: 'unit-collector', user: { id: 'usr_admin' } });
  const row = get('SELECT * FROM trishield_collectors WHERE id = ?', collector.id);
  const record = { timestamp: '2026-11-15T10:01:00Z', event_type: 'alert', src_ip: '1.1.1.4', dest_ip: '10.0.0.5', alert: { signature: 'Unit', signature_id: 2, severity: 3 } };
  const first = await ingest.ingestProviderRecords({ orgId: ORG, collector: row, kind: 'suricata', records: [record] });
  assert.equal(first.accepted, 1);
  const second = await ingest.ingestProviderRecords({ orgId: ORG, collector: row, kind: 'suricata', records: [record] });
  assert.equal(second.duplicates, 1);
  assert.equal(ingest.endpointSummary(ORG).length, 0);
});
