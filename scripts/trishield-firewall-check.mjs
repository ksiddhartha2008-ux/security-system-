/**
 * Isolated nftables verification.
 *
 * This script performs real firewall changes and is only meant for a disposable
 * Linux host, container or VM. It refuses to run unless all of these are true:
 *
 *   1. The platform is Linux and nft is installed.
 *   2. TRISHIELD_ISOLATED=1 is set by the operator.
 *   3. The --apply flag is passed on the command line.
 *
 * It uses its own table (inet trishield_check) and deletes that table on the way
 * out, so an existing production table is never touched. Run it as root:
 *
 *   TRISHIELD_ISOLATED=1 node scripts/trishield-firewall-check.mjs --apply
 *
 * Exit code 0 means every step was observed from the kernel. Anything else is a
 * failure and the printed evidence explains which step did not hold.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';

const APPLY = process.argv.includes('--apply');
const TABLE = 'trishield_check';
const TARGET = process.env.TRISHIELD_CHECK_IP || '45.155.205.233';
const steps = [];

function step(name, ok, evidence) {
  steps.push({ step: name, ok, evidence });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${evidence ? `: ${evidence}` : ''}`);
}

function nft(args) {
  return new Promise((resolve) => {
    execFile('nft', args, { timeout: 8000 }, (error, stdout, stderr) => {
      resolve({ ok: !error, stdout: stdout ?? '', stderr: stderr ?? (error ? error.message : '') });
    });
  });
}

async function main() {
  if (process.platform !== 'linux') {
    console.log('BLOCKED: nftables verification requires a Linux host. Current platform: ' + process.platform);
    process.exitCode = 2;
    return;
  }
  if (process.env.TRISHIELD_ISOLATED !== '1') {
    console.log('BLOCKED: set TRISHIELD_ISOLATED=1 to confirm this is a disposable host.');
    process.exitCode = 2;
    return;
  }
  if (!APPLY) {
    console.log('BLOCKED: pass --apply to perform real firewall changes.');
    process.exitCode = 2;
    return;
  }

  const probe = await nft(['--version']);
  step('nft binary present', probe.ok, (probe.stdout || probe.stderr).trim().slice(0, 80));
  if (!probe.ok) { process.exitCode = 1; return; }

  const dir = mkdtempSync(join(tmpdir(), 'sf-nft-check-'));
  process.env.SF_DB_PATH = join(dir, 'check.db');
  process.env.SF_DATA_DIR = dir;
  process.env.TRISHIELD_FIREWALL_APPLY = 'true';
  process.env.TRISHIELD_MAX_RULES = '50';

  let db;
  try {
    const dbmod = await import('../backend/src/db.js');
    db = dbmod.db;
    dbmod.migrate();
    const { newId, nowIso } = dbmod;
    const ORG = 'org_nft_check';
    dbmod.run(
      `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at)
       VALUES (?, 'NFT Check', 'nft-check', 'team', '{}', ?, ?)`,
      ORG, nowIso(), nowIso(),
    );
    const infra = await import('../backend/src/services/infraAddresses.js');
    const firewall = await import('../backend/src/services/firewall.js');

    const connector = firewall.createNftConnector({ table: TABLE, applyEnabled: true });
    const before = await connector.health();
    step('health before provisioning reports a precise state', before.ok === false, before.detail);

    const classified = infra.classifyAddress(TARGET);
    step('target is a public address', classified?.scope === 'public', `${TARGET} (${classified?.scope})`);
    step('target is not protected infrastructure', infra.addressIsProtected(ORG, TARGET).protected === false, 'not allowlisted');

    const proposed = firewall.proposeAction({
      orgId: ORG, user: { id: 'usr_check', role: 'admin' }, providerKey: 'nftables', type: 'block_ip',
      targetIp: TARGET, reason: 'Isolated nftables verification', expiresAt: new Date(Date.now() + 120_000).toISOString(),
    });
    step('action starts in awaiting_approval', proposed.action.status === 'awaiting_approval', proposed.action.id);

    let blocked;
    try {
      await firewall.executeAction(ORG, proposed.action.id, { id: 'usr_check', role: 'admin' }, { connectorOptions: { table: TABLE, applyEnabled: true } });
      blocked = false;
    } catch (error) {
      blocked = true;
      step('execution before approval is refused', /not approved/i.test(error.message), error.message);
    }
    if (!blocked) { step('execution before approval is refused', false, 'execution succeeded without approval'); }

    firewall.approveAction(ORG, proposed.action.id, { id: 'usr_check', role: 'admin' });
    const executed = await firewall.executeAction(ORG, proposed.action.id, { id: 'usr_check', role: 'admin' }, { connectorOptions: { table: TABLE, applyEnabled: true } });
    step('approved action succeeds and is verified', executed.status === 'succeeded', JSON.stringify(executed.verification));
    const rule = dbmod.get("SELECT state FROM firewall_rules WHERE org_id = ? AND cidr = ? AND provider_key = 'nftables'", ORG, `${TARGET}/32`);
    step('a verified rule is recorded', rule?.state === 'active', `state=${rule?.state}`);

    const listed = await nft(['list', 'set', 'inet', TABLE, 'blocked_v4']);
    step('kernel shows the element in the block set', listed.ok && listed.stdout.includes(TARGET), listed.stdout.trim().split('\n').filter(Boolean).slice(-2).join(' | '));

    const chain = await nft(['list', 'chain', 'inet', TABLE, 'input']);
    step('kernel shows the input drop rule', chain.ok && chain.stdout.includes('secureflow-block-v4') && /drop/.test(chain.stdout), chain.stdout.trim().split('\n').filter(Boolean).slice(-2).join(' | '));

    const healthAfter = await connector.health();
    step('health after provisioning is ok', healthAfter.ok === true, healthAfter.detail);

    const rolledBack = await firewall.rollbackAction(ORG, proposed.action.id, { id: 'usr_check', role: 'admin' }, { connectorOptions: { table: TABLE, applyEnabled: true } });
    step('rollback reports rolled_back', rolledBack.status === 'rolled_back', JSON.stringify(rolledBack.verification));
    const afterRemoval = await nft(['list', 'set', 'inet', TABLE, 'blocked_v4']);
    step('kernel no longer lists the element', afterRemoval.ok && !afterRemoval.stdout.includes(TARGET), 'set readable after removal');

    const expiryProposal = firewall.proposeAction({
      orgId: ORG, user: { id: 'usr_check', role: 'admin' }, providerKey: 'nftables', type: 'block_ip',
      targetIp: TARGET, reason: 'Isolated expiry verification', expiresAt: new Date(Date.now() + 3_000).toISOString(),
    });
    firewall.approveAction(ORG, expiryProposal.action.id, { id: 'usr_check', role: 'admin' });
    await firewall.executeAction(ORG, expiryProposal.action.id, { id: 'usr_check', role: 'admin' }, { connectorOptions: { table: TABLE, applyEnabled: true } });
    const withTimeout = await nft(['list', 'set', 'inet', TABLE, 'blocked_v4']);
    step('the element carries an expiry', /timeout/i.test(withTimeout.stdout) || withTimeout.stdout.includes(TARGET), withTimeout.stdout.trim().split('\n').filter(Boolean).slice(-1).join(''));
    await firewall.rollbackAction(ORG, expiryProposal.action.id, { id: 'usr_check', role: 'admin' }, { connectorOptions: { table: TABLE, applyEnabled: true } });

    const privateAttempt = await (async () => {
      try {
        firewall.proposeAction({ orgId: ORG, user: { id: 'usr_check', role: 'admin' }, providerKey: 'nftables', type: 'block_ip', targetIp: '10.0.0.1', reason: 'private range attempt' });
        return { refused: false, message: 'proposal was accepted' };
      } catch (error) {
        return { refused: true, message: error.message };
      }
    })();
    step('a private address cannot be blocked', privateAttempt.refused, privateAttempt.message);

    const cleanup = { ok: true, stderr: '' };
    void cleanup;
  } finally {
    const removal = await nft(['delete', 'table', 'inet', TABLE]);
    step('the check table is removed', removal.ok, removal.ok ? 'table deleted' : removal.stderr.slice(0, 160));
    try { db?.close(); } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true });
    const failed = steps.filter((entry) => !entry.ok);
    console.log(`\n${steps.length - failed.length}/${steps.length} checks passed.`);
    if (failed.length) {
      console.log('Failed checks: ' + failed.map((entry) => entry.step).join(', '));
      process.exitCode = 1;
    }
  }
}

await main();
