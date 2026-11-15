import { execFile } from 'node:child_process';
import { all, get, run, newId, nowIso, parseJson, transaction } from '../db.js';
import { badRequest, conflict, notFound } from '../lib/http.js';
import { addressIsProtected, classifyAddress } from './infraAddresses.js';

const NFT_TABLE = 'secureflow';
const MAX_ACTIVE_RULES = Number(process.env.TRISHIELD_MAX_RULES ?? 500);

function defaultRun(bin, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 6000, maxBuffer: 2 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function nftSetFor(family) {
  return family === 'ipv6' ? 'blocked_v6' : 'blocked_v4';
}

/**
 * nftables connector.
 *
 * Commands are passed as an argument vector, never through a shell. The binary
 * path is configuration, not request input. Actual changes require the explicit
 * TRISHIELD_FIREWALL_APPLY=true flag and a Linux host with nft installed.
 */
export function createNftConnector({ bin = process.env.SF_NFT_BIN || 'nft', table = NFT_TABLE, run = defaultRun, applyEnabled = process.env.TRISHIELD_FIREWALL_APPLY === 'true', platform = process.platform } = {}) {
  const available = platform === 'linux';
  const chainComments = { v4: 'secureflow-block-v4', v6: 'secureflow-block-v6' };
  const ensure = async (family) => {
    const set = nftSetFor(family);
    const type = family === 'ipv6' ? 'ipv6_addr' : 'ipv4_addr';
    try { await run(bin, ['add', 'table', 'inet', table]); } catch (error) { if (!/exists/i.test(String(error.stderr ?? error.message))) throw error; }
    try {
      await run(bin, ['add', 'set', 'inet', table, set, '{', 'type', type, ';', 'flags', 'timeout', ';', '}']);
    } catch (error) {
      if (!/exists/i.test(String(error.stderr ?? error.message))) throw error;
    }
    // A set on its own drops nothing. The base chain and its drop rules are what
    // make the block real, so they are provisioned and verified too.
    try {
      await run(bin, ['add', 'chain', 'inet', table, 'input', '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', 'policy', 'accept', ';', '}']);
    } catch (error) {
      if (!/exists/i.test(String(error.stderr ?? error.message))) throw error;
    }
    const chain = await run(bin, ['list', 'chain', 'inet', table, 'input']).catch(() => ({ stdout: '' }));
    const text = String(chain?.stdout ?? '');
    if (!text.includes(chainComments.v4)) {
      await run(bin, ['add', 'rule', 'inet', table, 'input', 'ip', 'saddr', '@blocked_v4', 'drop', 'comment', chainComments.v4]);
    }
    if (!text.includes(chainComments.v6)) {
      await run(bin, ['add', 'rule', 'inet', table, 'input', 'ip6', 'saddr', '@blocked_v6', 'drop', 'comment', chainComments.v6]);
    }
  };
  const readElements = async (family) => {
    const set = nftSetFor(family);
    const { stdout } = await run(bin, ['-j', 'list', 'set', 'inet', table, set]);
    const parsed = JSON.parse(stdout || '{"nftables":[]}');
    const elements = [];
    for (const entry of parsed.nftables ?? []) {
      for (const element of entry.set?.elem ?? []) {
        if (typeof element === 'string') elements.push(element.split(' ')[0]);
        else if (element?.elem?.val) elements.push(String(element.elem.val).split(' ')[0]);
      }
    }
    return elements;
  };
  return {
    key: 'nftables',
    kind: 'nftables',
    available,
    applyEnabled,
    async health() {
      if (!available) return { ok: false, code: 'unavailable', detail: 'nftables requires a Linux host with nft installed' };
      try {
        const { stdout } = await run(bin, ['list', 'table', 'inet', table]);
        const text = String(stdout ?? '');
        const missing = ['blocked_v4', 'blocked_v6', chainComments.v4, chainComments.v6].filter((token) => !text.includes(token));
        if (missing.length) {
          return { ok: false, code: 'unprovisioned', detail: `table inet ${table} exists but is missing ${missing.join(', ')}` };
        }
        return { ok: true, detail: `table inet ${table} with both drop rules is present` };
      } catch (error) {
        return { ok: false, code: 'error', detail: String(error.stderr ?? error.message).slice(0, 200) };
      }
    },
    async list(ip) {
      if (!available) throw new Error('nftables is unavailable on this platform');
      const family = ip ? classifyAddress(ip)?.family ?? 'ipv4' : 'ipv4';
      await ensure(family);
      return readElements(family);
    },
    async block(ip, { expiresAt } = {}) {
      if (!available) throw new Error('nftables is unavailable on this platform');
      if (!applyEnabled) throw new Error('Firewall apply is disabled (TRISHIELD_FIREWALL_APPLY)');
      const classified = classifyAddress(ip);
      if (!classified) throw new Error('Invalid IP address');
      await ensure(classified.family);
      const set = nftSetFor(classified.family);
      const timeout = expiresAt ? ` timeout ${Math.max(1, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000))}s` : '';
      await run(bin, ['add', 'element', 'inet', table, set, '{', classified.address, ...(timeout ? ['timeout', timeout.trim().split(' ')[1]] : []), '}']);
      return { providerRef: classified.address };
    },
    async unblock(ip) {
      if (!available) throw new Error('nftables is unavailable on this platform');
      if (!applyEnabled) throw new Error('Firewall apply is disabled (TRISHIELD_FIREWALL_APPLY)');
      const classified = classifyAddress(ip);
      if (!classified) throw new Error('Invalid IP address');
      await ensure(classified.family);
      await run(bin, ['delete', 'element', 'inet', table, nftSetFor(classified.family), '{', classified.address, '}']);
      return { providerRef: classified.address };
    },
    async verify(ip) {
      if (!available) return { verified: false, detail: 'nftables is unavailable on this platform' };
      // Verification is read-only. It must never repair the rule it is checking.
      try {
        const family = classifyAddress(ip)?.family ?? 'ipv4';
        const elements = await readElements(family);
        if (!elements.includes(ip)) return { verified: false, detail: 'element not present in the block set' };
        const chain = await run(bin, ['list', 'chain', 'inet', table, 'input']).catch(() => ({ stdout: '' }));
        const text = String(chain?.stdout ?? '');
        const expected = family === 'ipv6' ? chainComments.v6 : chainComments.v4;
        if (!text.includes(expected)) {
          return { verified: false, detail: 'the block set is present but the input chain drop rule is missing' };
        }
        return { verified: true, detail: 'element present and drop rule installed' };
      } catch (error) {
        return { verified: false, detail: String(error.message).slice(0, 200) };
      }
    },
  };
}

/**
 * Cloudflare account firewall access rules.
 * Credentials are environment only and never returned to a client.
 */
export function createCloudflareConnector({ token = process.env.SF_CLOUDFLARE_API_TOKEN, accountId = process.env.SF_CLOUDFLARE_ACCOUNT_ID, fetchImpl = fetch, applyEnabled = process.env.TRISHIELD_FIREWALL_APPLY === 'true' } = {}) {
  const configured = Boolean(token && accountId);
  const base = accountId ? `https://api.cloudflare.com/client/v4/accounts/${accountId}/firewall/access_rules/rules` : null;
  const request = async (path, options = {}) => {
    if (!configured) throw new Error('Cloudflare credentials are not configured');
    const response = await fetchImpl(`${base}${path}`, {
      ...options,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(options.headers ?? {}) },
      signal: AbortSignal.timeout(8000),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || body.success === false) throw new Error(`Cloudflare HTTP ${response.status}: ${body.errors?.[0]?.message ?? 'request failed'}`);
    return body;
  };
  return {
    key: 'cloudflare',
    kind: 'cloudflare',
    available: configured,
    applyEnabled,
    async health() {
      if (!configured) return { ok: false, code: 'unavailable', detail: 'SF_CLOUDFLARE_API_TOKEN and SF_CLOUDFLARE_ACCOUNT_ID are not configured' };
      try {
        await request('?per_page=1');
        return { ok: true, detail: 'Cloudflare firewall API reachable' };
      } catch (error) {
        return { ok: false, code: 'error', detail: String(error.message).slice(0, 200) };
      }
    },
    async list(ip) {
      const body = await request(`?per_page=100${ip ? `&configuration_target=ip&configuration_value=${encodeURIComponent(ip)}` : ''}`);
      return (body.result ?? []).map((rule) => ({ id: rule.id, ip: rule.configuration?.value, mode: rule.mode }));
    },
    async block(ip, { expiresAt, notes } = {}) {
      if (!applyEnabled) throw new Error('Firewall apply is disabled (TRISHIELD_FIREWALL_APPLY)');
      const body = await request('', {
        method: 'POST',
        body: JSON.stringify({
          mode: 'block',
          configuration: { target: 'ip', value: ip },
          notes: String(notes ?? 'SecureFlow TriShield').slice(0, 200),
          ...(expiresAt ? { expires_on: expiresAt } : {}),
        }),
      });
      return { providerRef: body.result?.id ?? null };
    },
    async unblock(_ip, providerRef) {
      if (!providerRef) throw new Error('Cloudflare rule id is required');
      await request(`/${providerRef}`, { method: 'DELETE' });
      return { providerRef };
    },
    async verify(ip) {
      try {
        const rules = await this.list(ip);
        return { verified: rules.some((rule) => rule.ip === ip), detail: rules.length ? 'rule present' : 'rule not present' };
      } catch (error) {
        return { verified: false, detail: String(error.message).slice(0, 200) };
      }
    },
  };
}

export function firewallProviders(env = process.env) {
  const nft = createNftConnector({ bin: env.SF_NFT_BIN || 'nft', applyEnabled: env.TRISHIELD_FIREWALL_APPLY === 'true' });
  const cf = createCloudflareConnector({ applyEnabled: env.TRISHIELD_FIREWALL_APPLY === 'true' });
  return [
    {
      key: 'nftables', name: 'Linux nftables', kind: 'host',
      configured: process.platform === 'linux',
      available: nft.available,
      applyEnabled: nft.available && nft.applyEnabled,
      status: nft.available ? 'CONFIGURED' : 'UNAVAILABLE',
      detail: nft.available ? 'Local nftables connector. Run a health check to verify the table.' : 'Requires a Linux host with nft installed.',
    },
    {
      key: 'cloudflare', name: 'Cloudflare firewall', kind: 'cloud',
      configured: cf.available,
      available: cf.available,
      applyEnabled: cf.available && cf.applyEnabled,
      status: cf.available ? 'CONFIGURED' : 'UNAVAILABLE',
      detail: cf.available ? 'Account firewall access rules. Credentials are environment only.' : 'SF_CLOUDFLARE_API_TOKEN and SF_CLOUDFLARE_ACCOUNT_ID are not configured.',
    },
  ];
}

function healthKey(providerKey) {
  return `trishield-${providerKey}`;
}

function statusFor(orgId, provider) {
  if (!provider.available) return 'UNAVAILABLE';
  const row = get('SELECT status, last_sync_at, last_error FROM integration_configs WHERE org_id = ? AND key = ?', orgId, healthKey(provider.key));
  if (row?.status === 'connected') return 'ACTIVE';
  if (row?.status === 'error') return 'ERROR';
  return 'CONFIGURED';
}

function recordHealth(orgId, providerKey, result) {
  const key = healthKey(providerKey);
  const existing = get('SELECT id FROM integration_configs WHERE org_id = ? AND key = ?', orgId, key);
  const status = result.ok ? 'connected' : 'error';
  if (existing) {
    run('UPDATE integration_configs SET status = ?, last_sync_at = ?, last_error = ?, updated_at = ? WHERE id = ?',
      status, result.ok ? nowIso() : null, result.ok ? null : String(result.detail ?? 'health check failed').slice(0, 300), nowIso(), existing.id);
  } else {
    run(
      `INSERT INTO integration_configs (id, org_id, key, name, category, status, config, last_sync_at, last_error, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'trishield', ?, '{}', ?, ?, ?, ?)`,
      newId('int'), orgId, key, providerKey === 'nftables' ? 'Linux nftables' : 'Cloudflare firewall', status,
      result.ok ? nowIso() : null, result.ok ? null : String(result.detail ?? 'health check failed').slice(0, 300), nowIso(), nowIso(),
    );
  }
}

export async function refreshFirewallHealth(orgId, options = {}) {
  const results = [];
  for (const provider of firewallProviders()) {
    if (!provider.available) {
      recordHealth(orgId, provider.key, { ok: false, detail: provider.detail });
      results.push({ key: provider.key, ok: false, status: 'UNAVAILABLE', detail: provider.detail });
      continue;
    }
    const connector = providerConnector(provider.key, options);
    const health = await connector.health();
    recordHealth(orgId, provider.key, health);
    results.push({ key: provider.key, ok: health.ok, status: health.ok ? 'ACTIVE' : 'ERROR', detail: health.detail });
  }
  return results;
}

function providerConnector(key, options = {}) {
  if (key === 'nftables') return createNftConnector(options);
  if (key === 'cloudflare') return createCloudflareConnector(options);
  throw notFound('Unknown firewall provider');
}

function actionRow(row) {
  return {
    id: row.id,
    providerKey: row.provider_key,
    type: row.type,
    targetIp: row.target_ip,
    cidr: row.cidr,
    reason: row.reason,
    riskClass: row.risk_class,
    status: row.status,
    approvalRequired: row.approval_required === 1,
    requestedBy: row.requested_by,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at,
    expiresAt: row.expires_at,
    permanent: row.permanent === 1,
    providerRef: row.provider_ref,
    verification: parseJson(row.verification, {}),
    error: row.error,
    metadata: parseJson(row.metadata, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function listActions(orgId, { status } = {}) {
  const params = [orgId];
  const where = ['org_id = ?'];
  if (status) { where.push('status = ?'); params.push(status); }
  return all(`SELECT * FROM firewall_actions WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT 100`, ...params).map(actionRow);
}

export function listRules(orgId) {
  return all('SELECT * FROM firewall_rules WHERE org_id = ? ORDER BY created_at DESC LIMIT 200', orgId).map((row) => ({
    id: row.id,
    providerKey: row.provider_key,
    externalId: row.external_id,
    direction: row.direction,
    action: row.action,
    family: row.family,
    cidr: row.cidr,
    protocol: row.protocol,
    port: row.port,
    comment: row.comment,
    state: row.state,
    expiresAt: row.expires_at,
    createdBy: row.created_by,
    createdAt: row.created_at,
    verifiedAt: row.verified_at,
    metadata: parseJson(row.metadata, {}),
  }));
}

export function proposeAction({ orgId, user, providerKey, type, targetIp, reason, expiresAt, permanent = false, idempotencyKey, connectorOptions = {} }) {
  if (!['block_ip', 'unblock_ip'].includes(type)) throw badRequest('Unsupported firewall action');
  if (!String(reason ?? '').trim()) throw badRequest('A reason is required for a firewall change');
  const classified = classifyAddress(targetIp);
  if (!classified) throw badRequest('A valid IPv4 or IPv6 address is required');
  if (classifyAddress(targetIp).scope !== 'public') {
    throw badRequest('Only public addresses can be blocked from the firewall');
  }
  const protectedAddress = addressIsProtected(orgId, targetIp);
  if (type === 'block_ip' && protectedAddress.protected) {
    throw conflict(`Refusing to block ${targetIp}: ${protectedAddress.reason}`);
  }
  const provider = firewallProviders().find((item) => item.key === providerKey);
  if (!provider) throw notFound('Unknown firewall provider');
  if (!provider.available) throw conflict(`${provider.name} is not available: ${provider.detail}`);
  const active = get('SELECT COUNT(*) AS c FROM firewall_rules WHERE org_id = ? AND state = \'active\'', orgId).c;
  if (active >= MAX_ACTIVE_RULES) throw conflict('The active firewall rule limit has been reached');
  if (permanent && user?.role !== 'admin') throw badRequest('Permanent blocks require an administrator');
  if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) throw badRequest('Expiry must be in the future');
  const riskClass = permanent ? 'high' : 'restricted';
  const approvalRequired = riskClass !== 'low';
  const key = idempotencyKey || `${providerKey}:${type}:${targetIp}:${expiresAt ?? 'permanent'}`;
  const existing = get('SELECT * FROM firewall_actions WHERE org_id = ? AND idempotency_key = ?', orgId, key);
  if (existing) return { action: actionRow(existing), duplicate: true };
  // A repeated request for the same live target must not queue a second approval.
  const open = get(
    `SELECT * FROM firewall_actions WHERE org_id = ? AND provider_key = ? AND type = ? AND target_ip = ?
       AND status IN ('proposed', 'awaiting_approval', 'approved', 'executing', 'verifying') ORDER BY created_at DESC LIMIT 1`,
    orgId, providerKey, type, classified.address,
  );
  if (open) return { action: actionRow(open), duplicate: true };
  const id = newId('fwa');
  const ts = nowIso();
  run(
    `INSERT INTO firewall_actions (id, org_id, provider_key, type, target_ip, cidr, reason, risk_class, status,
       approval_required, requested_by, idempotency_key, expires_at, permanent, verification, metadata, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?, ?)`,
    id, orgId, providerKey, type, classified.address, `${classified.address}/${classified.family === 'ipv6' ? 128 : 32}`,
    String(reason).trim().slice(0, 500), riskClass, approvalRequired ? 'awaiting_approval' : 'approved',
    approvalRequired ? 1 : 0, user?.id ?? null, key.slice(0, 200), expiresAt ?? null, permanent ? 1 : 0, ts, ts,
  );
  return { action: actionRow(get('SELECT * FROM firewall_actions WHERE id = ?', id)), duplicate: false };
}

export function approveAction(orgId, id, user) {
  if (user?.role !== 'admin') throw badRequest('Only an administrator can approve a firewall change');
  const action = get('SELECT * FROM firewall_actions WHERE id = ? AND org_id = ?', id, orgId);
  if (!action) throw notFound('Action not found');
  if (action.status !== 'awaiting_approval') throw conflict('This action is not awaiting approval');
  if (action.expires_at && new Date(action.expires_at).getTime() <= Date.now()) {
    run('UPDATE firewall_actions SET status = \'expired\', updated_at = ? WHERE id = ?', nowIso(), id);
    throw conflict('This action has expired');
  }
  run(
    'UPDATE firewall_actions SET status = \'approved\', approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?',
    user.id, nowIso(), nowIso(), id,
  );
  return actionRow(get('SELECT * FROM firewall_actions WHERE id = ?', id));
}

export function rejectAction(orgId, id, user) {
  if (user?.role !== 'admin') throw badRequest('Only an administrator can reject a firewall change');
  const action = get('SELECT * FROM firewall_actions WHERE id = ? AND org_id = ?', id, orgId);
  if (!action) throw notFound('Action not found');
  if (!['awaiting_approval', 'approved'].includes(action.status)) throw conflict('This action cannot be rejected');
  run('UPDATE firewall_actions SET status = \'rejected\', updated_at = ? WHERE id = ?', nowIso(), id);
  return actionRow(get('SELECT * FROM firewall_actions WHERE id = ?', id));
}

export async function executeAction(orgId, id, user, { connectorOptions = {} } = {}) {
  const action = get('SELECT * FROM firewall_actions WHERE id = ? AND org_id = ?', id, orgId);
  if (!action) throw notFound('Action not found');
  if (action.status === 'succeeded') return actionRow(action);
  if (!['approved', 'executing', 'verifying'].includes(action.status)) throw conflict('This action is not approved for execution');
  if (action.expires_at && new Date(action.expires_at).getTime() <= Date.now()) {
    run('UPDATE firewall_actions SET status = \'expired\', updated_at = ? WHERE id = ?', nowIso(), id);
    throw conflict('This action has expired');
  }
  const provider = firewallProviders().find((item) => item.key === action.provider_key);
  if (!provider?.available) throw conflict(`${action.provider_key} is not available`);
  if (!provider.applyEnabled) throw conflict('Firewall apply is disabled by configuration; no rule was changed');
  const connector = providerConnector(action.provider_key, connectorOptions);
  run('UPDATE firewall_actions SET status = \'executing\', error = NULL, updated_at = ? WHERE id = ?', nowIso(), id);
  try {
    const result = action.type === 'unblock_ip'
      ? await connector.unblock(action.target_ip, action.provider_ref)
      : await connector.block(action.target_ip, { expiresAt: action.expires_at, notes: action.reason });
    run('UPDATE firewall_actions SET status = \'verifying\', provider_ref = ?, updated_at = ? WHERE id = ?', result.providerRef ?? null, nowIso(), id);
    const verification = await connector.verify(action.target_ip);
    if (!verification.verified) throw new Error(`Provider did not confirm the rule: ${verification.detail}`);
    const ts = nowIso();
    transaction(() => {
      run(
        'UPDATE firewall_actions SET status = \'succeeded\', verification = ?, error = NULL, updated_at = ? WHERE id = ?',
        JSON.stringify(verification), ts, id,
      );
      const rule = get('SELECT * FROM firewall_rules WHERE org_id = ? AND cidr = ? AND provider_key = ? AND state = \'active\'', orgId, action.cidr, action.provider_key);
      if (action.type === 'unblock_ip') {
        if (rule) run('UPDATE firewall_rules SET state = \'removed\', verified_at = ?, metadata = ? WHERE id = ?', ts, JSON.stringify(verification), rule.id);
      } else if (rule) {
        run('UPDATE firewall_rules SET verified_at = ?, metadata = ? WHERE id = ?', ts, JSON.stringify(verification), rule.id);
      } else {
        run(
          `INSERT INTO firewall_rules (id, org_id, provider_key, external_id, direction, action, family, cidr, protocol, port,
             comment, state, expires_at, created_by, created_at, verified_at, metadata)
           VALUES (?, ?, ?, ?, 'inbound', 'block', ?, ?, 'any', NULL, ?, 'active', ?, ?, ?, ?, ?)`,
          newId('fwr'), orgId, action.provider_key, result.providerRef ?? null,
          classifyAddress(action.target_ip).family, action.cidr, action.reason.slice(0, 120),
          action.expires_at, user.id, ts, ts, JSON.stringify(verification),
        );
      }
    });
    return actionRow(get('SELECT * FROM firewall_actions WHERE id = ?', id));
  } catch (error) {
    run('UPDATE firewall_actions SET status = \'failed\', error = ?, updated_at = ? WHERE id = ?',
      String(error.message).slice(0, 500), nowIso(), id);
    throw conflict(`Firewall change failed: ${error.message}`);
  }
}

export async function rollbackAction(orgId, id, user, { connectorOptions = {} } = {}) {
  const action = get('SELECT * FROM firewall_actions WHERE id = ? AND org_id = ?', id, orgId);
  if (!action) throw notFound('Action not found');
  if (action.type !== 'block_ip' || action.status !== 'succeeded') throw conflict('Only a successful block can be rolled back');
  const connector = providerConnector(action.provider_key, connectorOptions);
  const result = await connector.unblock(action.target_ip, action.provider_ref);
  const verification = await connector.verify(action.target_ip);
  const ts = nowIso();
  run('UPDATE firewall_actions SET status = \'rolled_back\', verification = ?, updated_at = ? WHERE id = ?',
    JSON.stringify({ ...verification, rollback: result }), ts, id);
  run('UPDATE firewall_rules SET state = \'removed\', verified_at = ? WHERE org_id = ? AND cidr = ? AND provider_key = ? AND state = \'active\'',
    ts, orgId, action.cidr, action.provider_key);
  return actionRow(get('SELECT * FROM firewall_actions WHERE id = ?', id));
}

export function firewallStatus(orgId) {
  const providers = firewallProviders().map((provider) => ({
    ...provider,
    status: statusFor(orgId, provider),
    lastSyncAt: get('SELECT last_sync_at FROM integration_configs WHERE org_id = ? AND key = ?', orgId, healthKey(provider.key))?.last_sync_at ?? null,
  }));
  const rules = listRules(orgId);
  const actions = listActions(orgId);
  return {
    providers,
    applyEnabled: providers.some((provider) => provider.applyEnabled),
    activeRules: rules.filter((rule) => rule.state === 'active').length,
    pendingActions: actions.filter((action) => ['proposed', 'awaiting_approval', 'approved'].includes(action.status)).length,
    lastVerifiedAt: actions.filter((action) => action.status === 'succeeded').map((action) => action.updatedAt)[0] ?? null,
    note: 'A configured connector is not ACTIVE until a health check and a verified rule change succeed.',
  };
}
