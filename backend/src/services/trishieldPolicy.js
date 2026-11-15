import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { addressIsProtected, classifyAddress } from './infraAddresses.js';
import { approveAction, executeAction, proposeAction } from './firewall.js';
import { audit } from '../lib/audit.js';

export const DEFAULT_POLICIES = [
  {
    key: 'firewall.auto_block',
    enabled: 0,
    mode: 'approval',
    config: { minSeverity: 'high', durationMinutes: 60, categories: ['network', 'application'] },
  },
];

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function ensurePolicies(orgId) {
  for (const item of DEFAULT_POLICIES) {
    const existing = get('SELECT id FROM trishield_policies WHERE org_id = ? AND key = ?', orgId, item.key);
    if (!existing) {
      run(
        `INSERT INTO trishield_policies (id, org_id, key, enabled, mode, config, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('pol'), orgId, item.key, item.enabled, item.mode, JSON.stringify(item.config), nowIso(), nowIso(),
      );
    }
  }
}

export function listPolicies(orgId) {
  ensurePolicies(orgId);
  return all('SELECT * FROM trishield_policies WHERE org_id = ? ORDER BY key', orgId).map((row) => ({
    id: row.id, key: row.key, enabled: row.enabled === 1, mode: row.mode,
    config: parseJson(row.config, {}), updatedAt: row.updated_at,
  }));
}

/**
 * Deterministic policy evaluation. It can only propose or execute a temporary
 * block for a public source address that is not protected. Permanent changes and
 * high-impact infrastructure never come from this path.
 */
export async function evaluateEventForBlock({ orgId, event, env = process.env, connectorOptions = {} }) {
  if (!event?.srcIp || !event?.severity || !event?.dedupeKey) return { decision: 'none', reason: 'missing_fields' };
  // Synthetic demo telemetry must never reach a real provider.
  if (event.synthetic) return { decision: 'skipped', reason: 'synthetic_event' };
  const policy = get('SELECT * FROM trishield_policies WHERE org_id = ? AND key = \'firewall.auto_block\'', orgId);
  if (!policy || policy.enabled !== 1) return { decision: 'none', reason: 'policy_disabled' };
  const config = parseJson(policy.config, {});
  const minSeverity = config.minSeverity ?? 'high';
  if ((SEVERITY_RANK[event.severity] ?? 0) < (SEVERITY_RANK[minSeverity] ?? 3)) {
    return { decision: 'none', reason: 'below_severity' };
  }
  const categories = Array.isArray(config.categories) ? config.categories : ['network', 'application'];
  if (!categories.includes(event.category)) return { decision: 'none', reason: 'category_excluded' };
  const classified = classifyAddress(event.srcIp);
  if (!classified || classified.scope !== 'public') return { decision: 'none', reason: 'non_public_source' };
  const protectedAddress = addressIsProtected(orgId, event.srcIp);
  if (protectedAddress.protected) return { decision: 'none', reason: protectedAddress.reason };
  if (policy.mode === 'monitor') return { decision: 'monitor', reason: 'monitor_mode', targetIp: event.srcIp };

  const minutes = Math.min(Math.max(Number(config.durationMinutes) || 60, 5), 1440);
  const expiresAt = new Date(Date.now() + minutes * 60_000).toISOString();
  let proposed;
  try {
    proposed = proposeAction({
      orgId,
      user: { id: null, role: 'admin' },
      providerKey: env.TRISHIELD_PROVIDER || 'nftables',
      type: 'block_ip',
      targetIp: event.srcIp,
      reason: `Automatic policy: ${event.severity} ${event.eventType} from ${event.title}`.slice(0, 300),
      expiresAt,
      idempotencyKey: `policy:${event.dedupeKey}`,
    });
  } catch (error) {
    return { decision: 'none', reason: 'provider_unavailable', detail: String(error.message).slice(0, 200) };
  }
  if (proposed.duplicate) return { decision: 'duplicate', action: proposed.action };
  const systemReq = { user: { id: null, orgId, email: 'system', role: 'admin' }, ip: null, requestId: null };
  audit(systemReq, 'trishield.policy.action_proposed', 'firewall_action', proposed.action.id, { targetIp: event.srcIp, reason: 'policy', mode: policy.mode });
  if (policy.mode === 'approval') return { decision: 'awaiting_approval', action: proposed.action };

  if (env.TRISHIELD_AUTO_APPLY !== 'true') {
    return { decision: 'awaiting_approval', action: proposed.action, reason: 'auto_apply_disabled' };
  }
  try {
    approveAction(orgId, proposed.action.id, { id: null, role: 'admin' });
    const executed = await executeAction(orgId, proposed.action.id, { id: null, role: 'admin' }, { connectorOptions });
    audit(systemReq, 'trishield.policy.action_executed', 'firewall_action', proposed.action.id, { targetIp: event.srcIp });
    return { decision: 'executed', action: executed };
  } catch (error) {
    return { decision: 'failed', action: proposed.action, detail: String(error.message).slice(0, 200) };
  }
}
