import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, conflict, created, notFound, ok, pageParams, paginated, validate, ApiError } from '../lib/http.js';
import { requireAuth, requireRole, isRecentAuth } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { rateLimit } from '../lib/ratelimit.js';
import {
  approveAction, executeAction, firewallStatus, listActions, listRules, proposeAction,
  refreshFirewallHealth, rejectAction, rollbackAction,
} from '../services/firewall.js';
import {
  createCollector, collectorHealth, endpointSummary, listCollectors, revokeCollector,
} from '../services/trishieldIngest.js';
import {
  addressIsProtected, fingerprintAddress, infrastructureSummary, listInfrastructureAddresses,
  originProtectionStatus, revealAddress, syncInfrastructureAddresses,
} from '../services/infraAddresses.js';
import { ensurePolicies, listPolicies } from '../services/trishieldPolicy.js';

const router = Router();
router.use(requireAuth);

function actionOr404(orgId, id) {
  const row = get('SELECT * FROM firewall_actions WHERE id = ? AND org_id = ?', id, orgId);
  if (!row) throw notFound('Firewall action not found');
  return row;
}

router.get('/overview', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  const infra = infrastructureSummary(orgId);
  const firewall = firewallStatus(orgId);
  const collectors = collectorHealth(orgId);
  const endpoints = endpointSummary(orgId);
  const actions = listActions(orgId);
  const events = all(
    `SELECT source, COUNT(*) AS count FROM security_events
      WHERE org_id = ? AND (source = 'suricata' OR source = 'wazuh' OR source LIKE 'waf:%')
      GROUP BY source`, orgId,
  );
  const mfa = get('SELECT COUNT(*) AS total, SUM(CASE WHEN mfa_enabled = 1 THEN 1 ELSE 0 END) AS enabled FROM users WHERE org_id = ? AND status = \'active\'', orgId);
  const failedLogins = get('SELECT COUNT(*) AS c FROM login_attempts WHERE success = 0 AND created_at >= ?', new Date(Date.now() - 24 * 3600_000).toISOString())?.c ?? 0;
  const perimeterActive = firewall.providers.some((provider) => provider.status === 'ACTIVE')
    || collectors.some((collector) => collector.health === 'ACTIVE');
  const perimeterPresent = firewall.providers.some((provider) => provider.available) || collectors.length > 0;
  const perimeterStatus = perimeterActive ? 'ACTIVE' : perimeterPresent ? 'CONFIGURED' : 'NOT CONFIGURED';
  const endpointActive = endpoints.length > 0 || Boolean(process.env.CLAMAV_HOST);
  return ok(res, {
    layers: [
      {
        key: 'perimeter', name: 'Perimeter and network', status: perimeterStatus,
        detail: `${firewall.providers.filter((provider) => provider.available).length} firewall connector(s) available, ${collectors.filter((c) => c.health === 'ACTIVE').length} collector(s) active`,
      },
      {
        key: 'application', name: 'Application and identity', status: 'ACTIVE',
        detail: `${mfa.enabled ?? 0} of ${mfa.total ?? 0} active users have MFA; ${failedLogins} failed sign-ins in 24h`,
      },
      {
        key: 'endpoint', name: 'Endpoint and data', status: endpointActive ? 'ACTIVE' : 'NOT CONFIGURED',
        detail: `${endpoints.filter((agent) => agent.status === 'online').length} online endpoint agent(s); ClamAV ${process.env.CLAMAV_HOST ? 'configured' : 'not configured'}`,
      },
    ],
    infra,
    firewall,
    collectors,
    endpoints: {
      total: endpoints.length,
      online: endpoints.filter((agent) => agent.status === 'online').length,
      stale: endpoints.filter((agent) => agent.status !== 'online').length,
    },
    eventCounts: Object.fromEntries(events.map((row) => [row.source, row.count])),
    pendingApprovals: actions.filter((action) => action.status === 'awaiting_approval').length,
    recentActions: actions.slice(0, 8),
    origin: originProtectionStatus(),
    note: 'A connector is not ACTIVE until its real health check succeeds. No simulated event is presented as provider telemetry.',
  });
}));

router.get('/status', asyncHandler(async (req, res) => {
  const firewall = firewallStatus(req.user.orgId);
  return ok(res, {
    firewall: firewall.providers,
    collectors: collectorHealth(req.user.orgId),
    applyEnabled: firewall.applyEnabled,
    note: 'Live rule changes require TRISHIELD_FIREWALL_APPLY=true and a reachable provider.',
  });
}));

router.get('/integrations', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  return ok(res, {
    firewall: firewallStatus(orgId).providers,
    collectors: collectorHealth(orgId),
    threatIntel: [
      { key: 'virustotal', status: process.env.VIRUSTOTAL_API_KEY ? 'CONFIGURED' : 'UNAVAILABLE' },
      { key: 'abuseipdb', status: process.env.ABUSEIPDB_API_KEY ? 'CONFIGURED' : 'UNAVAILABLE' },
    ],
    endpoint: [
      { key: 'wazuh', status: listCollectors(orgId).some((collector) => collector.kind === 'wazuh') ? 'CONFIGURED' : 'UNAVAILABLE' },
      { key: 'clamav', status: process.env.CLAMAV_HOST ? 'CONFIGURED' : 'UNAVAILABLE' },
    ],
  });
}));

router.get('/firewall/status', asyncHandler(async (req, res) => {
  return ok(res, firewallStatus(req.user.orgId));
}));

router.get('/firewall/rules', asyncHandler(async (req, res) => {
  return ok(res, { rules: listRules(req.user.orgId), providers: firewallStatus(req.user.orgId).providers });
}));

router.post('/firewall/health', requireRole('admin'), asyncHandler(async (req, res) => {
  const results = await refreshFirewallHealth(req.user.orgId);
  audit(req, 'trishield.firewall.health', 'firewall_provider', null, { results });
  return ok(res, { results, status: firewallStatus(req.user.orgId) });
}));

router.get('/firewall/allowlist', asyncHandler(async (req, res) => {
  const rows = all('SELECT * FROM trishield_allowlist WHERE org_id = ? ORDER BY created_at DESC', req.user.orgId);
  return ok(res, rows.map((row) => ({ id: row.id, address: row.address, note: row.note, createdAt: row.created_at, createdBy: row.created_by })));
}));

router.post('/firewall/allowlist', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ address: z.string().trim().min(3).max(64), note: z.string().trim().max(200).default('') }), req.body);
  const protectedAddress = addressIsProtected(req.user.orgId, body.address);
  if (protectedAddress.reason === 'invalid_address') throw badRequest('A valid IP address is required');
  const existing = get('SELECT id FROM trishield_allowlist WHERE org_id = ? AND address = ?', req.user.orgId, body.address);
  if (existing) throw conflict('That address is already allowlisted');
  const id = newId('alw');
  run('INSERT INTO trishield_allowlist (id, org_id, address, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    id, req.user.orgId, body.address, body.note, req.user.id, nowIso());
  audit(req, 'trishield.allowlist.added', 'ip_allowlist', id, { address: body.address });
  return created(res, { id });
}));

router.delete('/firewall/allowlist/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM trishield_allowlist WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Allowlist entry not found');
  run('DELETE FROM trishield_allowlist WHERE id = ?', row.id);
  audit(req, 'trishield.allowlist.removed', 'ip_allowlist', row.id, { address: row.address });
  return ok(res, { removed: true });
}));

router.get('/actions', asyncHandler(async (req, res) => {
  return ok(res, listActions(req.user.orgId, { status: req.query.status ? String(req.query.status) : undefined }));
}));

router.post('/actions', requireRole('analyst', 'admin'), rateLimit({ windowMs: 60_000, max: 10, keyPrefix: 'trishield-action', failMode: 'closed' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    providerKey: z.enum(['nftables', 'cloudflare']),
    type: z.enum(['block_ip', 'unblock_ip']),
    targetIp: z.string().trim().min(3).max(64),
    reason: z.string().trim().min(6).max(500),
    expiresMinutes: z.number().int().min(1).max(10_080).optional(),
    permanent: z.boolean().default(false),
  }), req.body);
  const expiresAt = body.permanent ? null : new Date(Date.now() + (body.expiresMinutes ?? 60) * 60_000).toISOString();
  const result = proposeAction({
    orgId: req.user.orgId, user: req.user, providerKey: body.providerKey, type: body.type,
    targetIp: body.targetIp, reason: body.reason, expiresAt, permanent: body.permanent,
  });
  if (!result.duplicate) audit(req, 'trishield.action.proposed', 'firewall_action', result.action.id, { targetIp: body.targetIp, providerKey: body.providerKey });
  return created(res, result);
}));

router.post('/actions/:id/approve', requireRole('admin'), asyncHandler(async (req, res) => {
  const action = approveAction(req.user.orgId, req.params.id, req.user);
  audit(req, 'trishield.action.approved', 'firewall_action', action.id, { targetIp: action.targetIp });
  return ok(res, action);
}));

router.post('/actions/:id/reject', requireRole('admin'), asyncHandler(async (req, res) => {
  const action = rejectAction(req.user.orgId, req.params.id, req.user);
  audit(req, 'trishield.action.rejected', 'firewall_action', action.id, { targetIp: action.targetIp });
  return ok(res, action);
}));

router.post('/actions/:id/execute', requireRole('admin'), asyncHandler(async (req, res) => {
  const existing = actionOr404(req.user.orgId, req.params.id);
  if (existing.permanent === 1 && !isRecentAuth(req)) throw new ApiError(403, 'recent_auth_required', 'Confirm your password again before a permanent firewall change.');
  const action = await executeAction(req.user.orgId, req.params.id, req.user);
  audit(req, 'trishield.action.executed', 'firewall_action', action.id, { targetIp: action.targetIp, verified: action.verification });
  return ok(res, action);
}));

router.post('/actions/:id/rollback', requireRole('admin'), asyncHandler(async (req, res) => {
  const action = await rollbackAction(req.user.orgId, req.params.id, req.user);
  audit(req, 'trishield.action.rolled_back', 'firewall_action', action.id, { targetIp: action.targetIp });
  return ok(res, action);
}));

router.get('/network/events', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const total = get("SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND source = 'suricata'", req.user.orgId).c;
  const rows = all(
    `SELECT * FROM security_events WHERE org_id = ? AND source = 'suricata' ORDER BY occurred_at DESC LIMIT ? OFFSET ?`,
    req.user.orgId, limit, offset,
  );
  return paginated(res, rows.map((row) => ({
    id: row.id, eventType: row.event_type, severity: row.severity, title: row.title, description: row.description,
    srcIp: row.src_ip, destIp: row.dest_ip, occurredAt: row.occurred_at, status: row.status,
    synthetic: parseJson(row.raw, {}).synthetic === true, raw: parseJson(row.raw, {}),
  })), total, { page, limit });
}));

router.get('/waf/events', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const total = get("SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND source LIKE 'waf:%'", req.user.orgId).c;
  const rows = all(
    `SELECT * FROM security_events WHERE org_id = ? AND source LIKE 'waf:%' ORDER BY occurred_at DESC LIMIT ? OFFSET ?`,
    req.user.orgId, limit, offset,
  );
  return paginated(res, rows.map((row) => ({
    id: row.id, source: row.source, eventType: row.event_type, severity: row.severity, title: row.title,
    srcIp: row.src_ip, occurredAt: row.occurred_at,
    synthetic: parseJson(row.raw, {}).synthetic === true, raw: parseJson(row.raw, {}),
  })), total, { page, limit });
}));

router.get('/endpoints', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  const agents = endpointSummary(orgId);
  const scans = all(
    `SELECT id, filename, case_ref, status, scan_status, scan_detail, created_at FROM forensic_evidence
      WHERE org_id = ? ORDER BY created_at DESC LIMIT 20`, orgId,
  );
  return ok(res, {
    agents,
    collectors: collectorHealth(orgId),
    clamav: { configured: Boolean(process.env.CLAMAV_HOST), status: process.env.CLAMAV_HOST ? 'CONFIGURED' : 'UNAVAILABLE' },
    malwareScans: scans.map((row) => ({
      id: row.id, filename: row.filename, caseRef: row.case_ref, status: row.status,
      scanStatus: row.scan_status, scanDetail: row.scan_detail, createdAt: row.created_at,
    })),
  });
}));

router.get('/ip/addresses', asyncHandler(async (req, res) => {
  return ok(res, {
    addresses: listInfrastructureAddresses(req.user.orgId),
    summary: infrastructureSummary(req.user.orgId),
    origin: originProtectionStatus(),
  });
}));

router.post('/ip/discover', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ includePublic: z.boolean().default(false) }), req.body ?? {});
  const result = await syncInfrastructureAddresses(req.user.orgId, { includePublic: body.includePublic });
  audit(req, 'trishield.ip.discovered', 'infra_address', null, result);
  return ok(res, { ...result, addresses: listInfrastructureAddresses(req.user.orgId) });
}));

router.post('/ip/:id/reveal', requireRole('admin'), rateLimit({ windowMs: 60_000, max: 10, keyPrefix: 'trishield-ip-reveal', failMode: 'closed' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({ reason: z.string().trim().min(6).max(300) }), req.body);
  const revealed = revealAddress(req.user.orgId, req.params.id, req.user, body.reason);
  audit(req, 'trishield.ip.revealed', 'infra_address', req.params.id, { reason: body.reason, keyVersion: revealed.keyVersion });
  return ok(res, revealed);
}));

router.get('/ip/allowlist', asyncHandler(async (req, res) => {
  const rows = all('SELECT address, note, created_at FROM trishield_allowlist WHERE org_id = ?', req.user.orgId);
  return ok(res, rows);
}));

function policyRow(row) {
  return { id: row.id, key: row.key, enabled: row.enabled === 1, mode: row.mode, config: parseJson(row.config, {}), updatedAt: row.updated_at };
}

router.get('/policies', asyncHandler(async (req, res) => {
  ensurePolicies(req.user.orgId);
  return ok(res, listPolicies(req.user.orgId));
}));

router.patch('/policies/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    enabled: z.boolean().optional(),
    mode: z.enum(['monitor', 'approval', 'auto']).optional(),
    config: z.record(z.string(), z.any()).optional(),
  }), req.body);
  const row = get('SELECT * FROM trishield_policies WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Policy not found');
  const fields = [];
  const params = [];
  if (body.enabled !== undefined) { fields.push('enabled = ?'); params.push(body.enabled ? 1 : 0); }
  if (body.mode !== undefined) { fields.push('mode = ?'); params.push(body.mode); }
  if (body.config !== undefined) { fields.push('config = ?'); params.push(JSON.stringify(body.config)); }
  fields.push('updated_at = ?'); params.push(nowIso(), row.id);
  run(`UPDATE trishield_policies SET ${fields.join(', ')} WHERE id = ?`, ...params);
  audit(req, 'trishield.policy.updated', 'security_policy', row.id, { key: row.key, changes: body });
  return ok(res, policyRow(get('SELECT * FROM trishield_policies WHERE id = ?', row.id)));
}));

router.get('/collectors', requireRole('admin'), asyncHandler(async (req, res) => {
  return ok(res, collectorHealth(req.user.orgId));
}));

router.post('/collectors', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ kind: z.enum(['suricata', 'wazuh', 'waf']), name: z.string().trim().min(2).max(80) }), req.body);
  const collector = createCollector(req.user.orgId, { ...body, user: req.user });
  audit(req, 'trishield.collector.created', 'collector', collector.id, { kind: body.kind });
  return created(res, collector);
}));

router.delete('/collectors/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const result = revokeCollector(req.user.orgId, req.params.id);
  audit(req, 'trishield.collector.revoked', 'collector', result.id, {});
  return ok(res, result);
}));

export default router;
