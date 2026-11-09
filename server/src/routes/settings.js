import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson, db } from '../db.js';
import { asyncHandler, badRequest, conflict, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { verifyAuditChain } from '../lib/audit.js';
import { hashPasswordAsync } from '../lib/auth.js';
import { mirofishStatus } from '../services/mirofish.js';

const router = Router();
router.use(requireAuth);

router.get('/organization', asyncHandler(async (req, res) => {
  const org = get('SELECT * FROM organizations WHERE id = ?', req.user.orgId);
  if (!org) throw notFound('Organization not found');
  const users = get('SELECT COUNT(*) c FROM users WHERE org_id = ?', org.id).c;
  const assets = get('SELECT COUNT(*) c FROM assets WHERE org_id = ?', org.id).c;
  return ok(res, {
    id: org.id, name: org.name, slug: org.slug, plan: org.plan, settings: parseJson(org.settings, {}),
    createdAt: org.created_at, userCount: users, assetCount: assets,
  });
}));

router.patch('/organization', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    name: z.string().trim().min(2).max(80).optional(),
    settings: z.object({
      timezone: z.string().trim().max(60).optional(),
      retentionDays: z.number().int().min(7).max(3650).optional(),
      dataResidency: z.string().trim().max(60).optional(),
      contactEmail: z.string().trim().email().max(180).optional().nullable(),
      automationPaused: z.boolean().optional(),
      mfaPolicy: z.enum(['optional', 'admins', 'all']).optional(),
    }).optional(),
  }), req.body);
  const org = get('SELECT * FROM organizations WHERE id = ?', req.user.orgId);
  if (!org) throw notFound('Organization not found');
  const settings = { ...parseJson(org.settings, {}), ...(body.settings ?? {}) };
  run('UPDATE organizations SET name = ?, settings = ?, updated_at = ? WHERE id = ?',
    body.name ?? org.name, JSON.stringify(settings), nowIso(), org.id);
  audit(req, 'organization.updated', 'organization', org.id, { fields: Object.keys(body) });
  return ok(res, { id: org.id, name: body.name ?? org.name, settings });
}));

router.get('/users', asyncHandler(async (req, res) => {
  const rows = all(
    `SELECT id, email, name, role, status, last_login_at, created_at FROM users WHERE org_id = ? ORDER BY created_at`, req.user.orgId,
  );
  return ok(res, rows.map((u) => ({
    id: u.id, email: u.email, name: u.name, role: u.role, status: u.status,
    lastLoginAt: u.last_login_at, createdAt: u.created_at, isSelf: u.id === req.user.id,
  })));
}));

router.post('/users', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    name: z.string().trim().min(2).max(80),
    email: z.string().trim().toLowerCase().email().max(180),
    role: z.enum(['admin', 'analyst', 'viewer']),
    password: z.string().min(10).max(200),
  }), req.body);
  if (get('SELECT id FROM users WHERE email = ?', body.email)) throw conflict('An account with this email already exists');
  const id = newId('usr');
  run(
    `INSERT INTO users (id, org_id, email, name, password_hash, role, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
    id, req.user.orgId, body.email, body.name, await hashPasswordAsync(body.password), body.role, nowIso(), nowIso(),
  );
  audit(req, 'user.created', 'user', id, { role: body.role, email: body.email });
  return created(res, { id, email: body.email, name: body.name, role: body.role, status: 'active' });
}));

router.patch('/users/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    role: z.enum(['admin', 'analyst', 'viewer']).optional(),
    status: z.enum(['active', 'disabled']).optional(),
    name: z.string().trim().min(2).max(80).optional(),
  }), req.body);
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!user) throw notFound('User not found');
  if (user.id === req.user.id && body.role && body.role !== 'admin') {
    throw badRequest('You cannot remove your own admin role. Ask another admin.');
  }
  if (user.role === 'admin' && (body.role && body.role !== 'admin' || body.status === 'disabled')) {
    const admins = get(`SELECT COUNT(*) c FROM users WHERE org_id = ? AND role = 'admin' AND status = 'active'`, req.user.orgId).c;
    if (admins <= 1) throw badRequest('At least one active admin is required');
  }
  const fields = [];
  const params = [];
  if (body.role) { fields.push('role = ?'); params.push(body.role); }
  if (body.status) { fields.push('status = ?'); params.push(body.status); }
  if (body.name) { fields.push('name = ?'); params.push(body.name); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE users SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, user.id, req.user.orgId);
  if (body.status === 'disabled') run('DELETE FROM sessions WHERE user_id = ?', user.id);
  audit(req, 'user.updated', 'user', user.id, { fields: Object.keys(body) });
  return ok(res, { id: user.id, role: body.role ?? user.role, status: body.status ?? user.status });
}));

const INTEGRATION_CATALOG = [
  { key: 'wazuh', name: 'Wazuh', category: 'siem', env: ['WAZUH_API_URL', 'WAZUH_API_TOKEN'], description: 'Pull authentication and file integrity alerts from the Wazuh manager.' },
  { key: 'sysmon', name: 'Sysmon', category: 'endpoint', env: ['SYSMON_COLLECTOR_URL'], description: 'Collect process, network and file telemetry forwarded by Sysmon.' },
  { key: 'suricata', name: 'Suricata', category: 'network', env: ['SURICATA_EVE_PATH'], description: 'Read IDS alerts and flow records from eve.json.' },
  { key: 'zeek', name: 'Zeek', category: 'network', env: ['ZEEK_LOG_PATH'], description: 'Ingest connection and DNS logs produced by Zeek.' },
  { key: 'clamav', name: 'ClamAV', category: 'malware', env: ['CLAMAV_HOST'], description: 'Query the ClamAV daemon for file reputation in evidence review.' },
  { key: 'yara', name: 'YARA', category: 'malware', env: ['YARA_RULES_PATH'], description: 'Match evidence against local YARA rules.' },
  { key: 'virustotal', name: 'VirusTotal', category: 'threat-intel', env: ['VIRUSTOTAL_API_KEY'], description: 'Reputation lookups for hashes, domains and URLs. Indicators leave the platform.' },
  { key: 'abuseipdb', name: 'AbuseIPDB', category: 'threat-intel', env: ['ABUSEIPDB_API_KEY'], description: 'Abuse confidence scores for IP addresses. Addresses leave the platform.' },
  { key: 'mirofish', name: 'MiroFish', category: 'simulation', env: ['MIROFISH_BASE_URL'], description: 'Separate AGPL-3.0 simulation service; runs are imported read only.' },
  { key: 'api-anything', name: 'API Anything', category: 'developer-tool', env: ['API_ANYTHING_ENABLED'], description: 'Optional local MCP tool for development. Never used at runtime by SecureFlow.' },
];

router.get('/integrations', asyncHandler(async (req, res) => {
  const rows = all('SELECT * FROM integration_configs WHERE org_id = ?', req.user.orgId);
  const byKey = Object.fromEntries(rows.map((r) => [r.key, r]));
  const miro = await mirofishStatus();
  const data = INTEGRATION_CATALOG.map((item) => {
    const row = byKey[item.key];
    const envPresent = item.env.some((key) => Boolean(process.env[key]));
    let status = row?.status ?? 'unconfigured';
    if (envPresent && status === 'unconfigured') status = 'configured';
    if (!envPresent && status === 'connected') status = 'configured';
    let detail = null;
    if (item.key === 'mirofish') {
      status = miro.configured ? (miro.reachable ? 'connected' : 'error') : 'unconfigured';
      detail = miro.reason;
    }
    if (item.key === 'api-anything') {
      status = process.env.API_ANYTHING_ENABLED === 'true' ? 'configured' : 'disabled';
      detail = 'Development time tool. Not part of the application runtime.';
    }
    return {
      key: item.key, name: item.name, category: item.category, description: item.description,
      status, envVars: item.env, configured: envPresent || Boolean(row && row.status !== 'unconfigured'),
      detail, lastSyncAt: row?.last_sync_at ?? null,
      config: parseJson(row?.config ?? '{}', {}),
    };
  });
  return ok(res, data);
}));

router.post('/integrations/:key/test', requireRole('admin'), asyncHandler(async (req, res) => {
  const item = INTEGRATION_CATALOG.find((i) => i.key === req.params.key);
  if (!item) throw notFound('Unknown integration');
  if (item.key === 'mirofish') {
    const status = await mirofishStatus();
    run('UPDATE integration_configs SET status = ?, last_error = ?, last_sync_at = ?, updated_at = ? WHERE org_id = ? AND key = ?',
      status.reachable ? 'connected' : status.configured ? 'error' : 'unconfigured',
      status.reason ?? null, status.reachable ? nowIso() : null, nowIso(), req.user.orgId, 'mirofish');
    return ok(res, { key: 'mirofish', status: status.reachable ? 'connected' : 'error', detail: status.reason, latencyMs: status.latencyMs });
  }
  if (item.key === 'api-anything') {
    return ok(res, {
      key: 'api-anything', status: process.env.API_ANYTHING_ENABLED === 'true' ? 'configured' : 'disabled',
      detail: 'API Anything is a local development tool. SecureFlow does not call it at runtime, so there is no connectivity test to run.',
    });
  }
  const present = item.env.filter((key) => Boolean(process.env[key]));
  run('UPDATE integration_configs SET status = ?, last_sync_at = ?, updated_at = ? WHERE org_id = ? AND key = ?',
    present.length ? 'configured' : 'unconfigured', present.length ? nowIso() : null, nowIso(), req.user.orgId, item.key);
  return ok(res, {
    key: item.key,
    status: present.length ? 'configured' : 'unconfigured',
    detail: present.length
      ? `Environment variables present: ${present.join(', ')}. Adapter health checks are not implemented for this integration, so no live call was made.`
      : `No configuration found. Required: ${item.env.join(', ')}.`,
  });
}));

router.patch('/integrations/:key', requireRole('admin'), asyncHandler(async (req, res) => {
  const item = INTEGRATION_CATALOG.find((i) => i.key === req.params.key);
  if (!item) throw notFound('Unknown integration');
  const body = validate(z.object({
    status: z.enum(['unconfigured', 'configured', 'disabled']).optional(),
    config: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  }), req.body);
  const row = get('SELECT * FROM integration_configs WHERE org_id = ? AND key = ?', req.user.orgId, item.key);
  if (!row) throw notFound('Integration record not found');
  const config = { ...parseJson(row.config, {}), ...(body.config ?? {}) };
  // Secrets are never stored here. Config accepts non-secret metadata only.
  for (const key of Object.keys(config)) {
    if (/key|token|secret|password/i.test(key)) delete config[key];
  }
  run('UPDATE integration_configs SET status = ?, config = ?, updated_at = ? WHERE id = ?',
    body.status ?? row.status, JSON.stringify(config), nowIso(), row.id);
  audit(req, 'integration.updated', 'integration_config', row.id, { key: item.key, status: body.status });
  return ok(res, { key: item.key, status: body.status ?? row.status, config });
}));

router.get('/audit-logs/verify', requireRole('admin'), asyncHandler(async (req, res) => {
  const result = verifyAuditChain(req.user.orgId);
  return ok(res, result);
}));

router.get('/audit-logs', requireRole('admin'), asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 30 });
  const where = ['org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.action) { where.push('action LIKE ?'); params.push(`%${String(req.query.action).slice(0, 60)}%`); }
  if (req.query.actor) { where.push('actor_email LIKE ?'); params.push(`%${String(req.query.actor).slice(0, 60)}%`); }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM audit_logs WHERE ${sqlWhere}`, ...params).c;
  const rows = all(`SELECT * FROM audit_logs WHERE ${sqlWhere} ORDER BY created_at DESC LIMIT ? OFFSET ?`, ...params, limit, offset);
  return paginated(res, rows.map((a) => ({
    id: a.id, actorEmail: a.actor_email, action: a.action, resourceType: a.resource_type,
    resourceId: a.resource_id, ip: a.ip, result: a.result, requestId: a.request_id,
    metadata: parseJson(a.metadata, {}), createdAt: a.created_at,
  })), total, { page, limit });
}));

router.get('/health', asyncHandler(async (req, res) => {
  const checks = [];
  try {
    db.prepare('SELECT 1').get();
    checks.push({ name: 'Database', status: 'ok', detail: 'SQLite (WAL) reachable' });
  } catch (err) {
    checks.push({ name: 'Database', status: 'error', detail: err.message });
  }
  checks.push({ name: 'Simulation engine', status: 'ok', detail: 'SecureFlow native engine ready; MiroFish is optional' });
  const miro = await mirofishStatus();
  checks.push({
    name: 'MiroFish adapter',
    status: miro.configured ? (miro.reachable ? 'ok' : 'error') : 'unconfigured',
    detail: miro.reason ?? `Reachable in ${miro.latencyMs} ms`,
  });
  const counts = {
    events: get('SELECT COUNT(*) c FROM security_events WHERE org_id = ?', req.user.orgId).c,
    detections: get('SELECT COUNT(*) c FROM detections WHERE org_id = ?', req.user.orgId).c,
    incidents: get('SELECT COUNT(*) c FROM incidents WHERE org_id = ?', req.user.orgId).c,
    simulations: get('SELECT COUNT(*) c FROM simulations WHERE org_id = ?', req.user.orgId).c,
  };
  return ok(res, {
    status: checks.every((c) => c.status !== 'error') ? 'healthy' : 'degraded',
    uptimeSeconds: Math.round(process.uptime()),
    node: process.version,
    environment: process.env.NODE_ENV ?? 'development',
    checks,
    counts,
    checkedAt: nowIso(),
  });
}));

export default router;
