import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, notFound, ok, created, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { evaluateRules, refreshAssetRisk } from '../services/detection.js';
import { bus } from '../lib/events.js';
import { rateLimit } from '../lib/ratelimit.js';

const router = Router();
router.use(requireAuth);

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const CATEGORIES = ['identity', 'endpoint', 'network', 'application', 'email', 'vulnerability', 'cloud'];
const SOURCES = ['identity-provider', 'sysmon', 'suricata', 'zeek', 'mail-gateway', 'api-gateway', 'edr', 'scanner-import', 'manual', 'wazuh', 'clamav', 'yara'];

const eventSchema = z.object({
  eventType: z.string().trim().min(3).max(60).regex(/^[a-z0-9._-]+$/, 'Use lowercase letters, digits, dots, dashes or underscores'),
  source: z.string().trim().min(2).max(60),
  severity: z.enum(SEVERITIES),
  category: z.enum(CATEGORIES).optional(),
  title: z.string().trim().min(3).max(200),
  description: z.string().trim().max(2000).optional(),
  srcIp: z.string().trim().max(64).optional(),
  destIp: z.string().trim().max(64).optional(),
  userEmail: z.string().trim().max(180).optional(),
  assetId: z.string().trim().max(64).optional(),
  occurredAt: z.string().datetime().optional(),
  raw: z.record(z.string(), z.any()).optional(),
});

/** Ingest normalises an external record and runs the deterministic rules immediately. */
router.post('/', requireRole('analyst', 'admin'), rateLimit({ windowMs: 60_000, max: 600, keyPrefix: 'ingest' }), asyncHandler(async (req, res) => {
  const body = validate(eventSchema, req.body);
  if (body.assetId) {
    const asset = get('SELECT id FROM assets WHERE id = ? AND org_id = ?', body.assetId, req.user.orgId);
    if (!asset) throw notFound('Asset not found in this workspace');
  }
  const id = newId('evt');
  const occurredAt = body.occurredAt ?? nowIso();
  run(
    `INSERT INTO security_events (id, org_id, event_type, source, severity, category, title, description, src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)`,
    id, req.user.orgId, body.eventType, body.source, body.severity, body.category ?? 'endpoint', body.title,
    body.description ?? null, body.srcIp ?? null, body.destIp ?? null, body.userEmail ?? null,
    body.assetId ?? null, JSON.stringify(body.raw ?? {}), occurredAt, nowIso(),
  );
  const detections = evaluateRules(req.user.orgId);
  refreshAssetRisk(req.user.orgId);
  const event = get('SELECT * FROM security_events WHERE id = ?', id);
  const payload = {
    id: event.id, eventType: event.event_type, source: event.source, severity: event.severity,
    category: event.category, title: event.title, srcIp: event.src_ip, destIp: event.dest_ip,
    userEmail: event.user_email, assetId: event.asset_id, occurredAt: event.occurred_at, status: event.status,
  };
  bus.emit('org', { orgId: req.user.orgId, event: 'event.ingested', payload });
  audit(req, 'event.ingested', 'security_event', id, { eventType: body.eventType, severity: body.severity });
  return created(res, { event: payload, detections });
}));

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const params = [req.user.orgId];
  const where = ['e.org_id = ?'];
  if (req.query.severity && SEVERITIES.includes(String(req.query.severity))) { where.push('e.severity = ?'); params.push(String(req.query.severity)); }
  if (req.query.category && CATEGORIES.includes(String(req.query.category))) { where.push('e.category = ?'); params.push(String(req.query.category)); }
  if (req.query.source) { where.push('e.source = ?'); params.push(String(req.query.source)); }
  if (req.query.status) { where.push('e.status = ?'); params.push(String(req.query.status)); }
  if (req.query.assetId) { where.push('e.asset_id = ?'); params.push(String(req.query.assetId)); }
  if (req.query.from) { where.push('e.occurred_at >= ?'); params.push(String(req.query.from)); }
  if (req.query.to) { where.push('e.occurred_at <= ?'); params.push(String(req.query.to)); }
  if (req.query.q) {
    where.push('(e.title LIKE ? OR e.description LIKE ? OR e.event_type LIKE ? OR e.src_ip LIKE ? OR e.user_email LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM security_events e WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT e.*, a.hostname AS asset_hostname FROM security_events e
       LEFT JOIN assets a ON a.id = e.asset_id AND a.org_id = e.org_id
      WHERE ${sqlWhere}
      ORDER BY e.occurred_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map((e) => ({
    id: e.id, eventType: e.event_type, source: e.source, severity: e.severity, category: e.category,
    title: e.title, description: e.description, srcIp: e.src_ip, destIp: e.dest_ip, userEmail: e.user_email,
    assetId: e.asset_id, assetHostname: e.asset_hostname, status: e.status, raw: parseJson(e.raw, {}),
    occurredAt: e.occurred_at, dataOrigin: e.data_origin,
  })), total, { page, limit });
}));

router.get('/facets', asyncHandler(async (req, res) => {
  const severities = all('SELECT severity, COUNT(*) c FROM security_events WHERE org_id = ? GROUP BY severity', req.user.orgId);
  const sources = all('SELECT source, COUNT(*) c FROM security_events WHERE org_id = ? GROUP BY source ORDER BY c DESC LIMIT 12', req.user.orgId);
  const categories = all('SELECT category, COUNT(*) c FROM security_events WHERE org_id = ? GROUP BY category ORDER BY c DESC', req.user.orgId);
  return ok(res, {
    severities: Object.fromEntries(severities.map((s) => [s.severity, s.c])),
    sources: sources.map((s) => ({ source: s.source, count: s.c })),
    categories: categories.map((c) => ({ category: c.category, count: c.c })),
    sourcesAvailable: SOURCES,
    categoriesAvailable: CATEGORIES,
  });
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const e = get(
    `SELECT e.*, a.hostname AS asset_hostname, a.criticality AS asset_criticality
       FROM security_events e LEFT JOIN assets a ON a.id = e.asset_id AND a.org_id = e.org_id
      WHERE e.id = ? AND e.org_id = ?`,
    req.params.id, req.user.orgId,
  );
  if (!e) throw notFound('Event not found');
  const detections = all('SELECT id, title, severity, risk_score, status, detected_at FROM detections WHERE event_id = ? AND org_id = ?', e.id, req.user.orgId);
  const related = all(
    `SELECT id, title, severity, occurred_at FROM security_events
      WHERE org_id = ? AND id != ? AND (src_ip = ? OR asset_id = ?)
      ORDER BY occurred_at DESC LIMIT 10`,
    req.user.orgId, e.id, e.src_ip, e.asset_id,
  );
  return ok(res, {
    id: e.id, eventType: e.event_type, source: e.source, severity: e.severity, category: e.category,
    title: e.title, description: e.description, srcIp: e.src_ip, destIp: e.dest_ip, userEmail: e.user_email,
    assetId: e.asset_id, assetHostname: e.asset_hostname, assetCriticality: e.asset_criticality,
    status: e.status, raw: parseJson(e.raw, {}), occurredAt: e.occurred_at, dataOrigin: e.data_origin,
    detections, related,
  });
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ status: z.enum(['new', 'triaged', 'closed']) }), req.body);
  const existing = get('SELECT id FROM security_events WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!existing) throw notFound('Event not found');
  run('UPDATE security_events SET status = ? WHERE id = ? AND org_id = ?', body.status, req.params.id, req.user.orgId);
  audit(req, 'event.status_changed', 'security_event', req.params.id, { status: body.status });
  return ok(res, { id: req.params.id, status: body.status });
}));

export default router;
