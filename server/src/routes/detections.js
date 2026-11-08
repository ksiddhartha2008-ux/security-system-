import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { evaluateRules, refreshAssetRisk, RULES, SEVERITY_BASE } from '../services/detection.js';

const router = Router();
router.use(requireAuth);

const mapDetection = (d) => ({
  id: d.id, title: d.title, description: d.description, severity: d.severity, riskScore: d.risk_score,
  confidence: d.confidence, status: d.status, detectedAt: d.detected_at,
  ruleName: d.rule_name ?? null, ruleKey: d.rule_key ?? null,
  assetId: d.asset_id, assetHostname: d.asset_hostname ?? null,
  explanation: parseJson(d.explanation, {}),
});

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['d.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('d.status = ?'); params.push(String(req.query.status)); }
  if (req.query.severity) { where.push('d.severity = ?'); params.push(String(req.query.severity)); }
  if (req.query.minRisk) { where.push('d.risk_score >= ?'); params.push(Number(req.query.minRisk) || 0); }
  if (req.query.q) {
    where.push('(d.title LIKE ? OR d.description LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM detections d WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT d.*, r.name AS rule_name, r.key AS rule_key, a.hostname AS asset_hostname
       FROM detections d
       LEFT JOIN detection_rules r ON r.id = d.rule_id
       LEFT JOIN assets a ON a.id = d.asset_id AND a.org_id = d.org_id
      WHERE ${sqlWhere} ORDER BY d.risk_score DESC, d.detected_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map(mapDetection), total, { page, limit });
}));

router.get('/summary', asyncHandler(async (req, res) => {
  const status = all('SELECT status, COUNT(*) c FROM detections WHERE org_id = ? GROUP BY status', req.user.orgId);
  const severity = all('SELECT severity, COUNT(*) c FROM detections WHERE org_id = ? GROUP BY severity', req.user.orgId);
  const byRule = all(
    `SELECT r.key, r.name, COUNT(d.id) c, ROUND(AVG(d.risk_score)) avg_risk
       FROM detection_rules r LEFT JOIN detections d ON d.rule_id = r.id
      WHERE r.org_id = ? GROUP BY r.id ORDER BY c DESC`, req.user.orgId,
  );
  const last24 = get(
    `SELECT COUNT(*) c FROM detections WHERE org_id = ? AND detected_at >= ?`,
    req.user.orgId, new Date(Date.now() - 86_400_000).toISOString(),
  ).c;
  return ok(res, {
    status: Object.fromEntries(status.map((s) => [s.status, s.c])),
    severity: Object.fromEntries(severity.map((s) => [s.severity, s.c])),
    byRule, last24h: last24,
    scoreModel: { base: SEVERITY_BASE, description: 'Base severity plus capped factor weights, asset criticality and confidence lift. Deterministic and explainable.' },
  });
}));

router.get('/rules', asyncHandler(async (req, res) => {
  const rows = all('SELECT * FROM detection_rules WHERE org_id = ? ORDER BY category, name', req.user.orgId);
  return ok(res, rows.map((r) => ({
    id: r.id, key: r.key, name: r.name, category: r.category, severity: r.severity, description: r.description,
    threshold: r.threshold, windowMinutes: r.window_minutes, enabled: r.enabled === 1, updatedAt: r.updated_at,
    supported: RULES.some((rule) => rule.key === r.key),
  })));
}));

router.patch('/rules/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    enabled: z.boolean().optional(),
    threshold: z.number().int().min(1).max(10000).optional(),
    windowMinutes: z.number().int().min(1).max(1440).optional(),
  }), req.body);
  const row = get('SELECT * FROM detection_rules WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Rule not found');
  const fields = [];
  const params = [];
  if (body.enabled !== undefined) { fields.push('enabled = ?'); params.push(body.enabled ? 1 : 0); }
  if (body.threshold !== undefined) { fields.push('threshold = ?'); params.push(body.threshold); }
  if (body.windowMinutes !== undefined) { fields.push('window_minutes = ?'); params.push(body.windowMinutes); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE detection_rules SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'detection.rule_updated', 'detection_rule', row.id, { fields: body });
  return ok(res, mapRule(get('SELECT * FROM detection_rules WHERE id = ?', row.id)));
}));

const mapRule = (r) => ({
  id: r.id, key: r.key, name: r.name, category: r.category, severity: r.severity, description: r.description,
  threshold: r.threshold, windowMinutes: r.window_minutes, enabled: r.enabled === 1,
});

router.post('/run', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const produced = evaluateRules(req.user.orgId);
  refreshAssetRisk(req.user.orgId);
  audit(req, 'detection.rules_run', 'detection', null, { produced: produced.length });
  return ok(res, { produced: produced.length, detections: produced });
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const row = get(
    `SELECT d.*, r.name AS rule_name, r.key AS rule_key, a.hostname AS asset_hostname
       FROM detections d LEFT JOIN detection_rules r ON r.id = d.rule_id
       LEFT JOIN assets a ON a.id = d.asset_id AND a.org_id = d.org_id
      WHERE d.id = ? AND d.org_id = ?`, req.params.id, req.user.orgId,
  );
  if (!row) throw notFound('Detection not found');
  const event = row.event_id ? get('SELECT id, title, description, event_type, src_ip, occurred_at FROM security_events WHERE id = ? AND org_id = ?', row.event_id, req.user.orgId) : null;
  const relatedEvents = all(
    `SELECT id, title, severity, event_type, occurred_at FROM security_events
      WHERE org_id = ? AND (asset_id = ? OR src_ip = ?) ORDER BY occurred_at DESC LIMIT 10`,
    req.user.orgId, row.asset_id, event?.src_ip ?? null,
  );
  return ok(res, { ...mapDetection(row), event, relatedEvents });
}));

router.post('/:id/feedback', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    status: z.enum(['confirmed', 'false_positive', 'closed']),
    note: z.string().trim().max(1000).optional(),
  }), req.body);
  const row = get('SELECT * FROM detections WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Detection not found');
  const explanation = parseJson(row.explanation, {});
  explanation.feedback = { status: body.status, note: body.note ?? null, by: req.user.email, at: nowIso() };
  run('UPDATE detections SET status = ?, explanation = ?, updated_at = ? WHERE id = ? AND org_id = ?',
    body.status, JSON.stringify(explanation), nowIso(), row.id, req.user.orgId);
  audit(req, 'detection.feedback', 'detection', row.id, { status: body.status });
  return ok(res, { id: row.id, status: body.status });
}));

router.post('/:id/promote', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const detection = get('SELECT * FROM detections WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!detection) throw notFound('Detection not found');
  const existing = get(
    `SELECT i.id, i.ref FROM incidents i JOIN incident_events e ON e.incident_id = i.id
      WHERE i.org_id = ? AND json_extract(e.metadata, '$.detectionId') = ? LIMIT 1`,
    req.user.orgId, detection.id,
  );
  if (existing) throw badRequest(`This detection is already linked to incident ${existing.ref}`);
  const year = new Date().getUTCFullYear();
  const count = get('SELECT COUNT(*) c FROM incidents WHERE org_id = ?', req.user.orgId).c;
  const id = newId('inc');
  const ref = `INC-${year}-${1001 + count}`;
  const ts = nowIso();
  run(
    `INSERT INTO incidents (id, org_id, ref, title, description, severity, priority, status, assignee_id, created_by, detected_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?, ?, ?)`,
    id, req.user.orgId, ref, detection.title, detection.description,
    detection.severity, detection.risk_score >= 85 ? 'P1' : detection.severity === 'high' ? 'P2' : 'P3',
    req.user.id, detection.detected_at, ts, ts,
  );
  run(
    `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
     VALUES (?, ?, ?, 'created', ?, ?, ?, ?)`,
    newId('ince'), req.user.orgId, id, `Incident opened from detection ${detection.id}.`, req.user.id,
    JSON.stringify({ detectionId: detection.id, riskScore: detection.risk_score }), ts,
  );
  run(`UPDATE detections SET status = 'confirmed', updated_at = ? WHERE id = ?`, ts, detection.id);
  audit(req, 'detection.promoted', 'incident', id, { detectionId: detection.id, ref });
  return created(res, { incidentId: id, ref });
}));

export default router;
