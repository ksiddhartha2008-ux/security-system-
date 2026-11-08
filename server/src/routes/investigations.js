import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

const mapInv = (i) => ({
  id: i.id, ref: i.ref, title: i.title, hypothesis: i.hypothesis, status: i.status, severity: i.severity,
  ownerId: i.owner_id, owner: i.owner_name ?? null, incidentId: i.incident_id, incidentRef: i.incident_ref ?? null,
  findings: i.findings, createdAt: i.created_at, updatedAt: i.updated_at, noteCount: i.note_count ?? undefined,
});

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 20 });
  const where = ['i.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('i.status = ?'); params.push(String(req.query.status)); }
  if (req.query.q) {
    where.push('(i.title LIKE ? OR i.hypothesis LIKE ? OR i.ref LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM investigations i WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT i.*, u.name AS owner_name, inc.ref AS incident_ref,
            (SELECT COUNT(*) FROM investigation_notes n WHERE n.investigation_id = i.id) AS note_count
       FROM investigations i
       LEFT JOIN users u ON u.id = i.owner_id
       LEFT JOIN incidents inc ON inc.id = i.incident_id
      WHERE ${sqlWhere} ORDER BY i.created_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map(mapInv), total, { page, limit });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    title: z.string().trim().min(4).max(200),
    hypothesis: z.string().trim().max(4000).default(''),
    severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    incidentId: z.string().trim().max(64).optional().nullable(),
  }), req.body);
  if (body.incidentId && !get('SELECT id FROM incidents WHERE id = ? AND org_id = ?', body.incidentId, req.user.orgId)) {
    throw notFound('Incident not found in this workspace');
  }
  const count = get('SELECT COUNT(*) c FROM investigations WHERE org_id = ?', req.user.orgId).c;
  const id = newId('inv');
  const ts = nowIso();
  run(
    `INSERT INTO investigations (id, org_id, ref, title, hypothesis, status, severity, owner_id, incident_id, findings, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, '', ?, ?)`,
    id, req.user.orgId, `INV-${new Date().getUTCFullYear()}-${201 + count}`, body.title, body.hypothesis,
    body.severity, req.user.id, body.incidentId ?? null, ts, ts,
  );
  audit(req, 'investigation.created', 'investigation', id, { title: body.title });
  return created(res, mapInv(get('SELECT i.*, NULL AS owner_name, NULL AS incident_ref FROM investigations i WHERE i.id = ?', id)));
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const row = get(
    `SELECT i.*, u.name AS owner_name, inc.ref AS incident_ref FROM investigations i
       LEFT JOIN users u ON u.id = i.owner_id LEFT JOIN incidents inc ON inc.id = i.incident_id
      WHERE i.id = ? AND i.org_id = ?`, req.params.id, req.user.orgId,
  );
  if (!row) throw notFound('Investigation not found');
  const notes = all(
    `SELECT n.*, u.name AS author FROM investigation_notes n LEFT JOIN users u ON u.id = n.author_id
      WHERE n.investigation_id = ? AND n.org_id = ? ORDER BY n.created_at DESC`, row.id, req.user.orgId,
  );
  // Correlate by the indicators and assets referenced in the linked incident timeline.
  const iocs = all('SELECT id, type, value, threat_type, confidence, status FROM iocs WHERE org_id = ? ORDER BY confidence DESC LIMIT 12', req.user.orgId);
  const incidents = row.incident_id
    ? all('SELECT id, ref, title, severity, status, detected_at FROM incidents WHERE id = ? AND org_id = ?', row.incident_id, req.user.orgId)
    : [];
  const assets = all(
    `SELECT DISTINCT a.id, a.name, a.hostname, a.risk_score, a.criticality FROM assets a
       JOIN security_events e ON e.asset_id = a.id
      WHERE a.org_id = ? AND e.occurred_at >= ? ORDER BY a.risk_score DESC LIMIT 6`,
    req.user.orgId, new Date(Date.now() - 14 * 86_400_000).toISOString(),
  );
  const events = all(
    `SELECT e.id, e.title, e.severity, e.event_type, e.src_ip, e.occurred_at, a.hostname AS asset
       FROM security_events e LEFT JOIN assets a ON a.id = e.asset_id AND a.org_id = e.org_id
      WHERE e.org_id = ? AND e.severity IN ('high','critical')
      ORDER BY e.occurred_at DESC LIMIT 15`, req.user.orgId,
  ).map((e) => ({ ...e }));

  // Build a compact attack timeline from high severity telemetry and analyst notes.
  const timeline = [
    ...events.slice(0, 8).map((e) => ({ at: e.occurred_at, kind: 'event', label: e.title, detail: `${e.event_type} on ${e.asset ?? 'unassigned asset'}` })),
    ...notes.slice(0, 6).map((n) => ({ at: n.created_at, kind: 'note', label: 'Analyst note', detail: n.body.slice(0, 160) })),
  ].sort((a, b) => new Date(a.at) - new Date(b.at));

  return ok(res, { ...mapInv(row), notes: notes.map((n) => ({ id: n.id, body: n.body, author: n.author, createdAt: n.created_at })), iocs, incidents, assets, timeline });
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    status: z.enum(['active', 'paused', 'concluded']).optional(),
    findings: z.string().trim().max(8000).optional(),
    hypothesis: z.string().trim().max(4000).optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  }), req.body);
  const row = get('SELECT * FROM investigations WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Investigation not found');
  const fields = [];
  const params = [];
  if (body.status) { fields.push('status = ?'); params.push(body.status); }
  if (body.findings !== undefined) { fields.push('findings = ?'); params.push(body.findings); }
  if (body.hypothesis !== undefined) { fields.push('hypothesis = ?'); params.push(body.hypothesis); }
  if (body.severity) { fields.push('severity = ?'); params.push(body.severity); }
  if (!fields.length) throw notFound('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE investigations SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'investigation.updated', 'investigation', row.id, { fields: Object.keys(body) });
  return ok(res, mapInv(get(`SELECT i.*, u.name AS owner_name, inc.ref AS incident_ref FROM investigations i
    LEFT JOIN users u ON u.id = i.owner_id LEFT JOIN incidents inc ON inc.id = i.incident_id WHERE i.id = ?`, row.id)));
}));

router.post('/:id/notes', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ body: z.string().trim().min(2).max(4000) }), req.body);
  const row = get('SELECT id FROM investigations WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Investigation not found');
  const id = newId('note');
  run(
    `INSERT INTO investigation_notes (id, org_id, investigation_id, author_id, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    id, req.user.orgId, row.id, req.user.id, body.body, nowIso(),
  );
  audit(req, 'investigation.note_added', 'investigation', row.id);
  return created(res, { id, body: body.body, author: req.user.name, createdAt: nowIso() });
}));

export default router;
