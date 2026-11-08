import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

export const STATUS_FLOW = {
  open: ['investigating', 'closed'],
  investigating: ['contained', 'resolved', 'closed'],
  contained: ['investigating', 'resolved', 'closed'],
  resolved: ['closed', 'investigating'],
  closed: ['investigating'],
};

const mapIncident = (i) => ({
  id: i.id, ref: i.ref, title: i.title, description: i.description, severity: i.severity, priority: i.priority,
  status: i.status, assigneeId: i.assignee_id, assignee: i.assignee_name ?? null, detectedAt: i.detected_at,
  dueAt: i.due_at, resolvedAt: i.resolved_at, createdAt: i.created_at, updatedAt: i.updated_at,
  detectionCount: i.detection_count ?? undefined,
});

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['i.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('i.status = ?'); params.push(String(req.query.status)); }
  if (req.query.severity) { where.push('i.severity = ?'); params.push(String(req.query.severity)); }
  if (req.query.assigneeId) { where.push('i.assignee_id = ?'); params.push(String(req.query.assigneeId)); }
  if (req.query.q) {
    where.push('(i.title LIKE ? OR i.ref LIKE ? OR i.description LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM incidents i WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT i.*, u.name AS assignee_name FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id
      WHERE ${sqlWhere}
      ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
               i.detected_at DESC
      LIMIT ? OFFSET ?`, ...params, limit, offset,
  );
  const counts = all('SELECT status, COUNT(*) c FROM incidents WHERE org_id = ? GROUP BY status', req.user.orgId);
  return res.json({
    data: rows.map(mapIncident),
    meta: {
      page, limit, total, totalPages: Math.max(Math.ceil(total / limit), 1),
      counts: Object.fromEntries(counts.map((c) => [c.status, c.c])),
    },
  });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    title: z.string().trim().min(4).max(200),
    description: z.string().trim().max(4000).default(''),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    priority: z.enum(['P1', 'P2', 'P3', 'P4']).default('P3'),
    assigneeId: z.string().trim().max(64).optional().nullable(),
    detectedAt: z.string().datetime().optional(),
    detectionId: z.string().trim().max(64).optional(),
    dueAt: z.string().datetime().optional().nullable(),
  }), req.body);
  if (body.assigneeId && !get('SELECT id FROM users WHERE id = ? AND org_id = ?', body.assigneeId, req.user.orgId)) {
    throw badRequest('Assignee is not a member of this workspace');
  }
  const year = new Date().getUTCFullYear();
  const countRow = get('SELECT COUNT(*) c FROM incidents WHERE org_id = ?', req.user.orgId);
  const ref = `INC-${year}-${1001 + (countRow?.c ?? 0)}`;
  const id = newId('inc');
  const ts = nowIso();
  run(
    `INSERT INTO incidents (id, org_id, ref, title, description, severity, priority, status, assignee_id, created_by, detected_at, due_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
    id, req.user.orgId, ref, body.title, body.description, body.severity, body.priority,
    body.assigneeId ?? null, req.user.id, body.detectedAt ?? ts, body.dueAt ?? null, ts, ts,
  );
  run(
    `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
     VALUES (?, ?, ?, 'created', ?, ?, ?, ?)`,
    newId('ince'), req.user.orgId, id, `Incident ${ref} opened.`, req.user.id, JSON.stringify({ severity: body.severity, detectionId: body.detectionId ?? null }), ts,
  );
  if (body.detectionId) {
    const detection = get('SELECT id FROM detections WHERE id = ? AND org_id = ?', body.detectionId, req.user.orgId);
    if (detection) {
      run(`UPDATE detections SET status = 'confirmed', updated_at = ? WHERE id = ?`, ts, detection.id);
      run(
        `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
         VALUES (?, ?, ?, 'evidence', 'Linked detection promoted into this incident.', ?, ?, ?)`,
        newId('ince'), req.user.orgId, id, req.user.id, JSON.stringify({ detectionId: detection.id }), ts,
      );
    }
  }
  audit(req, 'incident.created', 'incident', id, { ref, severity: body.severity });
  return created(res, mapIncident(get('SELECT i.*, NULL AS assignee_name FROM incidents i WHERE i.id = ?', id)));
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const row = get(
    `SELECT i.*, u.name AS assignee_name, u.email AS assignee_email FROM incidents i
       LEFT JOIN users u ON u.id = i.assignee_id WHERE i.id = ? AND i.org_id = ?`,
    req.params.id, req.user.orgId,
  );
  if (!row) throw notFound('Incident not found');
  const timeline = all(
    `SELECT ie.*, u.name AS actor_name FROM incident_events ie LEFT JOIN users u ON u.id = ie.actor_id
      WHERE ie.incident_id = ? AND ie.org_id = ? ORDER BY ie.created_at ASC`, row.id, req.user.orgId,
  ).map((e) => ({ id: e.id, type: e.type, message: e.message, actor: e.actor_name, metadata: parseJson(e.metadata, {}), createdAt: e.created_at }));
  const linkedIds = all(
    `SELECT json_extract(metadata, '$.detectionId') AS detection_id FROM incident_events
      WHERE incident_id = ? AND org_id = ? AND json_extract(metadata, '$.detectionId') IS NOT NULL`,
    row.id, req.user.orgId,
  ).map((r) => r.detection_id);
  const detections = linkedIds.length
    ? all(
      `SELECT id, title, severity, risk_score, status, detected_at FROM detections
        WHERE org_id = ? AND id IN (${linkedIds.map(() => '?').join(',')}) ORDER BY detected_at DESC`,
      req.user.orgId, ...linkedIds,
    )
    : [];
  const investigations = all(
    `SELECT id, ref, title, status FROM investigations WHERE incident_id = ? AND org_id = ?`, row.id, req.user.orgId,
  );
  return ok(res, {
    ...mapIncident(row),
    assigneeEmail: row.assignee_email,
    timeline,
    detections,
    investigations,
    allowedTransitions: STATUS_FLOW[row.status] ?? [],
  });
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    status: z.enum(['open', 'investigating', 'contained', 'resolved', 'closed']).optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    priority: z.enum(['P1', 'P2', 'P3', 'P4']).optional(),
    assigneeId: z.string().trim().max(64).nullable().optional(),
    title: z.string().trim().min(4).max(200).optional(),
    description: z.string().trim().max(4000).optional(),
  }), req.body);
  const row = get('SELECT * FROM incidents WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Incident not found');
  if (body.status && body.status !== row.status) {
    const allowed = STATUS_FLOW[row.status] ?? [];
    if (!allowed.includes(body.status)) {
      throw badRequest(`Cannot move an incident from ${row.status} to ${body.status}. Allowed: ${allowed.join(', ') || 'none'}`);
    }
  }
  if (body.assigneeId && !get('SELECT id FROM users WHERE id = ? AND org_id = ?', body.assigneeId, req.user.orgId)) {
    throw badRequest('Assignee is not a member of this workspace');
  }
  const fields = [];
  const params = [];
  if (body.status) { fields.push('status = ?'); params.push(body.status); if (['resolved', 'closed'].includes(body.status)) { fields.push('resolved_at = ?'); params.push(nowIso()); } }
  if (body.severity) { fields.push('severity = ?'); params.push(body.severity); }
  if (body.priority) { fields.push('priority = ?'); params.push(body.priority); }
  if (body.assigneeId !== undefined) { fields.push('assignee_id = ?'); params.push(body.assigneeId); }
  if (body.title) { fields.push('title = ?'); params.push(body.title); }
  if (body.description !== undefined) { fields.push('description = ?'); params.push(body.description); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);

  const ts = nowIso();
  if (body.status && body.status !== row.status) {
    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'status', ?, ?, ?, ?)`,
      newId('ince'), req.user.orgId, row.id, `Status changed from ${row.status} to ${body.status}.`, req.user.id,
      JSON.stringify({ from: row.status, to: body.status }), ts,
    );
  }
  if (body.assigneeId !== undefined && body.assigneeId !== row.assignee_id) {
    const assignee = body.assigneeId ? get('SELECT name FROM users WHERE id = ?', body.assigneeId) : null;
    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'assignment', ?, ?, '{}', ?)`,
      newId('ince'), req.user.orgId, row.id, assignee ? `Assigned to ${assignee.name}.` : 'Assignee cleared.', req.user.id, ts,
    );
  }
  audit(req, 'incident.updated', 'incident', row.id, { fields: Object.keys(body) });
  return ok(res, mapIncident(get(`SELECT i.*, u.name AS assignee_name FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id WHERE i.id = ?`, row.id)));
}));

router.post('/:id/notes', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ message: z.string().trim().min(2).max(4000) }), req.body);
  const row = get('SELECT id FROM incidents WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Incident not found');
  const id = newId('ince');
  run(
    `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
     VALUES (?, ?, ?, 'note', ?, ?, '{}', ?)`,
    id, req.user.orgId, row.id, body.message, req.user.id, nowIso(),
  );
  audit(req, 'incident.note_added', 'incident', row.id);
  return created(res, { id, message: body.message, type: 'note', createdAt: nowIso() });
}));

export default router;
