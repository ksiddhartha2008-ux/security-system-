import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

const mapVuln = (v) => ({
  id: v.id, cveId: v.cve_id, title: v.title, description: v.description, severity: v.severity, cvss: v.cvss,
  assetId: v.asset_id, assetName: v.asset_name ?? null, assetHostname: v.asset_hostname ?? null,
  status: v.status, remediation: v.remediation, dueAt: v.due_at, discoveredAt: v.discovered_at,
  dataOrigin: v.data_origin,
});

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['v.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.severity) { where.push('v.severity = ?'); params.push(String(req.query.severity)); }
  if (req.query.status) { where.push('v.status = ?'); params.push(String(req.query.status)); }
  if (req.query.assetId) { where.push('v.asset_id = ?'); params.push(String(req.query.assetId)); }
  if (req.query.q) {
    where.push('(v.title LIKE ? OR v.cve_id LIKE ? OR v.description LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM vulnerabilities v WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT v.*, a.name AS asset_name, a.hostname AS asset_hostname FROM vulnerabilities v
       LEFT JOIN assets a ON a.id = v.asset_id AND a.org_id = v.org_id
      WHERE ${sqlWhere} ORDER BY v.cvss DESC, v.discovered_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  const stats = all('SELECT status, COUNT(*) c FROM vulnerabilities WHERE org_id = ? GROUP BY status', req.user.orgId);
  return res.json({
    data: rows.map(mapVuln),
    meta: { page, limit, total, totalPages: Math.max(Math.ceil(total / limit), 1), counts: Object.fromEntries(stats.map((s) => [s.status, s.c])) },
  });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    cveId: z.string().trim().max(30).optional().nullable(),
    title: z.string().trim().min(4).max(200),
    description: z.string().trim().max(4000).default(''),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    cvss: z.number().min(0).max(10),
    assetId: z.string().trim().max(64).optional().nullable(),
    remediation: z.string().trim().max(2000).optional().nullable(),
    dueAt: z.string().datetime().optional().nullable(),
  }), req.body);
  if (body.assetId && !get('SELECT id FROM assets WHERE id = ? AND org_id = ?', body.assetId, req.user.orgId)) {
    throw notFound('Asset not found in this workspace');
  }
  const id = newId('vuln');
  run(
    `INSERT INTO vulnerabilities (id, org_id, cve_id, title, description, severity, cvss, asset_id, status, remediation, due_at, discovered_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)`,
    id, req.user.orgId, body.cveId ?? null, body.title, body.description, body.severity, body.cvss,
    body.assetId ?? null, body.remediation ?? null, body.dueAt ?? null, nowIso(), nowIso(), nowIso(),
  );
  audit(req, 'vulnerability.created', 'vulnerability', id, { cveId: body.cveId, severity: body.severity });
  return created(res, mapVuln(get('SELECT v.*, NULL AS asset_name, NULL AS asset_hostname FROM vulnerabilities v WHERE v.id = ?', id)));
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    status: z.enum(['open', 'in_progress', 'remediated', 'accepted', 'false_positive']).optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    remediation: z.string().trim().max(2000).optional(),
    dueAt: z.string().datetime().nullable().optional(),
  }), req.body);
  const row = get('SELECT * FROM vulnerabilities WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Vulnerability not found');
  const fields = [];
  const params = [];
  if (body.status) { fields.push('status = ?'); params.push(body.status); }
  if (body.severity) { fields.push('severity = ?'); params.push(body.severity); }
  if (body.remediation !== undefined) { fields.push('remediation = ?'); params.push(body.remediation); }
  if (body.dueAt !== undefined) { fields.push('due_at = ?'); params.push(body.dueAt); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE vulnerabilities SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'vulnerability.updated', 'vulnerability', row.id, { fields: Object.keys(body) });
  return ok(res, { id: row.id, status: body.status ?? row.status });
}));

export default router;
