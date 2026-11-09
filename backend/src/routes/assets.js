import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, conflict, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

const assetSchema = z.object({
  name: z.string().trim().min(2).max(120),
  hostname: z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9._-]+$/, 'Hostname may only contain letters, digits, dots, dashes and underscores'),
  ipAddress: z.string().trim().max(64).optional().nullable(),
  macAddress: z.string().trim().max(32).optional().nullable(),
  os: z.string().trim().max(80).optional().nullable(),
  assetType: z.enum(['server', 'workstation', 'database', 'network', 'cloud', 'container host', 'ot', 'mobile']).default('server'),
  criticality: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  owner: z.string().trim().max(80).optional().nullable(),
  tags: z.array(z.string().trim().max(30)).max(12).default([]),
  status: z.enum(['online', 'offline', 'quarantined', 'decommissioned']).default('online'),
});

const map = (a) => ({
  id: a.id, name: a.name, hostname: a.hostname, ipAddress: a.ip_address, macAddress: a.mac_address,
  os: a.os, assetType: a.asset_type, criticality: a.criticality, owner: a.owner, riskScore: a.risk_score,
  status: a.status, tags: parseJson(a.tags, []), lastSeenAt: a.last_seen_at, createdAt: a.created_at,
  dataOrigin: a.data_origin,
  eventCount: a.event_count ?? undefined, openDetections: a.open_detections ?? undefined,
});

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['a.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.criticality) { where.push('a.criticality = ?'); params.push(String(req.query.criticality)); }
  if (req.query.status) { where.push('a.status = ?'); params.push(String(req.query.status)); }
  if (req.query.assetType) { where.push('a.asset_type = ?'); params.push(String(req.query.assetType)); }
  if (req.query.q) {
    where.push('(a.name LIKE ? OR a.hostname LIKE ? OR a.ip_address LIKE ? OR a.owner LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM assets a WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT a.*,
            (SELECT COUNT(*) FROM security_events e WHERE e.asset_id = a.id) AS event_count,
            (SELECT COUNT(*) FROM detections d WHERE d.asset_id = a.id AND d.status = 'open') AS open_detections
       FROM assets a WHERE ${sqlWhere}
      ORDER BY a.risk_score DESC, a.name ASC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map(map), total, { page, limit });
}));

router.get('/summary', asyncHandler(async (req, res) => {
  const rows = all(
    `SELECT criticality, COUNT(*) c, ROUND(AVG(risk_score)) avg_risk FROM assets WHERE org_id = ? GROUP BY criticality`,
    req.user.orgId,
  );
  const byType = all('SELECT asset_type, COUNT(*) c FROM assets WHERE org_id = ? GROUP BY asset_type', req.user.orgId);
  return ok(res, {
    byCriticality: rows.map((r) => ({ criticality: r.criticality, count: r.c, avgRisk: r.avg_risk ?? 0 })),
    byType: byType.map((r) => ({ assetType: r.asset_type, count: r.c })),
  });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(assetSchema, req.body);
  if (get('SELECT id FROM assets WHERE org_id = ? AND hostname = ?', req.user.orgId, body.hostname)) {
    throw conflict('An asset with that hostname already exists');
  }
  const id = newId('ast');
  const ts = nowIso();
  run(
    `INSERT INTO assets (id, org_id, name, hostname, ip_address, mac_address, os, asset_type, criticality, owner, risk_score, status, tags, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
    id, req.user.orgId, body.name, body.hostname, body.ipAddress ?? null, body.macAddress ?? null, body.os ?? null,
    body.assetType, body.criticality, body.owner ?? null, body.status, JSON.stringify(body.tags), nowIso(), ts, ts,
  );
  audit(req, 'asset.created', 'asset', id, { hostname: body.hostname });
  const row = get('SELECT * FROM assets WHERE id = ?', id);
  return created(res, map(row));
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM assets WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Asset not found');
  const events = all(
    `SELECT id, title, event_type, severity, occurred_at FROM security_events WHERE asset_id = ? AND org_id = ?
      ORDER BY occurred_at DESC LIMIT 20`, row.id, req.user.orgId,
  );
  const detections = all(
    `SELECT id, title, severity, risk_score, status, detected_at FROM detections WHERE asset_id = ? AND org_id = ?
      ORDER BY detected_at DESC LIMIT 10`, row.id, req.user.orgId,
  );
  const vulnerabilities = all(
    `SELECT id, cve_id, title, severity, cvss, status FROM vulnerabilities WHERE asset_id = ? AND org_id = ?
      ORDER BY cvss DESC`, row.id, req.user.orgId,
  );
  const network = all(
    `SELECT id, src_ip, dest_ip, dest_port, bytes_out, verdict, occurred_at FROM network_events
      WHERE asset_id = ? AND org_id = ? ORDER BY occurred_at DESC LIMIT 10`, row.id, req.user.orgId,
  );
  return ok(res, { ...map(row), events, detections, vulnerabilities, network });
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(assetSchema.partial(), req.body);
  const row = get('SELECT * FROM assets WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Asset not found');
  const fields = [];
  const params = [];
  const assign = (column, value) => { fields.push(`${column} = ?`); params.push(value); };
  if (body.name !== undefined) assign('name', body.name);
  if (body.hostname !== undefined) assign('hostname', body.hostname);
  if (body.ipAddress !== undefined) assign('ip_address', body.ipAddress);
  if (body.macAddress !== undefined) assign('mac_address', body.macAddress);
  if (body.os !== undefined) assign('os', body.os);
  if (body.assetType !== undefined) assign('asset_type', body.assetType);
  if (body.criticality !== undefined) assign('criticality', body.criticality);
  if (body.owner !== undefined) assign('owner', body.owner);
  if (body.status !== undefined) assign('status', body.status);
  if (body.tags !== undefined) assign('tags', JSON.stringify(body.tags));
  if (!fields.length) throw badRequest('Nothing to update');
  assign('updated_at', nowIso());
  run(`UPDATE assets SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'asset.updated', 'asset', row.id, { fields: Object.keys(body) });
  return ok(res, map(get('SELECT * FROM assets WHERE id = ?', row.id)));
}));

router.delete('/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM assets WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Asset not found');
  run('DELETE FROM assets WHERE id = ? AND org_id = ?', row.id, req.user.orgId);
  audit(req, 'asset.deleted', 'asset', row.id, { hostname: row.hostname });
  return ok(res, { id: row.id, deleted: true });
}));

export default router;
