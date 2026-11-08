import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { buildReport, REPORT_TYPES } from '../services/reports.js';

const router = Router();
router.use(requireAuth);

router.get('/types', asyncHandler(async (_req, res) => ok(res, REPORT_TYPES)));

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 20 });
  const total = get('SELECT COUNT(*) c FROM reports WHERE org_id = ?', req.user.orgId).c;
  const rows = all(
    `SELECT id, type, title, status, generated_by, created_at FROM reports WHERE org_id = ?
      ORDER BY created_at DESC LIMIT ? OFFSET ?`, req.user.orgId, limit, offset,
  );
  return paginated(res, rows.map((r) => ({
    id: r.id, type: r.type, title: r.title, status: r.status, createdAt: r.created_at,
    generatedBy: r.generated_by ? get('SELECT name FROM users WHERE id = ?', r.generated_by)?.name ?? null : null,
  })), total, { page, limit });
}));

router.post('/generate', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    type: z.enum(REPORT_TYPES.map((t) => t.key)),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  }), req.body);
  const report = buildReport(req.user.orgId, body.type, { from: body.from, to: body.to });
  const id = newId('rpt');
  run(
    `INSERT INTO reports (id, org_id, type, title, params, status, summary, body_md, generated_by, created_at)
     VALUES (?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?)`,
    id, req.user.orgId, report.type, report.title, JSON.stringify({ from: body.from ?? null, to: body.to ?? null }),
    JSON.stringify(report.summary), report.body_md, req.user.id, nowIso(),
  );
  audit(req, 'report.generated', 'report', id, { type: body.type });
  return created(res, { id, type: report.type, title: report.title, summary: report.summary, bodyMd: report.body_md, createdAt: nowIso() });
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM reports WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Report not found');
  return ok(res, {
    id: row.id, type: row.type, title: row.title, status: row.status, params: parseJson(row.params, {}),
    summary: parseJson(row.summary, {}), bodyMd: row.body_md, createdAt: row.created_at,
  });
}));

function toCsv(summary) {
  const lines = [];
  lines.push(`# ${summary.generatedAt}`);
  for (const kpi of summary.kpis ?? []) lines.push(`KPI,${String(kpi.label).replace(/,/g, ';')},${kpi.value}`);
  for (const table of summary.tables ?? []) {
    lines.push('');
    lines.push(`# ${table.title}`);
    lines.push(table.columns.map((c) => `"${c.label}"`).join(','));
    for (const row of table.rows ?? []) {
      lines.push(table.columns.map((c) => {
        const value = row[c.key];
        return `"${String(value ?? '').replace(/"/g, '""')}"`;
      }).join(','));
    }
  }
  return lines.join('\r\n');
}

router.get('/:id/download', asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM reports WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Report not found');
  const format = String(req.query.format ?? 'md');
  const safeTitle = row.title.replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 60);
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.csv"`);
    return res.send(toCsv(parseJson(row.summary, {})));
  }
  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.json"`);
    return res.send(JSON.stringify({ ...row, summary: parseJson(row.summary, {}) }, null, 2));
  }
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.md"`);
  return res.send(row.body_md);
}));

router.delete('/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const row = get('SELECT id FROM reports WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Report not found');
  run('DELETE FROM reports WHERE id = ? AND org_id = ?', row.id, req.user.orgId);
  audit(req, 'report.deleted', 'report', row.id, {});
  return ok(res, { id: row.id, deleted: true });
}));

export default router;
