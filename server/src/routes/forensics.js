import { Router } from 'express';
import { z } from 'zod';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, basename, resolve } from 'node:path';
import { all, get, run, newId, nowIso, dataDir, parseJson } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

const EVIDENCE_DIR = join(dataDir, 'evidence');
const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME = new Set([
  'text/plain', 'text/csv', 'application/json', 'application/pdf', 'image/png', 'image/jpeg',
  'application/zip', 'application/octet-stream', 'text/x-log',
]);

const safeName = (name) => basename(String(name)).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120) || 'evidence.bin';

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 25 });
  const where = ['org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('status = ?'); params.push(String(req.query.status)); }
  if (req.query.q) {
    where.push('(filename LIKE ? OR description LIKE ? OR case_ref LIKE ? OR sha256 LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM forensic_evidence WHERE ${sqlWhere}`, ...params).c;
  const rows = all(`SELECT * FROM forensic_evidence WHERE ${sqlWhere} ORDER BY created_at DESC LIMIT ? OFFSET ?`, ...params, limit, offset);
  return paginated(res, rows.map((e) => ({
    id: e.id, caseRef: e.case_ref, filename: e.filename, description: e.description, mimeType: e.mime_type,
    sizeBytes: e.size_bytes, sha256: e.sha256, collectedFrom: e.collected_from, collectedBy: e.collected_by,
    status: e.status, createdAt: e.created_at,
  })), total, { page, limit });
}));

router.get('/stats', asyncHandler(async (req, res) => {
  const totals = get(`SELECT COUNT(*) c, COALESCE(SUM(size_bytes),0) bytes FROM forensic_evidence WHERE org_id = ?`, req.user.orgId);
  const byStatus = all('SELECT status, COUNT(*) c FROM forensic_evidence WHERE org_id = ? GROUP BY status', req.user.orgId);
  const cases = all('SELECT case_ref, COUNT(*) c FROM forensic_evidence WHERE org_id = ? GROUP BY case_ref ORDER BY c DESC LIMIT 8', req.user.orgId);
  return ok(res, { total: totals.c, totalBytes: totals.bytes, byStatus, cases });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    caseRef: z.string().trim().min(2).max(40).regex(/^[A-Za-z0-9-]+$/, 'Use letters, digits and dashes'),
    filename: z.string().trim().min(1).max(160),
    description: z.string().trim().max(1000).default(''),
    mimeType: z.string().trim().max(80),
    contentBase64: z.string().min(1),
    collectedFrom: z.string().trim().max(120).optional(),
  }), req.body);
  if (!ALLOWED_MIME.has(body.mimeType)) throw badRequest(`Unsupported file type. Allowed: ${[...ALLOWED_MIME].join(', ')}`);
  let buffer;
  try {
    buffer = Buffer.from(body.contentBase64, 'base64');
  } catch {
    throw badRequest('contentBase64 is not valid base64');
  }
  if (!buffer.length) throw badRequest('The uploaded file is empty');
  if (buffer.length > MAX_BYTES) throw badRequest('Evidence files are limited to 5 MB in this build');
  const filename = safeName(body.filename);
  const id = newId('evi');
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const storagePath = resolve(join(EVIDENCE_DIR, `${id}-${filename}`));
  if (!storagePath.startsWith(resolve(EVIDENCE_DIR))) throw badRequest('Invalid storage path');
  writeFileSync(storagePath, buffer);
  const sha256 = createHash('sha256').update(buffer).digest('hex');
  const ts = nowIso();
  run(
    `INSERT INTO forensic_evidence (id, org_id, case_ref, filename, description, mime_type, size_bytes, sha256, storage_path, collected_from, collected_by, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sealed', ?)`,
    id, req.user.orgId, body.caseRef, filename, body.description, body.mimeType, buffer.length, sha256,
    storagePath, body.collectedFrom ?? null, req.user.id, ts,
  );
  run(
    `INSERT INTO custody_records (id, org_id, evidence_id, action, actor_id, note, hash_at_action, created_at)
     VALUES (?, ?, ?, 'collected', ?, ?, ?, ?)`,
    newId('cus'), req.user.orgId, id, req.user.id, `Uploaded ${buffer.length} bytes. SHA-256 computed on intake.`, sha256, ts,
  );
  audit(req, 'evidence.created', 'forensic_evidence', id, { caseRef: body.caseRef, sha256 });
  return created(res, { id, filename, sha256, sizeBytes: buffer.length, caseRef: body.caseRef, status: 'sealed', createdAt: ts });
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const evidence = get('SELECT * FROM forensic_evidence WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!evidence) throw notFound('Evidence not found');
  const custody = all(
    `SELECT c.*, u.name AS actor_name FROM custody_records c LEFT JOIN users u ON u.id = c.actor_id
      WHERE c.evidence_id = ? AND c.org_id = ? ORDER BY c.created_at ASC`, evidence.id, req.user.orgId,
  );
  const exists = existsSync(evidence.storage_path);
  const onDisk = exists ? statSync(evidence.storage_path).size : null;
  return ok(res, {
    id: evidence.id, caseRef: evidence.case_ref, filename: evidence.filename, description: evidence.description,
    mimeType: evidence.mime_type, sizeBytes: evidence.size_bytes, sha256: evidence.sha256,
    collectedFrom: evidence.collected_from, collectedBy: evidence.collected_by, status: evidence.status,
    createdAt: evidence.created_at, filePresent: exists, fileSizeOnDisk: onDisk,
    custody: custody.map((c) => ({ id: c.id, action: c.action, actor: c.actor_name, note: c.note, hashAtAction: c.hash_at_action, createdAt: c.created_at })),
  });
}));

router.get('/:id/download', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const evidence = get('SELECT * FROM forensic_evidence WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!evidence) throw notFound('Evidence not found');
  const resolved = resolve(evidence.storage_path);
  if (!resolved.startsWith(resolve(EVIDENCE_DIR)) || !existsSync(resolved)) throw notFound('Evidence file is not available on disk');
  run(
    `INSERT INTO custody_records (id, org_id, evidence_id, action, actor_id, note, hash_at_action, created_at)
     VALUES (?, ?, ?, 'downloaded', ?, 'File streamed to an authorised analyst.', ?, ?)`,
    newId('cus'), req.user.orgId, evidence.id, req.user.id, evidence.sha256, nowIso(),
  );
  audit(req, 'evidence.downloaded', 'forensic_evidence', evidence.id, {});
  res.setHeader('Content-Type', evidence.mime_type);
  res.setHeader('X-Evidence-SHA256', evidence.sha256);
  res.setHeader('Content-Disposition', `attachment; filename="${safeName(evidence.filename)}"`);
  return res.sendFile(resolved);
}));

router.post('/:id/verify', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const evidence = get('SELECT * FROM forensic_evidence WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!evidence) throw notFound('Evidence not found');
  const resolved = resolve(evidence.storage_path);
  if (!resolved.startsWith(resolve(EVIDENCE_DIR)) || !existsSync(resolved)) throw notFound('Evidence file is not available on disk');
  const actual = createHash('sha256').update(readFileSync(resolved)).digest('hex');
  const match = actual === evidence.sha256;
  run(
    `INSERT INTO custody_records (id, org_id, evidence_id, action, actor_id, note, hash_at_action, created_at)
     VALUES (?, ?, ?, 'integrity_check', ?, ?, ?, ?)`,
    newId('cus'), req.user.orgId, evidence.id, req.user.id,
    match ? 'SHA-256 matched the recorded hash.' : 'SHA-256 DID NOT match the recorded hash.', actual, nowIso(),
  );
  audit(req, 'evidence.verified', 'forensic_evidence', evidence.id, { match });
  return ok(res, { id: evidence.id, expected: evidence.sha256, actual, match, verifiedAt: nowIso() });
}));

router.post('/:id/custody', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    action: z.enum(['in_review', 'note', 'released']),
    note: z.string().trim().min(2).max(1000),
  }), req.body);
  const evidence = get('SELECT * FROM forensic_evidence WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!evidence) throw notFound('Evidence not found');
  const ts = nowIso();
  run(
    `INSERT INTO custody_records (id, org_id, evidence_id, action, actor_id, note, hash_at_action, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('cus'), req.user.orgId, evidence.id, body.action, req.user.id, body.note, evidence.sha256, ts,
  );
  if (body.action === 'in_review' || body.action === 'released') {
    run('UPDATE forensic_evidence SET status = ? WHERE id = ? AND org_id = ?',
      body.action === 'released' ? 'released' : 'in_review', evidence.id, req.user.orgId);
  }
  audit(req, 'evidence.custody_note', 'forensic_evidence', evidence.id, { action: body.action });
  return created(res, { id: evidence.id, action: body.action, createdAt: ts });
}));

export default router;

