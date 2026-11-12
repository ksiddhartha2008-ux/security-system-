import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso } from '../db.js';
import { asyncHandler, badRequest, conflict, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { rateLimit } from '../lib/ratelimit.js';

const router = Router();
router.use(requireAuth);

const IOC_TYPES = ['ip', 'domain', 'url', 'sha256', 'md5', 'email'];

const normalizeValue = (type, value) => {
  const v = value.trim();
  if (type === 'ip' && !/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && !v.includes(':')) throw badRequest('Enter a valid IPv4 or IPv6 address');
  if (type === 'sha256' && !/^[a-f0-9]{64}$/i.test(v)) throw badRequest('A SHA-256 hash is 64 hexadecimal characters');
  if (type === 'md5' && !/^[a-f0-9]{32}$/i.test(v)) throw badRequest('An MD5 hash is 32 hexadecimal characters');
  if (type === 'email' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) throw badRequest('Enter a valid email address');
  if (type === 'domain' && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) throw badRequest('Enter a valid domain');
  if (type === 'url' && !/^https?:\/\//i.test(v)) throw badRequest('URL indicators must start with http:// or https://');
  return type === 'domain' ? v.toLowerCase() : v;
};

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.type && IOC_TYPES.includes(String(req.query.type))) { where.push('type = ?'); params.push(String(req.query.type)); }
  if (req.query.status) { where.push('status = ?'); params.push(String(req.query.status)); }
  if (req.query.q) {
    where.push('(value LIKE ? OR description LIKE ? OR threat_type LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM iocs WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT * FROM iocs WHERE ${sqlWhere} ORDER BY confidence DESC, created_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map((i) => ({
    id: i.id, type: i.type, value: i.value, threatType: i.threat_type, confidence: i.confidence,
    source: i.source, description: i.description, status: i.status, lastSeenAt: i.last_seen_at, createdAt: i.created_at,
  })), total, { page, limit });
}));

router.get('/summary', asyncHandler(async (req, res) => {
  const row = get(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
            SUM(CASE WHEN confidence >= 80 THEN 1 ELSE 0 END) AS high_confidence,
            COUNT(DISTINCT source) AS sources
       FROM iocs WHERE org_id = ?`,
    req.user.orgId,
  );
  return ok(res, {
    total: row.total ?? 0,
    active: row.active ?? 0,
    highConfidence: row.high_confidence ?? 0,
    sources: row.sources ?? 0,
  });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    type: z.enum(IOC_TYPES),
    value: z.string().trim().min(3).max(2048),
    threatType: z.string().trim().max(60).default('unknown'),
    confidence: z.number().int().min(0).max(100).default(50),
    description: z.string().trim().max(1000).optional(),
    status: z.enum(['active', 'monitoring', 'retired']).default('active'),
  }), req.body);
  const value = normalizeValue(body.type, body.value);
  if (get('SELECT id FROM iocs WHERE org_id = ? AND type = ? AND value = ?', req.user.orgId, body.type, value)) {
    throw conflict('That indicator already exists in this workspace');
  }
  const id = newId('ioc');
  run(
    `INSERT INTO iocs (id, org_id, type, value, threat_type, confidence, source, description, status, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'manual', ?, ?, ?, ?, ?)`,
    id, req.user.orgId, body.type, value, body.threatType, body.confidence, body.description ?? null,
    body.status, nowIso(), nowIso(), nowIso(),
  );
  audit(req, 'ioc.created', 'ioc', id, { type: body.type, value });
  return created(res, { id, type: body.type, value, threatType: body.threatType, confidence: body.confidence, status: body.status, source: 'manual', createdAt: nowIso() });
}));

router.patch('/:id', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    status: z.enum(['active', 'monitoring', 'retired']).optional(),
    confidence: z.number().int().min(0).max(100).optional(),
    description: z.string().trim().max(1000).optional(),
    threatType: z.string().trim().max(60).optional(),
  }), req.body);
  const row = get('SELECT * FROM iocs WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Indicator not found');
  const fields = [];
  const params = [];
  if (body.status) { fields.push('status = ?'); params.push(body.status); }
  if (body.confidence !== undefined) { fields.push('confidence = ?'); params.push(body.confidence); }
  if (body.description !== undefined) { fields.push('description = ?'); params.push(body.description); }
  if (body.threatType) { fields.push('threat_type = ?'); params.push(body.threatType); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE iocs SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'ioc.updated', 'ioc', row.id, { fields: Object.keys(body) });
  return ok(res, { id: row.id });
}));

router.delete('/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const row = get('SELECT * FROM iocs WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Indicator not found');
  run('DELETE FROM iocs WHERE id = ? AND org_id = ?', row.id, req.user.orgId);
  audit(req, 'ioc.deleted', 'ioc', row.id, { value: row.value });
  return ok(res, { id: row.id, deleted: true });
}));

const LOOKUP_TYPES = {
  ip: 'ip',
  domain: 'domain',
  hash: 'sha256',
  email: 'email',
  url: 'url',
};

router.post('/lookup', rateLimit({ windowMs: 60_000, max: 30, keyPrefix: 'intel-lookup' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    query: z.string().trim().min(3).max(2048),
    type: z.enum(['auto', 'ip', 'domain', 'hash', 'email', 'url']).default('auto'),
  }), req.body);
  let type = body.type;
  const value = body.query.trim();
  if (type === 'auto') {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':')) type = 'ip';
    else if (/^[a-f0-9]{64}$/i.test(value)) type = 'hash';
    else if (/^[a-f0-9]{32}$/i.test(value)) type = 'hash';
    else if (/^https?:\/\//i.test(value)) type = 'url';
    else if (value.includes('@')) type = 'email';
    else type = 'domain';
  }
  const iocType = LOOKUP_TYPES[type];
  const local = get(
    'SELECT * FROM iocs WHERE org_id = ? AND type = ? AND value = ?',
    req.user.orgId, iocType === 'sha256' ? 'sha256' : iocType, value.toLowerCase(),
  ) ?? get('SELECT * FROM iocs WHERE org_id = ? AND type IN (?,?) AND value = ?', req.user.orgId, iocType, iocType === 'sha256' ? 'md5' : iocType, value);

  const external = [];
  let score = local ? local.confidence : 0;
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey && (type === 'hash' || type === 'url' || type === 'domain')) {
    try {
      const path = type === 'hash'
        ? `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`
        : type === 'url'
          ? `https://www.virustotal.com/api/v3/urls/${Buffer.from(value).toString('base64url')}`
          : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
      const response = await fetch(path, { headers: { 'x-apikey': vtKey }, signal: AbortSignal.timeout(8000) });
      if (response.ok) {
        const data = await response.json();
        const stats = data?.data?.attributes?.last_analysis_stats ?? {};
        external.push({ provider: 'VirusTotal', malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0, harmless: stats.harmless ?? 0, undetected: stats.undetected ?? 0 });
        score = Math.max(score, Math.min(100, (stats.malicious ?? 0) * 12 + (stats.suspicious ?? 0) * 5));
      } else if (response.status === 404) {
        external.push({ provider: 'VirusTotal', note: 'No record for this indicator' });
      } else {
        external.push({ provider: 'VirusTotal', error: `HTTP ${response.status}` });
      }
    } catch (err) {
      external.push({ provider: 'VirusTotal', error: err.message });
    }
  }
  if (process.env.ABUSEIPDB_API_KEY && type === 'ip') {
    try {
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`, {
        headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }, signal: AbortSignal.timeout(8000),
      });
      if (response.ok) {
        const data = await response.json();
        external.push({ provider: 'AbuseIPDB', abuseConfidenceScore: data?.data?.abuseConfidenceScore ?? 0, totalReports: data?.data?.totalReports ?? 0, countryCode: data?.data?.countryCode ?? null });
        score = Math.max(score, data?.data?.abuseConfidenceScore ?? 0);
      } else {
        external.push({ provider: 'AbuseIPDB', error: `HTTP ${response.status}` });
      }
    } catch (err) {
      external.push({ provider: 'AbuseIPDB', error: err.message });
    }
  }

  const verdict = score >= 70 ? 'malicious' : score >= 40 ? 'suspicious' : local ? 'known' : 'unknown';
  const result = {
    query: value,
    type: iocType,
    verdict,
    score,
    localMatch: local ? {
      id: local.id, threatType: local.threat_type, confidence: local.confidence, source: local.source,
      description: local.description, status: local.status, lastSeenAt: local.last_seen_at,
    } : null,
    external,
    providersConfigured: Boolean(vtKey) || Boolean(process.env.ABUSEIPDB_API_KEY),
    note: !vtKey && !process.env.ABUSEIPDB_API_KEY
      ? 'No external reputation provider is configured. The verdict is based on workspace indicators only.'
      : null,
    lookedUpAt: nowIso(),
  };
  run(
    `INSERT INTO intel_lookups (id, org_id, ioc_type, value, verdict, score, source, details, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('lk'), req.user.orgId, iocType, value, verdict, score,
    external.length ? external.map((e) => e.provider).join(',') : 'workspace',
    JSON.stringify({ localMatch: Boolean(local), external }), nowIso(),
  );
  audit(req, 'intel.lookup', 'ioc', local?.id ?? null, { query: value, type: iocType, verdict });
  return ok(res, result);
}));

router.get('/lookups/recent', asyncHandler(async (req, res) => {
  const rows = all('SELECT * FROM intel_lookups WHERE org_id = ? ORDER BY created_at DESC LIMIT 15', req.user.orgId);
  return ok(res, rows.map((r) => ({ id: r.id, type: r.ioc_type, value: r.value, verdict: r.verdict, score: r.score, source: r.source, createdAt: r.created_at })));
}));

export default router;
