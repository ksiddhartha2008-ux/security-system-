import { Router } from 'express';
import { z } from 'zod';
import { all, get } from '../db.js';
import { ApiError, asyncHandler, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole, requireRecentAuth } from '../lib/auth.js';
import { websiteProtectionEnabled } from '../lib/websiteFlag.js';
import { normalizeWebsiteInput } from '../lib/websiteNormalize.js';
import {
  createSite, listSites, siteDetail, checkVerification, restartVerification,
  updateSite, softDeleteSite, getSite, activeKeyCount, connectionState, heartbeatSeconds,
} from '../services/websiteSites.js';
import { createKey, listKeys, revokeKey } from '../services/websiteKeys.js';
import { exportSiteData, requestDataDeletion } from '../services/websiteData.js';
import { installSnippet } from '../services/websiteSnippet.js';
import { createTxtResolver } from '../lib/dnsTxt.js';

const router = Router();

router.use((req, res, next) => {
  if (websiteProtectionEnabled()) return next();
  return next(notFound());
});

router.use(requireAuth);

const createSchema = z.object({
  url: z.string().trim().min(1).max(2048),
  display_name: z.string().trim().min(1).max(100).optional(),
  scope: z.enum(['host', 'domain']).default('host'),
  criticality: z.number().int().min(1).max(5).default(3),
}).strict();

const patchSchema = z.object({
  display_name: z.string().trim().min(1).max(100).optional(),
  criticality: z.number().int().min(1).max(5).optional(),
  sensitive_paths: z.array(z.string().max(128)).max(40).optional(),
}).strict();

const keySchema = z.object({
  label: z.string().trim().max(60).optional(),
  expires_at: z.string().datetime().optional(),
}).strict();

router.get('/', asyncHandler(async (req, res) => {
  const sites = listSites(req.user.orgId, { status: req.query.status, q: req.query.q });
  const summary = {
    total: sites.length,
    verified: sites.filter((site) => site.status === 'verified').length,
    pending: sites.filter((site) => site.status === 'pending_verification').length,
    attention: sites.filter((site) => ['lapsed', 'expired'].includes(site.status)).length,
    connected: sites.filter((site) => site.connection.state === 'connected').length,
  };
  return ok(res, sites, { summary });
}));

router.post('/', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(createSchema, req.body);
  const result = createSite(req, body);
  return created(res, {
    site: siteDetail(req.user.orgId, result.site.id),
    reused: result.reused,
  });
}));

/** Normalize without writing anything, so the wizard can show the exact hostname. */
router.post('/preview', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({ url: z.string().trim().min(1).max(2048) }).strict(), req.body);
  const result = normalizeWebsiteInput(body.url, { env: process.env });
  if (!result.ok) {
    return res.status(400).json({ error: { code: result.code, message: result.message, request_id: req.requestId } });
  }
  return ok(res, result.value);
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const detail = siteDetail(req.user.orgId, req.params.id);
  const site = getSite(req.user.orgId, req.params.id);
  const events24h = get(
    `SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND website_site_id = ? AND occurred_at >= ?`,
    req.user.orgId, site.id, new Date(Date.now() - 24 * 3600_000).toISOString(),
  ).c;
  const events7d = get(
    `SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND website_site_id = ? AND occurred_at >= ?`,
    req.user.orgId, site.id, new Date(Date.now() - 7 * 24 * 3600_000).toISOString(),
  ).c;
  const detections = get(
    `SELECT COUNT(*) AS c FROM detections WHERE org_id = ? AND json_extract(explanation, '$.websiteSiteId') = ?`,
    req.user.orgId, site.id,
  ).c;
  const incidents = get(
    `SELECT COUNT(DISTINCT i.id) AS c FROM incidents i JOIN incident_entities ie ON ie.incident_id = i.id
      WHERE i.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?`,
    req.user.orgId, site.asset_id ?? '__none__',
  ).c;
  const notifications = all(
    `SELECT id, kind, priority, status, suppression_reason, title, body, created_at
       FROM notifications WHERE org_id = ? AND site_id = ? ORDER BY created_at DESC LIMIT 10`,
    req.user.orgId, site.id,
  ).map((row) => ({
    id: row.id, kind: row.kind, priority: row.priority, status: row.status,
    suppressionReason: row.suppression_reason, title: row.title, body: row.body, createdAt: row.created_at,
  }));
  const topSources = all(
    `SELECT src_ip, COUNT(*) AS hits FROM security_events
      WHERE org_id = ? AND website_site_id = ? AND src_ip IS NOT NULL AND occurred_at >= ?
      GROUP BY src_ip ORDER BY hits DESC LIMIT 5`,
    req.user.orgId, site.id, new Date(Date.now() - 7 * 24 * 3600_000).toISOString(),
  ).map((row) => ({ ip: row.src_ip, count: row.hits }));
  const detectionsByRule = all(
    `SELECT json_extract(explanation, '$.ruleKey') AS rule_key, COUNT(*) AS hits
       FROM detections WHERE org_id = ? AND json_extract(explanation, '$.websiteSiteId') = ?
      GROUP BY rule_key ORDER BY hits DESC`,
    req.user.orgId, site.id,
  ).map((row) => ({ ruleKey: row.rule_key, count: row.hits }));
  return ok(res, {
    ...detail,
    stats: { events24h, events7d, detections, incidents, topSources, detectionsByRule },
    notifications,
    installSnippet: site.status === 'verified' ? installSnippet(site) : null,
    heartbeatSeconds: heartbeatSeconds(),
  });
}));

router.patch('/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(patchSchema, req.body);
  const site = updateSite(req, req.params.id, body);
  return ok(res, siteDetail(req.user.orgId, site.id));
}));

router.delete('/:id', requireRole('admin'), requireRecentAuth, asyncHandler(async (req, res) => {
  return ok(res, softDeleteSite(req, req.params.id));
}));

router.post('/:id/verify', requireRole('admin'), asyncHandler(async (req, res) => {
  const result = await checkVerification(req, { siteId: req.params.id, source: 'manual', resolver: createTxtResolver() });
  if (result.status === 'conflict') {
    throw new ApiError(409, 'site_conflict', 'Another workspace has already verified an overlapping hostname.');
  }
  return ok(res, result);
}));

router.post('/:id/verification/restart', requireRole('admin'), asyncHandler(async (req, res) => {
  restartVerification(req, req.params.id);
  return ok(res, siteDetail(req.user.orgId, req.params.id));
}));

router.post('/:id/keys', requireRole('admin'), requireRecentAuth, asyncHandler(async (req, res) => {
  const body = validate(keySchema, req.body);
  const key = createKey(req, req.params.id, { label: body.label, expiresAt: body.expires_at });
  res.setHeader('Cache-Control', 'no-store');
  return created(res, key);
}));

router.get('/:id/keys', requireRole('admin'), asyncHandler(async (req, res) => {
  return ok(res, listKeys(req.user.orgId, req.params.id));
}));

router.delete('/:id/keys/:keyId', requireRole('admin'), requireRecentAuth, asyncHandler(async (req, res) => {
  return ok(res, revokeKey(req, req.params.id, req.params.keyId));
}));

router.get('/:id/events', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  getSite(orgId, req.params.id);
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const where = ['org_id = ?', 'website_site_id = ?'];
  const params = [orgId, req.params.id];
  if (req.query.type) { where.push('event_type = ?'); params.push(String(req.query.type)); }
  if (req.query.q) {
    where.push('(src_ip LIKE ? OR user_email LIKE ? OR title LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 80)}%`;
    params.push(like, like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) AS c FROM security_events WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT id, event_type, title, src_ip, user_email, asset_id, raw, occurred_at, trust_level
       FROM security_events WHERE ${sqlWhere} ORDER BY occurred_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map((row) => {
    let payload = {};
    try { payload = JSON.parse(row.raw || '{}'); } catch { payload = {}; }
    return {
      id: row.id,
      type: payload.type ?? row.event_type,
      eventType: row.event_type,
      title: row.title,
      srcIp: row.src_ip,
      actor: row.user_email,
      path: payload.request?.path ?? null,
      method: payload.request?.method ?? null,
      status: payload.request?.status ?? null,
      userAgent: payload.client?.user_agent ?? null,
      attributes: payload.attributes ?? {},
      ipClass: payload.ip_class ?? null,
      trustLevel: row.trust_level,
      occurredAt: row.occurred_at,
    };
  }), total, { page, limit });
}));

router.get('/:id/detections', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  getSite(orgId, req.params.id);
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 25 });
  const params = [orgId, req.params.id];
  let filter = '';
  if (req.query.ruleKey) { filter = ' AND json_extract(explanation, \'$.ruleKey\') = ?'; params.push(String(req.query.ruleKey)); }
  const total = get(
    `SELECT COUNT(*) AS c FROM detections WHERE org_id = ? AND json_extract(explanation, '$.websiteSiteId') = ?${filter}`,
    ...params,
  ).c;
  const rows = all(
    `SELECT id, title, description, severity, risk_score, confidence, status, detected_at, explanation
       FROM detections WHERE org_id = ? AND json_extract(explanation, '$.websiteSiteId') = ?${filter}
      ORDER BY detected_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  let incidentByDetection = new Map();
  if (rows.length) {
    const links = all(
      `SELECT detection_id, incident_id FROM incident_detections WHERE detection_id IN (${rows.map(() => '?').join(',')})`,
      ...rows.map((row) => row.id),
    );
    incidentByDetection = new Map(links.map((link) => [link.detection_id, link.incident_id]));
  }
  return paginated(res, rows.map((row) => {
    let explanation = {};
    try { explanation = JSON.parse(row.explanation || '{}'); } catch { explanation = {}; }
    return {
      id: row.id, title: row.title, description: row.description, severity: row.severity,
      riskScore: row.risk_score, confidence: row.confidence, status: row.status,
      ruleKey: explanation.ruleKey ?? null, factors: explanation.factors ?? [],
      observed: explanation.observed ?? {}, detectedAt: row.detected_at,
      incidentId: incidentByDetection.get(row.id) ?? null,
    };
  }), total, { page, limit });
}));

router.get('/:id/incidents', asyncHandler(async (req, res) => {
  const orgId = req.user.orgId;
  const site = getSite(orgId, req.params.id);
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 20 });
  const total = site.asset_id
    ? get(`SELECT COUNT(DISTINCT i.id) AS c FROM incidents i JOIN incident_entities ie ON ie.incident_id = i.id
            WHERE i.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?`, orgId, site.asset_id).c
    : 0;
  const rows = site.asset_id ? all(
    `SELECT DISTINCT i.id, i.ref, i.title, i.severity, i.priority, i.status, i.detected_at, i.updated_at
       FROM incidents i JOIN incident_entities ie ON ie.incident_id = i.id
      WHERE i.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?
      ORDER BY i.detected_at DESC LIMIT ? OFFSET ?`,
    orgId, site.asset_id, limit, offset,
  ) : [];
  return paginated(res, rows.map((row) => ({
    id: row.id, ref: row.ref, title: row.title, severity: row.severity,
    priority: row.priority, status: row.status, detectedAt: row.detected_at, updatedAt: row.updated_at,
  })), total, { page, limit });
}));

router.get('/:id/export', requireRole('admin'), asyncHandler(async (req, res) => {
  const data = exportSiteData(req.user.orgId, req.params.id);
  res.setHeader('Content-Disposition', `attachment; filename="secureflow-website-${req.params.id}.json"`);
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ data });
}));

router.post('/:id/data-deletion', requireRole('admin'), requireRecentAuth, asyncHandler(async (req, res) => {
  const body = validate(z.object({ confirm: z.string().max(253) }).strict(), req.body);
  const result = requestDataDeletion(req, req.params.id, body);
  if (result.error === 'confirmation_mismatch') {
    return res.status(400).json({ error: { code: 'confirmation_mismatch', message: 'Type the hostname exactly to confirm.', request_id: req.requestId } });
  }
  return ok(res, result);
}));

export default router;
