import { Router } from 'express';
import { z } from 'zod';
import { all, parseJson } from '../db.js';
import { asyncHandler, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth } from '../lib/auth.js';
import { rateLimit } from '../lib/ratelimit.js';
import { scanUrl } from '../services/phishing.js';
import { audit } from '../lib/audit.js';
import { broadcast } from '../lib/events.js';

const router = Router();
router.use(requireAuth);

router.post('/scan', rateLimit({ windowMs: 60 * 60 * 1000, max: 40, keyPrefix: 'phish-scan', message: 'Scan limit reached for this hour. Try again later.' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({ url: z.string().trim().min(4).max(2048) }), req.body);
  const result = await scanUrl({ url: body.url, orgId: req.user.orgId, userId: req.user.id });
  audit(req, 'phishing.scanned', 'phishing_scan', result.id, { verdict: result.verdict, riskScore: result.riskScore });
  broadcast(req.user.orgId, 'phishing.scan_completed', { id: result.id, verdict: result.verdict, riskScore: result.riskScore, domain: result.domain });
  return ok(res, result);
}));

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 25 });
  const where = ['org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.verdict) { where.push('verdict = ?'); params.push(String(req.query.verdict)); }
  const sqlWhere = where.join(' AND ');
  const total = all(`SELECT COUNT(*) c FROM phishing_scans WHERE ${sqlWhere}`, ...params)[0].c;
  const rows = all(`SELECT * FROM phishing_scans WHERE ${sqlWhere} ORDER BY created_at DESC LIMIT ? OFFSET ?`, ...params, limit, offset);
  return paginated(res, rows.map((s) => ({
    id: s.id, url: s.url, domain: s.domain, verdict: s.verdict, riskScore: s.risk_score,
    indicators: parseJson(s.indicators, []), redirectChain: parseJson(s.redirect_chain, []),
    reachable: s.reachable === 1, reputation: parseJson(s.reputation, {}), createdAt: s.created_at,
  })), total, { page, limit });
}));

export default router;
