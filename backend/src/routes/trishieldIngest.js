import { Router } from 'express';
import { asyncHandler, badRequest, created, forbidden } from '../lib/http.js';
import { rateLimit } from '../lib/ratelimit.js';
import { authenticateCollector, ingestProviderRecords } from '../services/trishieldIngest.js';

const router = Router();

/**
 * Collector ingestion. Authenticated by a per-collector bearer token, never by a
 * session or an organization id in the payload. Mounted before CSRF because a
 * collector has no cookie session.
 */
router.post('/:kind', rateLimit({ windowMs: 60_000, max: 600, keyPrefix: 'trishield-ingest' }), asyncHandler(async (req, res) => {
  const kind = String(req.params.kind ?? '');
  if (!['suricata', 'wazuh', 'waf'].includes(kind)) throw badRequest('Unknown collector kind');
  const collector = authenticateCollector(req.headers.authorization);
  if (collector.kind !== kind) throw forbidden('This token belongs to a different collector kind');
  const body = req.body;
  const records = Array.isArray(body) ? body : Array.isArray(body?.records) ? body.records : body && typeof body === 'object' ? [body] : [];
  if (!records.length) throw badRequest('Send one record, an array, or an object with a records array');
  const result = await ingestProviderRecords({ orgId: collector.org_id, collector, kind, records });
  return created(res, result);
}));

export default router;
