import express, { Router } from 'express';
import { readAuthorizationKey, verifyApiKey } from '../lib/apiKeys.js';
import { parseEnvelope, ingestBatch } from '../services/websiteIngest.js';
import { enqueue } from '../services/websiteScheduler.js';
import { runWebsitePipeline } from '../services/websitePipeline.js';
import { websiteProtectionEnabled } from '../lib/websiteFlag.js';
import { run } from '../db.js';
import { bus } from '../lib/events.js';

const router = Router();

const fail = (res, status, code, message, extra = {}) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json({ error: { code, message, request_id: res.req?.requestId ?? null } , ...extra });
};

router.use((req, res, next) => {
  if (!websiteProtectionEnabled()) return fail(res, 404, 'not_found', 'Not found');
  const encoding = req.headers['content-encoding'];
  if (encoding && encoding.toLowerCase() !== 'identity') {
    return fail(res, 415, 'unsupported_media_type', 'Send the batch without content encoding.');
  }
  return next();
});

/**
 * Ingestion authenticates with the API key only. The route is mounted before
 * cookies and CSRF are read, so ambient credentials cannot authenticate it.
 */
router.post('/website-events', express.raw({ type: () => true, limit: '256kb' }), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const apiKey = readAuthorizationKey(req.headers.authorization);
  if (!apiKey) return fail(res, 401, 'invalid_api_key', 'Provide a website API key in the Authorization header.');

  const auth = verifyApiKey(apiKey);
  if (!auth.ok) {
    if (auth.code === 'site_not_verified') return fail(res, 403, 'site_not_verified', 'This website is not verified.');
    return fail(res, 401, 'invalid_api_key', 'The API key is not valid.');
  }

  if (!Buffer.isBuffer(req.body)) return fail(res, 400, 'invalid_batch', 'Send a JSON body.');
  if (req.body.length === 0) return fail(res, 400, 'invalid_batch', 'The request body is empty.');

  let envelope;
  try {
    envelope = parseEnvelope(req.body, req.headers['content-type']);
  } catch (error) {
    if (error.status) return fail(res, error.status, error.code, error.message);
    return fail(res, 400, 'invalid_batch', 'The envelope could not be read.');
  }

  let result;
  try {
    result = ingestBatch({ site: auth.site, key: auth.key, envelope });
  } catch (error) {
    if (error.status === 429) {
      res.setHeader('Retry-After', String(error.retryAfter ?? 60));
      return fail(res, 429, 'rate_limited', error.message);
    }
    if (error.status) return fail(res, error.status, error.code, error.message);
    console.error('[website] ingestion failed', error.message);
    res.setHeader('Retry-After', '30');
    return fail(res, 503, 'service_unavailable', 'The event could not be stored. Retry the batch.');
  }

  const jobId = enqueue('pipeline', auth.site.org_id, { siteId: auth.site.id });
  res.status(202).json({
    accepted: result.accepted,
    duplicates: result.duplicates,
    rejected: result.rejected,
    dropped_fields: result.droppedFields,
  });

  setImmediate(() => {
    try {
      runWebsitePipeline(auth.site.org_id, auth.site.id);
      run('DELETE FROM website_jobs WHERE id = ?', jobId);
      bus.emit('org', {
        orgId: auth.site.org_id,
        event: 'website.events',
        payload: { siteId: auth.site.id, accepted: result.accepted, duplicates: result.duplicates },
      });
    } catch (error) {
      run(
        'UPDATE website_jobs SET last_error = ?, next_run_at = ?, updated_at = datetime(\'now\') WHERE id = ?',
        String(error.message).slice(0, 500), new Date(Date.now() + 60_000).toISOString(), jobId,
      );
      console.error('[website] post commit pipeline failed', error.message);
    }
  });
});

export default router;
