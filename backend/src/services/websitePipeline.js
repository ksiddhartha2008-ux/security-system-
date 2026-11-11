import { evaluateRules, refreshAssetRisk } from './detection.js';
import { correlateWebsiteDetections } from './websiteIncidents.js';
import { refreshIntegrationHealth } from './websiteHealth.js';

/**
 * Post-commit pipeline. Ingestion stores events first and then calls this. A
 * durable job row is written before the call, so a crash during detection is
 * retried by the scheduler and the stored events are never lost.
 */
export function runWebsitePipeline(orgId, siteId = null) {
  const detections = evaluateRules(orgId);
  const incidents = correlateWebsiteDetections(orgId);
  refreshAssetRisk(orgId);
  let health = [];
  try {
    health = refreshIntegrationHealth(orgId);
  } catch (error) {
    console.error('[website] health refresh failed', error.message);
  }
  return {
    siteId,
    detections: detections.filter((item) => !siteId || item.siteId === siteId),
    incidents,
    health,
  };
}
