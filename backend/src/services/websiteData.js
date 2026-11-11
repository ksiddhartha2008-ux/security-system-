import { all, get, run, newId, nowIso, transaction, parseJson } from '../db.js';
import { audit } from '../lib/audit.js';
import { getSite } from './websiteSites.js';
import { keyMetadata } from './websiteKeys.js';

const DAY = 24 * 60 * 60 * 1000;

function orgPolicy(orgId) {
  const org = get('SELECT settings FROM organizations WHERE id = ?', orgId);
  const settings = parseJson(org?.settings, {});
  const days = Number(settings.retentionDays ?? 90);
  return {
    retentionDays: Number.isFinite(days) && days >= 7 ? days : 90,
    legalHold: settings.legalHold === true,
  };
}

/** Bounded, tenant scoped retention. Legal hold stops every deletion. */
export function applyRetention(orgId, { now = Date.now() } = {}) {
  const policy = orgPolicy(orgId);
  if (policy.legalHold) return { skipped: 'legal_hold', retentionDays: policy.retentionDays };

  const cutoff = new Date(now - policy.retentionDays * DAY).toISOString();
  const counts = {};
  transaction(() => {
    counts.events = get(
      `SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND website_site_id IS NOT NULL AND occurred_at < ?`,
      orgId, cutoff,
    ).c;
    if (counts.events) {
      run(`DELETE FROM security_events WHERE org_id = ? AND website_site_id IS NOT NULL AND occurred_at < ?`, orgId, cutoff);
    }

    const markerCutoff = new Date(now - Math.max(7, policy.retentionDays) * DAY).toISOString();
    counts.eventIds = get('SELECT COUNT(*) AS c FROM website_event_ids WHERE org_id = ? AND received_at < ?', orgId, markerCutoff).c;
    run('DELETE FROM website_event_ids WHERE org_id = ? AND received_at < ?', orgId, markerCutoff);

    counts.usage = get('SELECT COUNT(*) AS c FROM website_usage WHERE updated_at < ?', new Date(now - 2 * DAY).toISOString()).c;
    run('DELETE FROM website_usage WHERE updated_at < ?', new Date(now - 2 * DAY).toISOString());

    counts.attempts = get('SELECT COUNT(*) AS c FROM website_verification_attempts WHERE org_id = ? AND created_at < ?', orgId, new Date(now - 30 * DAY).toISOString()).c;
    run('DELETE FROM website_verification_attempts WHERE org_id = ? AND created_at < ?', orgId, new Date(now - 30 * DAY).toISOString());

    counts.notifications = get('SELECT COUNT(*) AS c FROM notifications WHERE org_id = ? AND created_at < ?', orgId, new Date(now - 180 * DAY).toISOString()).c;
    run('DELETE FROM notifications WHERE org_id = ? AND created_at < ?', orgId, new Date(now - 180 * DAY).toISOString());
  });

  if (Object.values(counts).some((value) => value > 0)) {
    audit(null, 'website.retention_applied', 'organization', orgId, { ...counts, retentionDays: policy.retentionDays }, { orgId });
  }
  return { ...counts, retentionDays: policy.retentionDays, cutoff };
}

/** Tenant scoped export. No secret or hash is ever included. */
export function exportSiteData(orgId, siteId) {
  const site = getSite(orgId, siteId);
  const events = all(
    `SELECT id, event_type, source, severity, title, src_ip, user_email, asset_id, raw, occurred_at, created_at, trust_level
       FROM security_events WHERE org_id = ? AND website_site_id = ? ORDER BY occurred_at DESC LIMIT 5000`,
    orgId, siteId,
  ).map((row) => ({ ...row, raw: parseJson(row.raw, {}) }));
  const detections = all(
    `SELECT id, title, severity, risk_score, status, explanation, detected_at
       FROM detections WHERE org_id = ? AND json_extract(explanation, '$.websiteSiteId') = ?
      ORDER BY detected_at DESC LIMIT 5000`,
    orgId, siteId,
  ).map((row) => ({ ...row, explanation: parseJson(row.explanation, {}) }));
  const incidents = all(
    `SELECT DISTINCT i.id, i.ref, i.title, i.severity, i.priority, i.status, i.detected_at
       FROM incidents i
       JOIN incident_entities ie ON ie.incident_id = i.id
      WHERE i.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?
      ORDER BY i.detected_at DESC LIMIT 1000`,
    orgId, site.asset_id ?? '__none__',
  );
  const keys = all('SELECT * FROM site_api_keys WHERE org_id = ? AND site_id = ? ORDER BY created_at DESC', orgId, siteId).map(keyMetadata);

  return {
    exportedAt: nowIso(),
    site: {
      id: site.id, displayName: site.display_name, hostname: site.hostname, scope: site.scope,
      status: site.status, criticality: site.criticality, verifiedAt: site.verified_at, createdAt: site.created_at,
    },
    counts: { events: events.length, detections: detections.length, incidents: incidents.length, keys: keys.length },
    events, detections, incidents, keys,
  };
}

/**
 * Customer initiated deletion of website event data. Idempotent: the request is
 * recorded, the deletion runs in a transaction and the completed counts are
 * stored so the result can be verified afterwards.
 */
export function requestDataDeletion(req, siteId, { confirm } = {}) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);
  if (confirm !== site.hostname) {
    return { error: 'confirmation_mismatch' };
  }
  const id = newId('del');
  const counts = transaction(() => {
    run(
      `INSERT INTO website_deletion_requests (id, org_id, site_id, status, deleted_counts, requested_by, created_at)
       VALUES (?, ?, ?, 'pending', '{}', ?, ?)`,
      id, orgId, siteId, req.user.id, nowIso(),
    );
    const events = get('SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND website_site_id = ?', orgId, siteId).c;
    run('DELETE FROM security_events WHERE org_id = ? AND website_site_id = ?', orgId, siteId);
    const markers = get('SELECT COUNT(*) AS c FROM website_event_ids WHERE org_id = ? AND site_id = ?', orgId, siteId).c;
    run('DELETE FROM website_event_ids WHERE org_id = ? AND site_id = ?', orgId, siteId);
    const usage = get('SELECT COUNT(*) AS c FROM website_usage WHERE site_id = ?', siteId).c;
    run('DELETE FROM website_usage WHERE site_id = ?', siteId);
    const result = { events, eventIds: markers, usage };
    run(
      `UPDATE website_deletion_requests SET status = 'completed', deleted_counts = ?, completed_at = ? WHERE id = ?`,
      JSON.stringify(result), nowIso(), id,
    );
    audit(req, 'website.data_deleted', 'website_site', siteId, { requestId: id, ...result });
    return result;
  });
  return { requestId: id, ...counts };
}
