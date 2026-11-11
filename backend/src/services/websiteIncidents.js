import { all, get, run, newId, nowIso, transaction, parseJson } from '../db.js';
import { SEVERITY_SCORE } from './websiteRules.js';

const PRIORITY_RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };
const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

export function priorityFor(severity, criticality) {
  const score = SEVERITY_SCORE[severity] ?? 2;
  const raw = 2 * score + Number(criticality ?? 3);
  if (raw >= 13) return 'P1';
  if (raw >= 10) return 'P2';
  if (raw >= 7) return 'P3';
  return 'P4';
}

const higherSeverity = (a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a);

function siteFor(orgId, siteId) {
  return get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', siteId, orgId);
}

function entitiesFor(detection, site, explanation) {
  const entities = [];
  if (site?.asset_id) entities.push(['site', site.asset_id]);
  const ip = explanation.observed?.srcIp ?? null;
  if (ip) entities.push(['ip', ip]);
  const actor = explanation.observed?.actor ?? null;
  if (actor) entities.push(['actor', actor]);
  return entities;
}

/**
 * Group website detections by shared website, source address and account.
 * Deterministic and idempotent: incident_detections has a primary key on the
 * detection, so a retry or a second worker cannot attach or create twice.
 */
export function correlateWebsiteDetections(orgId, { limit = 40 } = {}) {
  const detections = all(
    `SELECT d.* FROM detections d
      WHERE d.org_id = ? AND d.status = 'open'
        AND json_extract(d.explanation, '$.websiteSiteId') IS NOT NULL
      ORDER BY d.risk_score DESC, d.detected_at ASC
      LIMIT ?`,
    orgId, limit,
  );

  const created = [];
  for (const detection of detections) {
    const explanation = parseJson(detection.explanation, {});
    const site = explanation.websiteSiteId ? siteFor(orgId, explanation.websiteSiteId) : null;
    if (!site) continue;

    const already = get('SELECT incident_id FROM incident_detections WHERE detection_id = ?', detection.id);
    if (already) continue;

    const entities = entitiesFor(detection, site, explanation);
    let incident = null;
    for (const [type, value] of entities) {
      incident = get(
        `SELECT i.* FROM incidents i
           JOIN incident_entities ie ON ie.incident_id = i.id
          WHERE i.org_id = ? AND i.status IN ('open','investigating')
            AND ie.entity_type = ? AND ie.entity_value = ?
          ORDER BY i.created_at DESC LIMIT 1`,
        orgId, type, value,
      );
      if (incident) break;
    }

    if (incident) {
      const attached = attachToIncident(orgId, incident, site, detection, explanation, entities);
      if (attached) created.push({ id: incident.id, ref: incident.ref, detectionId: detection.id, attached: true });
      continue;
    }

    const incidentId = createIncident(orgId, site, detection, explanation, entities);
    if (incidentId) {
      const row = get('SELECT * FROM incidents WHERE id = ?', incidentId);
      created.push({ id: incidentId, ref: row.ref, detectionId: detection.id, attached: false });
    }
  }
  return created;
}

function createIncident(orgId, site, detection, explanation, entities) {
  try {
    return transaction(() => {
      const existing = get('SELECT incident_id FROM incident_detections WHERE detection_id = ?', detection.id);
      if (existing) return null;

      const year = new Date().getUTCFullYear();
      const count = get('SELECT COUNT(*) AS c FROM incidents WHERE org_id = ?', orgId).c;
      let ref = `INC-${year}-${1001 + count}`;
      if (get('SELECT id FROM incidents WHERE org_id = ? AND ref = ?', orgId, ref)) {
        ref = `INC-${year}-${1001 + count + Math.floor(Math.random() * 900)}`;
      }
      const id = newId('inc');
      const ts = nowIso();
      const severity = detection.severity;
      const priority = priorityFor(severity, site.criticality);
      const title = `${explanation.ruleName ?? detection.title} against ${site.display_name}`;
      const description = [
        'Website detections were grouped by the shared website, source address and account.',
        `Rule: ${explanation.ruleKey ?? 'unknown'}.`,
        `Risk score: ${detection.risk_score}. Criticality: ${site.criticality}.`,
        'No statement about attacker identity or intent is made.',
      ].join(' ');

      run(
        `INSERT INTO incidents (id, org_id, ref, title, description, severity, priority, status, assignee_id, created_by, detected_at, due_at, resolved_at, created_at, updated_at, data_origin, demo_batch_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'open', NULL, NULL, ?, NULL, NULL, ?, ?, ?, ?)`,
        id, orgId, ref, title, description, severity, priority,
        detection.detected_at, ts, ts, detection.data_origin ?? 'REAL', detection.demo_batch_id ?? null,
      );

      run(
        `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
         VALUES (?, ?, ?, 'created', ?, NULL, ?, ?)`,
        newId('ince'), orgId, id,
        `Incident opened by website correlation from detection ${detection.id}.`,
        JSON.stringify({ detectionId: detection.id, ruleKey: explanation.ruleKey, siteId: site.id, priority }), ts,
      );
      run(
        `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
         VALUES (?, ?, ?, 'evidence', ?, NULL, ?, ?)`,
        newId('ince'), orgId, id,
        'The detection and its source events are stored as evidence.',
        JSON.stringify({ detectionId: detection.id, eventId: detection.event_id }), ts,
      );

      for (const [type, value] of entities) {
        run(
          `INSERT OR IGNORE INTO incident_entities (id, org_id, incident_id, entity_type, entity_value, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
          newId('ien'), orgId, id, type, value, ts,
        );
      }
      run('INSERT INTO incident_detections (detection_id, incident_id, org_id, created_at) VALUES (?, ?, ?, ?)', detection.id, id, orgId, ts);
      run(`UPDATE detections SET status = 'confirmed', updated_at = ? WHERE id = ? AND org_id = ?`, ts, detection.id, orgId);

      const incident = get('SELECT * FROM incidents WHERE id = ?', id);
      recordIncidentNotification(orgId, incident, site, { reason: 'incident_created' });
      return id;
    });
  } catch (error) {
    if (/UNIQUE constraint failed/.test(error?.message ?? '')) return null;
    throw error;
  }
}

function attachToIncident(orgId, incident, site, detection, explanation, entities) {
  return transaction(() => {
    const link = run(
      'INSERT OR IGNORE INTO incident_detections (detection_id, incident_id, org_id, created_at) VALUES (?, ?, ?, ?)',
      detection.id, incident.id, orgId, nowIso(),
    );
    if (!link.changes) return false;
    const ts = nowIso();
    const severity = higherSeverity(incident.severity, detection.severity);
    const priority = priorityFor(severity, site.criticality);
    // The title follows the highest severity rule that has joined the incident.
    const title = severity !== incident.severity && explanation.ruleName
      ? `${explanation.ruleName} against ${site.display_name}`
      : incident.title;
    run(
      `UPDATE incidents SET severity = ?, priority = ?, title = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
      severity, priority, title, ts, incident.id, orgId,
    );
    for (const [type, value] of entities) {
      run(
        `INSERT OR IGNORE INTO incident_entities (id, org_id, incident_id, entity_type, entity_value, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        newId('ien'), orgId, incident.id, type, value, ts,
      );
    }
    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'detection', ?, NULL, ?, ?)`,
      newId('ince'), orgId, incident.id,
      `Detection ${detection.id} attached to the incident.`,
      JSON.stringify({ detectionId: detection.id, ruleKey: explanation.ruleKey, severity: detection.severity }), ts,
    );
    run(`UPDATE detections SET status = 'confirmed', updated_at = ? WHERE id = ? AND org_id = ?`, ts, detection.id, orgId);
    if (PRIORITY_RANK[priority] < PRIORITY_RANK[incident.priority]) {
      recordIncidentNotification(orgId, { ...incident, priority, severity }, site, { reason: 'priority_increased' });
    }
    return true;
  });
}

/**
 * Throttled in-app notification. Suppression is recorded with a reason and the
 * incident is never suppressed; a critical alert is only ever delayed, and the
 * delay is visible on the website and incident views.
 */
export function recordIncidentNotification(orgId, incident, site, { reason = 'incident_created' } = {}) {
  const cooldownMs = 15 * 60 * 1000;
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const last = get(
    'SELECT * FROM notifications WHERE org_id = ? AND incident_id = ? ORDER BY created_at DESC LIMIT 1',
    orgId, incident.id,
  );
  const orgCount = get(
    `SELECT COUNT(*) AS c FROM notifications WHERE org_id = ? AND created_at >= ? AND status = 'sent'`,
    orgId, hourAgo,
  ).c;
  const cap = Number(process.env.SF_NOTIFICATION_HOURLY_CAP ?? 60);

  let status = 'sent';
  let suppression = null;
  const priorityIncreased = last && PRIORITY_RANK[incident.priority] < PRIORITY_RANK[last.priority];
  if (orgCount >= cap) {
    status = 'suppressed';
    suppression = 'organization_hourly_cap';
  } else if (last && Date.now() - new Date(last.created_at).getTime() < cooldownMs && !priorityIncreased) {
    status = 'suppressed';
    suppression = 'incident_cooldown_15m';
  }

  const title = status === 'sent'
    ? `${incident.priority} ${incident.severity}: ${incident.title}`
    : `Suppressed: ${incident.priority} ${incident.severity}: ${incident.title}`;
  const body = status === 'sent'
    ? `Recorded ${reason.replace(/_/g, ' ')}. Website: ${site.display_name} (${site.hostname}). Open the incident for the linked detections and events.`
    : `A notification was not delivered because of ${String(suppression).replace(/_/g, ' ')}. The incident and its detections are preserved; counters were updated silently.`;

  const dedupe = `${incident.id}:${Math.floor(Date.now() / 60000)}`;
  run(
    `INSERT OR IGNORE INTO notifications (id, org_id, incident_id, site_id, kind, priority, channel, status, suppression_reason, title, body, dedupe_key, created_at)
     VALUES (?, ?, ?, ?, 'incident', ?, 'in_app', ?, ?, ?, ?, ?, ?)`,
    newId('ntf'), orgId, incident.id, site.id, incident.priority, status, suppression, title, body, dedupe, nowIso(),
  );

  if (status === 'sent') {
    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'notification', ?, NULL, ?, ?)`,
      newId('ince'), orgId, incident.id,
      `In-app notification recorded (${incident.priority}).`,
      JSON.stringify({ reason, channel: 'in_app' }), nowIso(),
    );
  }
  return { status, suppression };
}
