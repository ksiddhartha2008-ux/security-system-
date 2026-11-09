import { all, get, run, newId, nowIso, parseJson } from '../db.js';

const PRIORITY = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4' };

/**
 * Deterministic incident correlation. A high risk detection that is not yet
 * linked to an incident becomes one, together with the events that share its
 * asset or source address. No model inference and no arbitrary counts.
 */
export function correlateDetections(orgId, { limit = 8, actorId = null } = {}) {
  const rows = all(
    `SELECT d.*, e.src_ip AS event_src_ip, e.asset_id AS event_asset_id, e.occurred_at AS event_occurred_at
       FROM detections d
       LEFT JOIN security_events e ON e.id = d.event_id
      WHERE d.org_id = ? AND d.status = 'open' AND d.risk_score >= 70
        AND NOT EXISTS (
          SELECT 1 FROM incident_events ie
           WHERE ie.org_id = d.org_id AND json_extract(ie.metadata, '$.detectionId') = d.id
        )
      ORDER BY d.risk_score DESC, d.detected_at DESC
      LIMIT ?`,
    orgId, limit,
  );

  const created = [];
  const year = new Date().getUTCFullYear();

  for (const detection of rows) {
    const assetId = detection.asset_id ?? detection.event_asset_id ?? null;
    const srcIp = detection.event_src_ip ?? parseJson(detection.explanation, {}).observed?.srcIp ?? null;
    const since = new Date(Date.now() - 2 * 3600_000).toISOString();
    const related = all(
      `SELECT id FROM security_events
        WHERE org_id = ? AND id != ?
          AND (asset_id = ? OR src_ip = ?)
          AND occurred_at >= ?
        ORDER BY occurred_at DESC LIMIT 5`,
      orgId, detection.event_id ?? '', assetId, srcIp, since,
    );
    const eventIds = [detection.event_id, ...related.map((row) => row.id)].filter(Boolean);

    const count = get('SELECT COUNT(*) AS c FROM incidents WHERE org_id = ?', orgId).c;
    const ref = `INC-${year}-${1001 + count}`;
    const id = newId('inc');
    const ts = nowIso();
    const explanation = parseJson(detection.explanation, {});

    run(
      `INSERT INTO incidents (id, org_id, ref, title, description, severity, priority, status, assignee_id, created_by, detected_at, due_at, resolved_at, created_at, updated_at, data_origin, demo_batch_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?, NULL, NULL, ?, ?, ?, ?)`,
      id, orgId, ref, detection.title,
      `${detection.description}\n\nCorrelated from detection ${detection.id} (rule: ${explanation.ruleKey ?? 'unknown'}). ${eventIds.length} related event(s) linked.`,
      detection.severity, PRIORITY[detection.severity] ?? 'P3', actorId,
      detection.detected_at, ts, ts, detection.data_origin ?? 'REAL', detection.demo_batch_id ?? null,
    );

    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'created', ?, ?, ?, ?)`,
      newId('ince'), orgId, id,
      `Incident opened by deterministic correlation from detection ${detection.id}.`,
      actorId, JSON.stringify({ detectionId: detection.id, eventIds, correlation: 'risk-threshold', riskScore: detection.risk_score }), ts,
    );

    run(
      `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
       VALUES (?, ?, ?, 'evidence', ?, NULL, ?, ?)`,
      newId('ince'), orgId, id,
      `${eventIds.length} event(s) attached as correlated evidence.`,
      JSON.stringify({ eventIds }), ts,
    );

    run(`UPDATE detections SET status = 'confirmed', updated_at = ? WHERE id = ?`, ts, detection.id);
    created.push({ id, ref, detectionId: detection.id, eventIds, riskScore: detection.risk_score });
  }

  return created;
}
