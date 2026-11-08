import { Router } from 'express';
import { all, get } from '../db.js';
import { asyncHandler, ok } from '../lib/http.js';
import { requireAuth } from '../lib/auth.js';

const router = Router();
router.use(requireAuth);

const since = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

router.get('/summary', asyncHandler(async (req, res) => {
  const org = req.user.orgId;
  const oneDay = since(1);
  const sevenDays = since(7);

  const eventTotals = get(
    `SELECT COUNT(*) total,
            SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) high_severity,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) critical,
            SUM(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END) last_24h
       FROM security_events WHERE org_id = ?`,
    oneDay, org,
  );
  const incidents = get(
    `SELECT COUNT(*) total,
            SUM(CASE WHEN status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) open_count,
            SUM(CASE WHEN severity = 'critical' AND status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) critical_open
       FROM incidents WHERE org_id = ?`,
    org,
  );
  const assets = get(
    `SELECT COUNT(*) total,
            SUM(CASE WHEN criticality = 'critical' THEN 1 ELSE 0 END) critical,
            SUM(CASE WHEN risk_score >= 60 THEN 1 ELSE 0 END) at_risk,
            COALESCE(AVG(risk_score), 0) avg_risk
       FROM assets WHERE org_id = ?`,
    org,
  );
  const detections = get(
    `SELECT COUNT(*) total, SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) open_count,
            SUM(CASE WHEN status = 'open' AND risk_score >= 70 THEN 1 ELSE 0 END) high_risk
       FROM detections WHERE org_id = ?`,
    org,
  );
  const vulns = get(
    `SELECT COUNT(*) total, SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) open_count,
            SUM(CASE WHEN severity = 'critical' AND status = 'open' THEN 1 ELSE 0 END) critical_open
       FROM vulnerabilities WHERE org_id = ?`,
    org,
  );
  const sims = get(
    `SELECT COUNT(*) total, SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) completed,
            COALESCE(AVG(CASE WHEN risk_score IS NOT NULL THEN risk_score END), 0) avg_risk
       FROM simulations WHERE org_id = ?`,
    org,
  );
  const incidents7 = get(
    `SELECT COUNT(*) c FROM incidents WHERE org_id = ? AND detected_at >= ?`, org, sevenDays,
  );
  const resolved = all(
    `SELECT detected_at, resolved_at FROM incidents
      WHERE org_id = ? AND resolved_at IS NOT NULL ORDER BY resolved_at DESC LIMIT 25`, org,
  );
  const mttrHours = resolved.length
    ? +(resolved.reduce((sum, r) => sum + (new Date(r.resolved_at) - new Date(r.detected_at)) / 3_600_000, 0) / resolved.length).toFixed(1)
    : null;

  const severity = all(`SELECT severity, COUNT(*) c FROM security_events WHERE org_id = ? AND occurred_at >= ? GROUP BY severity`, org, sevenDays);
  const incidentStatus = all(`SELECT status, COUNT(*) c FROM incidents WHERE org_id = ? GROUP BY status`, org);
  const detectionStatus = all(`SELECT status, COUNT(*) c FROM detections WHERE org_id = ? GROUP BY status`, org);

  const topAssets = all(
    `SELECT id, name, hostname, criticality, risk_score, status FROM assets WHERE org_id = ? ORDER BY risk_score DESC, criticality DESC LIMIT 5`, org,
  );
  const recentEvents = all(
    `SELECT e.id, e.title, e.event_type, e.severity, e.source, e.occurred_at, a.hostname AS asset
       FROM security_events e LEFT JOIN assets a ON a.id = e.asset_id AND a.org_id = e.org_id
      WHERE e.org_id = ? ORDER BY e.occurred_at DESC LIMIT 8`, org,
  );
  const topSources = all(
    `SELECT source, COUNT(*) c FROM security_events WHERE org_id = ? AND occurred_at >= ? GROUP BY source ORDER BY c DESC LIMIT 5`,
    org, sevenDays,
  );
  const openIncidents = all(
    `SELECT i.id, i.ref, i.title, i.severity, i.status, i.detected_at, u.name AS assignee
       FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id
      WHERE i.org_id = ? AND i.status NOT IN ('resolved','closed')
      ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, i.detected_at DESC
      LIMIT 5`, org,
  );

  return ok(res, {
    kpis: {
      eventsTotal: eventTotals.total ?? 0,
      events24h: eventTotals.last_24h ?? 0,
      highSeverityEvents: eventTotals.high_severity ?? 0,
      criticalEvents: eventTotals.critical ?? 0,
      incidentsTotal: incidents.total ?? 0,
      incidentsOpen: incidents.open_count ?? 0,
      criticalIncidents: incidents.critical_open ?? 0,
      incidents7d: incidents7.c ?? 0,
      assetsTotal: assets.total ?? 0,
      criticalAssets: assets.critical ?? 0,
      assetsAtRisk: assets.at_risk ?? 0,
      avgAssetRisk: Math.round(assets.avg_risk ?? 0),
      detectionsOpen: detections.open_count ?? 0,
      detectionsHighRisk: detections.high_risk ?? 0,
      vulnerabilitiesOpen: vulns.open_count ?? 0,
      criticalVulns: vulns.critical_open ?? 0,
      simulations: sims.total ?? 0,
      simulationsCompleted: sims.completed ?? 0,
      meanSimulatedRisk: Math.round(sims.avg_risk ?? 0),
      mttrHours,
    },
    severity: Object.fromEntries(severity.map((s) => [s.severity, s.c])),
    incidentStatus: Object.fromEntries(incidentStatus.map((s) => [s.status, s.c])),
    detectionStatus: Object.fromEntries(detectionStatus.map((s) => [s.status, s.c])),
    topAssets,
    recentEvents,
    topSources,
    openIncidents,
    generatedAt: new Date().toISOString(),
  });
}));

router.get('/trends', asyncHandler(async (req, res) => {
  const org = req.user.orgId;
  const days = Math.min(Math.max(Number(req.query.days ?? 14), 7), 90);
  const start = since(days);
  const events = all(
    `SELECT substr(occurred_at, 1, 10) AS day, COUNT(*) c,
            SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) high
       FROM security_events WHERE org_id = ? AND occurred_at >= ? GROUP BY day ORDER BY day`,
    org, start,
  );
  const incidents = all(
    `SELECT substr(detected_at, 1, 10) AS day, COUNT(*) c FROM incidents
      WHERE org_id = ? AND detected_at >= ? GROUP BY day ORDER BY day`, org, start,
  );
  const detections = all(
    `SELECT substr(detected_at, 1, 10) AS day, COUNT(*) c, ROUND(AVG(risk_score)) avg_risk FROM detections
      WHERE org_id = ? AND detected_at >= ? GROUP BY day ORDER BY day`, org, start,
  );
  const network = all(
    `SELECT substr(occurred_at, 1, 10) AS day, SUM(bytes_out) bytes, COUNT(*) flows FROM network_events
      WHERE org_id = ? AND occurred_at >= ? GROUP BY day ORDER BY day`, org, start,
  );

  const map = new Map();
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10);
    map.set(d, { day: d, events: 0, highSeverity: 0, incidents: 0, detections: 0, avgRisk: 0, bytesOut: 0, flows: 0 });
  }
  for (const row of events) {
    const entry = map.get(row.day);
    if (entry) { entry.events = row.c; entry.highSeverity = row.high; }
  }
  for (const row of incidents) { const e = map.get(row.day); if (e) e.incidents = row.c; }
  for (const row of detections) { const e = map.get(row.day); if (e) { e.detections = row.c; e.avgRisk = row.avg_risk ?? 0; } }
  for (const row of network) { const e = map.get(row.day); if (e) { e.bytesOut = row.bytes; e.flows = row.flows; } }
  return ok(res, [...map.values()]);
}));

export default router;
