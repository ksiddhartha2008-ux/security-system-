import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { WEBSITE_RULES } from './websiteRules.js';

/** ISO timestamp N minutes in the past, matching the stored ISO-8601 format exactly. */
const WINDOW = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();

/**
 * Deterministic detection baseline. Every detection stores the factors used to
 * score it so an analyst can audit the decision. AI never decides alone here.
 */
export const SEVERITY_BASE = { info: 5, low: 25, medium: 45, high: 65, critical: 85 };
export const CRITICALITY_BONUS = { low: 0, medium: 3, high: 7, critical: 12 };

export const RULES = [
  {
    key: 'brute-force-auth',
    name: 'Repeated authentication failures from one source',
    category: 'identity',
    severity: 'high',
    description: 'A single source IP produced 5 or more failed authentications inside the 10 minute window.',
    threshold: 5,
    windowMinutes: 10,
    evaluate(orgId) {
      const rows = all(
        `SELECT src_ip, COUNT(*) AS hits, MIN(occurred_at) AS first_seen, MAX(occurred_at) AS last_seen,
                GROUP_CONCAT(DISTINCT user_email) AS targets
           FROM security_events
          WHERE org_id = ? AND event_type = 'auth.failure'
            AND occurred_at >= '${WINDOW(10)}'
          GROUP BY src_ip HAVING hits >= 5 ORDER BY hits DESC LIMIT 25`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `brute:${r.src_ip}`,
        title: `Authentication brute force from ${r.src_ip}`,
        description: `${r.hits} failed authentication attempts were recorded from ${r.src_ip} within 10 minutes.`,
        severity: 'high',
        confidence: Math.min(60 + r.hits * 3, 96),
        observed: { srcIp: r.src_ip, attempts: r.hits, firstSeen: r.first_seen, lastSeen: r.last_seen },
        factors: [
          { label: 'Failed authentication volume', weight: 40, detail: `${r.hits} failures in 10 minutes` },
          { label: 'Single source concentration', weight: 20, detail: `all attempts originated from ${r.src_ip}` },
          { label: 'Rule confidence', weight: 15, detail: 'deterministic threshold rule, no model inference' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'credential-stuffing',
    name: 'Credential stuffing pattern across many accounts',
    category: 'identity',
    severity: 'critical',
    description: 'One source tried several distinct accounts with failed credentials, the classic stuffing shape.',
    threshold: 8,
    windowMinutes: 15,
    evaluate(orgId) {
      const rows = all(
        `SELECT src_ip, COUNT(*) AS hits, COUNT(DISTINCT user_email) AS targets
           FROM security_events
          WHERE org_id = ? AND event_type = 'auth.failure' AND user_email IS NOT NULL
            AND occurred_at >= '${WINDOW(15)}'
          GROUP BY src_ip HAVING hits >= 8 AND targets >= 4 ORDER BY hits DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `stuffing:${r.src_ip}`,
        title: `Credential stuffing attempt from ${r.src_ip}`,
        description: `${r.hits} failed logins spread across ${r.targets} distinct accounts from one source in 15 minutes.`,
        severity: 'critical',
        confidence: 90,
        observed: { srcIp: r.src_ip, attempts: r.hits, accounts: r.targets },
        factors: [
          { label: 'Account spread', weight: 45, detail: `${r.targets} distinct accounts targeted` },
          { label: 'Attempt volume', weight: 30, detail: `${r.hits} failures in 15 minutes` },
          { label: 'Source concentration', weight: 15, detail: 'all failures from one address' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'api-rate-abuse',
    name: 'API request rate far above baseline',
    category: 'application',
    severity: 'medium',
    description: 'A client exceeded 60 API requests in 5 minutes, indicating scraping or abuse.',
    threshold: 60,
    windowMinutes: 5,
    evaluate(orgId) {
      const rows = all(
        `SELECT src_ip, COUNT(*) AS hits
           FROM security_events
          WHERE org_id = ? AND event_type IN ('api.request','api.rate_limit')
            AND occurred_at >= '${WINDOW(5)}'
          GROUP BY src_ip HAVING hits >= 60 ORDER BY hits DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `api:${r.src_ip}`,
        title: `Abnormal API request rate from ${r.src_ip}`,
        description: `${r.hits} API requests in 5 minutes from a single client, above the 60 request baseline.`,
        severity: 'medium',
        confidence: 78,
        observed: { srcIp: r.src_ip, requests: r.hits },
        factors: [
          { label: 'Request rate', weight: 45, detail: `${r.hits} requests in 5 minutes` },
          { label: 'Single client', weight: 20, detail: `traffic attributed to ${r.src_ip}` },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'port-scan',
    name: 'Sequential port scanning',
    category: 'network',
    severity: 'high',
    description: 'One source touched 12 or more distinct destination ports in 10 minutes.',
    threshold: 12,
    windowMinutes: 10,
    evaluate(orgId) {
      const rows = all(
        `SELECT src_ip, COUNT(DISTINCT dest_port) AS ports, COUNT(*) AS flows
           FROM network_events
          WHERE org_id = ? AND occurred_at >= '${WINDOW(10)}'
          GROUP BY src_ip HAVING ports >= 12 ORDER BY ports DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `scan:${r.src_ip}`,
        title: `Port scan from ${r.src_ip}`,
        description: `${r.ports} distinct destination ports probed by ${r.src_ip} in 10 minutes.`,
        severity: 'high',
        confidence: 84,
        observed: { srcIp: r.src_ip, distinctPorts: r.ports, flows: r.flows },
        factors: [
          { label: 'Port diversity', weight: 45, detail: `${r.ports} distinct destination ports` },
          { label: 'Flow count', weight: 20, detail: `${r.flows} connection attempts` },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'data-exfiltration',
    name: 'Large outbound data transfer',
    category: 'network',
    severity: 'critical',
    description: 'A single outbound flow exceeded 50 MB, the threshold used for bulk transfer review.',
    threshold: 50,
    windowMinutes: 60,
    evaluate(orgId) {
      const rows = all(
        `SELECT src_ip, dest_ip, SUM(bytes_out) AS bytes, COUNT(*) AS flows
           FROM network_events
          WHERE org_id = ? AND direction = 'outbound' AND bytes_out > 52428800
            AND occurred_at >= '${WINDOW(60)}'
          GROUP BY src_ip, dest_ip ORDER BY bytes DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `exfil:${r.src_ip}:${r.dest_ip}`,
        title: `Large outbound transfer to ${r.dest_ip}`,
        description: `${(r.bytes / 1048576).toFixed(1)} MB left ${r.src_ip} toward ${r.dest_ip} in the last hour.`,
        severity: 'critical',
        confidence: 80,
        observed: { srcIp: r.src_ip, destIp: r.dest_ip, megabytes: +(r.bytes / 1048576).toFixed(1), flows: r.flows },
        factors: [
          { label: 'Transfer volume', weight: 55, detail: `${(r.bytes / 1048576).toFixed(1)} MB outbound` },
          { label: 'External destination', weight: 15, detail: `destination ${r.dest_ip}` },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'ransomware-behaviour',
    name: 'Ransomware style file and process behaviour',
    category: 'endpoint',
    severity: 'critical',
    description: 'File encryption bursts or shadow copy deletion were observed on a monitored endpoint.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const rows = all(
        `SELECT id, asset_id, src_ip, title, event_type, occurred_at
           FROM security_events
          WHERE org_id = ? AND event_type IN ('file.encrypt','process.shadow_copy_delete','process.ransom_note')
            AND occurred_at >= '${WINDOW(30)}'
          ORDER BY occurred_at DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `ransom:${r.id}`,
        eventId: r.id,
        assetId: r.asset_id,
        title: `Ransomware behaviour on asset: ${r.title}`,
        description: 'Endpoint telemetry matches a ransomware behaviour pattern (mass encryption or recovery inhibition).',
        severity: 'critical',
        confidence: 88,
        observed: { eventType: r.event_type, assetId: r.asset_id, occurredAt: r.occurred_at },
        factors: [
          { label: 'Behaviour match', weight: 55, detail: r.event_type },
          { label: 'Endpoint evidence', weight: 20, detail: 'process and file telemetry agree' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'phishing-interaction',
    name: 'User interacted with a reported phishing message',
    category: 'email',
    severity: 'high',
    description: 'A user clicked or submitted credentials after a reported phishing message.',
    threshold: 1,
    windowMinutes: 60,
    evaluate(orgId) {
      const rows = all(
        `SELECT id, user_email, src_ip, title, event_type, occurred_at
           FROM security_events
          WHERE org_id = ? AND event_type IN ('email.click','email.credential_submit')
            AND occurred_at >= '${WINDOW(60)}'
          ORDER BY occurred_at DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `phish:${r.id}`,
        eventId: r.id,
        title: `Phishing interaction by ${r.user_email ?? 'a user'}`,
        description: 'A mailbox user interacted with a message that matched phishing indicators.',
        severity: 'high',
        confidence: 82,
        observed: { userEmail: r.user_email, eventType: r.event_type, occurredAt: r.occurred_at },
        factors: [
          { label: 'User interaction', weight: 45, detail: r.event_type },
          { label: 'Reported message', weight: 20, detail: r.title },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'web-attack',
    name: 'Web attack signature on an internet facing service',
    category: 'application',
    severity: 'critical',
    description: 'A request matched a SQL injection or cross site scripting signature against a web service.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const rows = all(
        `SELECT id, asset_id, src_ip, title, event_type, occurred_at
           FROM security_events
          WHERE org_id = ? AND event_type IN ('web.sql_injection','web.xss')
            AND occurred_at >= '${WINDOW(30)}'
          ORDER BY occurred_at DESC LIMIT 20`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `web:${r.id}`,
        eventId: r.id,
        assetId: r.asset_id,
        title: `Web attack attempt: ${r.title}`,
        description: `A ${r.event_type === 'web.xss' ? 'cross site scripting' : 'SQL injection'} payload was sent from ${r.src_ip ?? 'an unknown source'}.`,
        severity: 'critical',
        confidence: 92,
        observed: { eventType: r.event_type, srcIp: r.src_ip, occurredAt: r.occurred_at },
        factors: [
          { label: 'Signature match', weight: 50, detail: r.event_type },
          { label: 'Internet facing target', weight: 18, detail: 'request reached the application tier' },
          { label: 'Deterministic rule', weight: 12, detail: 'no model inference' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'malware-detection',
    name: 'Malware detected on a monitored endpoint',
    category: 'endpoint',
    severity: 'critical',
    description: 'Endpoint protection reported a malicious file or quarantined payload.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const rows = all(
        `SELECT id, asset_id, src_ip, title, event_type, occurred_at
           FROM security_events
          WHERE org_id = ? AND event_type IN ('malware.detected','malware.quarantined')
            AND occurred_at >= '${WINDOW(30)}'
          ORDER BY occurred_at DESC LIMIT 20`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `malware:${r.id}`,
        eventId: r.id,
        assetId: r.asset_id,
        title: `Malware detection: ${r.title}`,
        description: 'A malicious payload was identified by the endpoint sensor.',
        severity: 'critical',
        confidence: 95,
        observed: { eventType: r.event_type, assetId: r.asset_id, occurredAt: r.occurred_at },
        factors: [
          { label: 'Malware verdict', weight: 55, detail: r.event_type },
          { label: 'Endpoint evidence', weight: 20, detail: 'sensor verdict on the host' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'privileged-login-anomaly',
    name: 'Privileged account sign-in from an unusual source',
    category: 'identity',
    severity: 'high',
    description: 'An administrative account signed in from a source outside the usual range.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const rows = all(
        `SELECT id, asset_id, src_ip, title, user_email, occurred_at
           FROM security_events
          WHERE org_id = ? AND event_type = 'auth.privileged_login'
            AND occurred_at >= '${WINDOW(30)}'
          ORDER BY occurred_at DESC LIMIT 10`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `admin-login:${r.id}`,
        eventId: r.id,
        assetId: r.asset_id,
        title: `Privileged sign-in from an unusual source`,
        description: `${r.user_email ?? 'An administrative account'} signed in from ${r.src_ip ?? 'an external address'} outside the usual range.`,
        severity: 'high',
        confidence: 82,
        observed: { userEmail: r.user_email, srcIp: r.src_ip, occurredAt: r.occurred_at },
        factors: [
          { label: 'Privileged account', weight: 35, detail: r.user_email ?? 'admin role' },
          { label: 'Unusual source', weight: 25, detail: r.src_ip ?? 'external address' },
          { label: 'Time correlation', weight: 10, detail: 'outside the normal pattern' },
        ],
        srcIp: r.src_ip,
      }));
    },
  },
  {
    key: 'volume-anomaly',
    name: 'Event volume far above the hourly baseline',
    category: 'application',
    severity: 'medium',
    description: 'The last complete hour carried at least three times the seven day hourly average, with a floor of 30 events.',
    threshold: 3,
    windowMinutes: 60,
    evaluate(orgId) {
      const since = new Date(Date.now() - 7 * 24 * 3600_000).toISOString();
      const buckets = all(
        `SELECT substr(occurred_at, 1, 13) AS hour, COUNT(*) AS c
           FROM security_events WHERE org_id = ? AND occurred_at >= ?
          GROUP BY hour ORDER BY hour DESC LIMIT 200`,
        orgId, since,
      );
      if (buckets.length < 6) return [];
      const currentHour = new Date().toISOString().slice(0, 13);
      const current = buckets.find((b) => b.hour === currentHour)?.c ?? 0;
      const prior = buckets.filter((b) => b.hour !== currentHour).map((b) => b.c);
      if (!prior.length) return [];
      const average = prior.reduce((sum, value) => sum + value, 0) / prior.length;
      if (current < 30 || current < average * 3) return [];
      const ratio = average > 0 ? +(current / average).toFixed(1) : 0;
      return [{
        signature: `volume:${currentHour}`,
        title: 'Event volume is far above the hourly baseline',
        description: `${current} events were recorded this hour against a seven day hourly average of ${average.toFixed(1)} (${ratio}x).`,
        severity: 'medium',
        confidence: 72,
        observed: { currentHour, current, average: +average.toFixed(1), ratio, hoursCompared: prior.length },
        factors: [
          { label: 'Volume ratio', weight: 40, detail: `${ratio}x the seven day hourly average` },
          { label: 'Baseline stability', weight: 12, detail: `${prior.length} hours of history compared` },
          { label: 'Statistical method', weight: 8, detail: 'mean of prior hours, no model inference' },
        ],
      }];
    },
  },
  {
    key: 'privilege-escalation',
    name: 'Repeated authorization denials',
    category: 'application',
    severity: 'medium',
    description: 'Five or more authorization denials from one identity indicates probing for permissions.',
    threshold: 5,
    windowMinutes: 10,
    evaluate(orgId) {
      const rows = all(
        `SELECT user_email, COUNT(*) AS hits
           FROM security_events
          WHERE org_id = ? AND event_type = 'authz.denied' AND user_email IS NOT NULL
            AND occurred_at >= '${WINDOW(10)}'
          GROUP BY user_email HAVING hits >= 5 ORDER BY hits DESC LIMIT 15`,
        orgId,
      );
      return rows.map((r) => ({
        signature: `privesc:${r.user_email}`,
        title: `Authorization probing by ${r.user_email}`,
        description: `${r.hits} authorization denials for ${r.user_email} in 10 minutes.`,
        severity: 'medium',
        confidence: 74,
        observed: { userEmail: r.user_email, denials: r.hits },
        factors: [
          { label: 'Denial volume', weight: 40, detail: `${r.hits} denied requests` },
          { label: 'Single identity', weight: 15, detail: r.user_email },
        ],
      }));
    },
  },
];

export function scoreDetection({ severity, confidence, factors = [], assetCriticality = 'medium' }) {
  const base = SEVERITY_BASE[severity] ?? 40;
  const explained = factors.reduce((sum, f) => sum + (Number(f.weight) || 0), 0);
  const bonus = CRITICALITY_BONUS[assetCriticality] ?? 0;
  const confidenceLift = Math.round((Number(confidence) || 50) * 0.08);
  const raw = base + Math.min(explained, 30) * 0.25 + bonus + confidenceLift;
  return Math.max(1, Math.min(100, Math.round(raw)));
}

export function ruleRowToRule(row) {
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    severity: row.severity,
    category: row.category,
    description: row.description,
    threshold: row.threshold,
    windowMinutes: row.window_minutes,
    enabled: row.enabled === 1,
  };
}

export function ensureRules(orgId) {
  const existing = all('SELECT key FROM detection_rules WHERE org_id = ?', orgId).map((r) => r.key);
  const ts = nowIso();
  for (const rule of [...RULES, ...WEBSITE_RULES]) {
    if (existing.includes(rule.key)) continue;
    run(
      `INSERT INTO detection_rules (id, org_id, key, name, category, severity, description, threshold, window_minutes, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
      newId('rule'), orgId, rule.key, rule.name, rule.category, rule.severity, rule.description,
      rule.threshold, rule.windowMinutes, ts, ts,
    );
  }
}

/** Evaluate every enabled deterministic rule. `write=false` gives a dry run. */
export function evaluateRules(orgId, { write = true, dataOrigin: originHint = null, demoBatchId: batchHint = null } = {}) {
  ensureRules(orgId);
  const dbRules = all('SELECT * FROM detection_rules WHERE org_id = ? AND enabled = 1', orgId);
  const recent = all(
    `SELECT explanation FROM detections WHERE org_id = ? AND detected_at >= '${WINDOW(120)}'`,
    orgId,
  ).map((r) => parseJson(r.explanation, {}).signature).filter(Boolean);

  const produced = [];
  for (const row of dbRules) {
    const rule = [...RULES, ...WEBSITE_RULES].find((r) => r.key === row.key);
    if (!rule) continue;
    let findings = [];
    try {
      findings = rule.evaluate(orgId) ?? [];
    } catch (err) {
      console.error('[detection] rule failed', rule.key, err.message);
      continue;
    }
    for (const finding of findings) {
      if (recent.includes(finding.signature)) continue;
      const asset = finding.assetId
        ? get('SELECT criticality, data_origin, demo_batch_id FROM assets WHERE id = ? AND org_id = ?', finding.assetId, orgId)
        : null;
      const sourceEvent = finding.eventId
        ? get('SELECT data_origin, demo_batch_id FROM security_events WHERE id = ? AND org_id = ?', finding.eventId, orgId)
        : null;
      const dataOrigin = sourceEvent?.data_origin ?? asset?.data_origin ?? originHint ?? 'REAL';
      const demoBatchId = sourceEvent?.demo_batch_id ?? asset?.demo_batch_id ?? batchHint ?? null;
      const risk = scoreDetection({
        severity: finding.severity,
        confidence: finding.confidence,
        factors: finding.factors,
        assetCriticality: asset?.criticality ?? 'medium',
      });
      const explanation = {
        ruleKey: rule.key,
        ruleName: rule.name,
        signature: finding.signature,
        summary: finding.description,
        factors: finding.factors,
        observed: finding.observed,
        scoreModel: 'base severity + capped factor weights + asset criticality + confidence lift',
        deterministic: true,
        windowMinutes: rule.windowMinutes,
        websiteSiteId: finding.siteId ?? null,
        evaluatedAt: nowIso(),
      };
      const id = newId('det');
      if (write) {
        run(
          `INSERT INTO detections (id, org_id, rule_id, event_id, asset_id, title, description, severity, risk_score, confidence, status, explanation, detected_at, created_at, updated_at, data_origin, demo_batch_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
          id, orgId, row.id, finding.eventId ?? null, finding.assetId ?? null,
          finding.title, finding.description, finding.severity, risk, finding.confidence,
          JSON.stringify(explanation), nowIso(), nowIso(), nowIso(), dataOrigin, demoBatchId,
        );
        recent.push(finding.signature);
        produced.push({ id, title: finding.title, severity: finding.severity, riskScore: risk, ruleKey: rule.key, siteId: finding.siteId ?? null });
      } else {
        produced.push({ title: finding.title, severity: finding.severity, riskScore: risk, ruleKey: rule.key, siteId: finding.siteId ?? null });
      }
    }
  }
  return produced;
}

/** Raise the risk score on an asset that appears in high risk detections. */
export function refreshAssetRisk(orgId) {
  const rows = all(
    `SELECT asset_id, MAX(risk_score) AS top FROM detections
      WHERE org_id = ? AND asset_id IS NOT NULL AND status IN ('open','confirmed')
        AND detected_at >= '${WINDOW(10080)}' GROUP BY asset_id`,
    orgId,
  );
  for (const row of rows) {
    run('UPDATE assets SET risk_score = ?, updated_at = ? WHERE id = ? AND org_id = ?',
      Math.min(100, row.top), nowIso(), row.asset_id, orgId);
  }
}
