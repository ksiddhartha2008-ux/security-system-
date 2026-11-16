/**
 * Credential and database protection summary.
 *
 * Everything here is derived from stored security metadata. SecureFlow never
 * receives customer passwords, session cookies, tokens or request bodies, so
 * this module has nothing sensitive to redact at read time.
 */
import { all, get } from '../db.js';
import { verifyAuditChain } from '../lib/audit.js';
import { maskAddress } from './infraAddresses.js';

const HOURS = (hours) => new Date(Date.now() - hours * 3600_000).toISOString();

function countByType(orgId, types, since) {
  if (!types.length) return {};
  const placeholders = types.map(() => '?').join(', ');
  const rows = all(
    `SELECT event_type, COUNT(*) AS count FROM security_events
      WHERE org_id = ? AND occurred_at >= ? AND event_type IN (${placeholders})
      GROUP BY event_type`,
    orgId, since, ...types,
  );
  return Object.fromEntries(rows.map((row) => [row.event_type, row.count]));
}

function detectionRows(orgId, pattern, limit = 6) {
  return all(
    `SELECT rule_id, title, severity, risk_score, detected_at, explanation FROM detections
      WHERE org_id = ? AND status IN ('open','confirmed') AND json_extract(explanation, '$.ruleKey') LIKE ?
      ORDER BY risk_score DESC, detected_at DESC LIMIT ?`,
    orgId, pattern, limit,
  ).map((row) => {
    let explanation = {};
    try { explanation = JSON.parse(row.explanation || '{}'); } catch { explanation = {}; }
    return {
      ruleId: explanation.ruleKey ?? row.rule_id,
      title: row.title,
      severity: row.severity,
      riskScore: row.risk_score,
      detectedAt: row.detected_at,
    };
  });
}

function topSources(orgId, since) {
  return all(
    `SELECT src_ip, COUNT(*) AS hits FROM security_events
      WHERE org_id = ? AND occurred_at >= ? AND event_type IN ('auth.failure','auth.mfa_failure','database.auth_failure')
        AND src_ip IS NOT NULL
      GROUP BY src_ip ORDER BY hits DESC LIMIT 5`,
    orgId, since,
  ).map((row) => ({ address: maskAddress(row.src_ip), hits: row.hits }));
}

export function dataProtectionOverview(orgId) {
  const day = HOURS(24);
  const week = HOURS(24 * 7);
  const credentialTypes = [
    'auth.success', 'auth.failure', 'auth.password_reset', 'auth.mfa_failure',
    'auth.account_locked', 'auth.password_changed', 'authz.denied', 'api.rate_limit',
  ];
  const databaseTypes = ['database.auth_failure', 'database.privileged', 'database.schema_change', 'database.export'];

  const credentialDay = countByType(orgId, credentialTypes, day);
  const credentialWeek = countByType(orgId, credentialTypes, week);
  const databaseDay = countByType(orgId, databaseTypes, day);

  const exports = get(
    `SELECT COUNT(*) AS exports,
            COALESCE(SUM(CAST(json_extract(raw, '$.attributes.records') AS INTEGER)), 0) AS records
       FROM security_events
      WHERE org_id = ? AND occurred_at >= ? AND event_type = 'database.export'`,
    orgId, day,
  );

  const mfa = get(
    "SELECT COUNT(*) AS total, SUM(CASE WHEN mfa_enabled = 1 THEN 1 ELSE 0 END) AS enabled FROM users WHERE org_id = ? AND status = 'active'",
    orgId,
  );
  const sites = get(
    "SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) AS verified, MAX(last_event_at) AS lastEventAt FROM website_sites WHERE org_id = ? AND status != 'deleted'",
    orgId,
  );
  const incidents = get(
    `SELECT COUNT(*) AS open FROM incidents WHERE org_id = ? AND status IN ('open','investigating')`,
    orgId,
  );

  let audit = { ok: null, detail: 'Not checked' };
  try {
    const result = verifyAuditChain(orgId);
    audit = {
      ok: result.ok !== false,
      detail: result.ok === false ? `Audit chain broken at ${result.brokenAt ?? 'an unknown row'}` : 'Audit chain verified',
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    audit = { ok: false, detail: String(error.message).slice(0, 160) };
  }

  return {
    generatedAt: new Date().toISOString(),
    credential: {
      events24h: Object.values(credentialDay).reduce((sum, value) => sum + value, 0),
      events7d: Object.values(credentialWeek).reduce((sum, value) => sum + value, 0),
      failures24h: credentialDay['auth.failure'] ?? 0,
      successes24h: credentialDay['auth.success'] ?? 0,
      mfaFailures24h: credentialDay['auth.mfa_failure'] ?? 0,
      resetRequests24h: credentialDay['auth.password_reset'] ?? 0,
      locked24h: credentialDay['auth.account_locked'] ?? 0,
      denials24h: credentialDay['authz.denied'] ?? 0,
      rateLimited24h: credentialDay['api.rate_limit'] ?? 0,
      mfa: { enabled: mfa?.enabled ?? 0, total: mfa?.total ?? 0 },
      detections: detectionRows(orgId, 'w-auth-%'),
      apiDetections: detectionRows(orgId, 'w-api-%', 3),
      topSources: topSources(orgId, day),
    },
    database: {
      events24h: Object.values(databaseDay).reduce((sum, value) => sum + value, 0),
      authFailures24h: databaseDay['database.auth_failure'] ?? 0,
      privileged24h: databaseDay['database.privileged'] ?? 0,
      schemaChanges24h: databaseDay['database.schema_change'] ?? 0,
      exports24h: databaseDay['database.export'] ?? 0,
      exportedRecords24h: Number(exports?.records ?? 0),
      detections: detectionRows(orgId, 'w-db-%'),
      auditSource: {
        state: sites?.verified ? 'CONFIGURED' : 'NOT CONFIGURED',
        detail: sites?.verified
          ? 'Database metadata arrives through the website SDK. The SDK must emit database.* events from the application; it does not read the database audit log itself.'
          : 'No verified website is sending database metadata. Register and verify a website, then emit database.* events from the application.',
      },
    },
    sites: {
      total: sites?.total ?? 0,
      verified: sites?.verified ?? 0,
      lastEventAt: sites?.lastEventAt ?? null,
    },
    incidents: { open: incidents?.open ?? 0 },
    audit,
    policy: {
      secretsAccepted: false,
      note: 'Passwords, tokens, cookies and request bodies are rejected or stripped at ingestion. Only security metadata is stored.',
    },
  };
}
