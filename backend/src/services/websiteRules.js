import { all, get } from '../db.js';

const WINDOW = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();
const BUCKET = (minutes) => Math.floor(Date.now() / (minutes * 60_000));

/** Numeric severity used by the priority formula: 1 informational to 4 critical. */
export const SEVERITY_SCORE = { info: 1, low: 2, medium: 2, high: 3, critical: 4 };

function siteIndex(orgId) {
  const rows = all(
    `SELECT id, display_name, asset_id, criticality, hostname, scope, registrable_domain, sensitive_paths
       FROM website_sites WHERE org_id = ? AND status != 'deleted'`,
    orgId,
  );
  return new Map(rows.map((row) => [row.id, row]));
}

const base = (site, rule, severity, confidence, description, observed, factors, extra = {}) => ({
  signature: extra.signature,
  title: rule.name,
  description,
  severity,
  confidence,
  observed,
  factors,
  assetId: extra.assetId ?? site?.asset_id ?? null,
  siteId: extra.siteId ?? site?.id ?? null,
  siteName: site?.display_name ?? null,
  srcIp: extra.srcIp ?? null,
  actorId: extra.actorId ?? null,
  eventId: extra.eventId ?? null,
  ruleKey: rule.key,
});

/**
 * Website rules. Every threshold is a starting value exercised by fixtures in
 * backend/tests/website-detection.test.mjs, not a claim of optimal tuning.
 * Rules that compare against history simply produce nothing until the site has
 * enough data (cold start guard).
 */
export const WEBSITE_RULES = [
  {
    key: 'w-auth-001',
    name: 'Credential stuffing or password spraying',
    category: 'identity',
    severity: 'high',
    description: 'One client address produced at least 20 failed sign-ins across at least 10 distinct accounts within 10 minutes.',
    threshold: 20,
    windowMinutes: 10,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, src_ip, COUNT(*) AS hits, COUNT(DISTINCT user_email) AS actors
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL AND event_type = 'auth.failure'
            AND src_ip IS NOT NULL AND user_email IS NOT NULL AND occurred_at >= ?
          GROUP BY website_site_id, src_ip
         HAVING COUNT(*) >= 20 AND COUNT(DISTINCT user_email) >= 10
          ORDER BY hits DESC LIMIT 20`,
        orgId, WINDOW(10),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', Math.min(94, 80 + Math.floor(row.hits / 20)), `${row.hits} failed sign-ins for ${row.actors} accounts from ${row.src_ip} in 10 minutes.`, { srcIp: row.src_ip, attempts: row.hits, accounts: row.actors, windowMinutes: 10 }, [
        { label: 'Account spread', weight: 45, detail: `${row.actors} distinct accounts` },
        { label: 'Attempt volume', weight: 30, detail: `${row.hits} failures in 10 minutes` },
        { label: 'Single source', weight: 15, detail: row.src_ip },
      ], { signature: `w-auth-001:${row.site_id}:${row.src_ip}:${BUCKET(10)}`, srcIp: row.src_ip }));
    },
  },
  {
    key: 'w-auth-002',
    name: 'Brute force against one account',
    category: 'identity',
    severity: 'high',
    description: 'One account received at least 8 failed sign-ins within 10 minutes from any address.',
    threshold: 8,
    windowMinutes: 10,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, user_email AS actor, COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL AND event_type = 'auth.failure'
            AND user_email IS NOT NULL AND occurred_at >= ?
          GROUP BY website_site_id, user_email HAVING COUNT(*) >= 8
          ORDER BY hits DESC LIMIT 20`,
        orgId, WINDOW(10),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', Math.min(92, 78 + row.hits), `${row.hits} failed sign-ins for one account from ${row.sources} address(es) in 10 minutes.`, { actor: row.actor, attempts: row.hits, sources: row.sources }, [
        { label: 'Failure volume', weight: 40, detail: `${row.hits} failures` },
        { label: 'Single account', weight: 20, detail: row.actor },
      ], { signature: `w-auth-002:${row.site_id}:${row.actor}:${BUCKET(10)}`, actorId: row.actor }));
    },
  },
  {
    key: 'w-auth-003',
    name: 'Successful sign-in after authentication failures',
    category: 'identity',
    severity: 'critical',
    description: 'A sign-in succeeded after repeated failures for the same account, or from an address that produced a stuffing pattern in the previous 30 minutes.',
    threshold: 5,
    windowMinutes: 30,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT e.id, e.website_site_id AS site_id, e.user_email AS actor, e.src_ip, e.occurred_at,
                (SELECT COUNT(*) FROM security_events f
                  WHERE f.org_id = e.org_id AND f.website_site_id = e.website_site_id
                    AND f.event_type = 'auth.failure' AND f.user_email = e.user_email
                    AND julianday(f.occurred_at) BETWEEN julianday(e.occurred_at) - (30.0/1440) AND julianday(e.occurred_at)) AS prior_failures,
                (SELECT COUNT(*) FROM security_events f
                  WHERE f.org_id = e.org_id AND f.website_site_id = e.website_site_id
                    AND f.event_type = 'auth.failure' AND f.src_ip = e.src_ip
                    AND julianday(f.occurred_at) BETWEEN julianday(e.occurred_at) - (30.0/1440) AND julianday(e.occurred_at)) AS address_failures,
                (SELECT COUNT(DISTINCT f.user_email) FROM security_events f
                  WHERE f.org_id = e.org_id AND f.website_site_id = e.website_site_id
                    AND f.event_type = 'auth.failure' AND f.src_ip = e.src_ip
                    AND julianday(f.occurred_at) BETWEEN julianday(e.occurred_at) - (30.0/1440) AND julianday(e.occurred_at)) AS address_actors
           FROM security_events e
          WHERE e.org_id = ? AND e.website_site_id IS NOT NULL AND e.event_type = 'auth.success'
            AND e.occurred_at >= ? AND e.user_email IS NOT NULL
          ORDER BY e.occurred_at DESC LIMIT 40`,
        orgId, WINDOW(30),
      );
      return rows
        .filter((row) => row.prior_failures >= 5 || (row.address_failures >= 20 && row.address_actors >= 10))
        .map((row) => {
          const pattern = row.prior_failures >= 5 ? 'account' : 'address';
          return base(sites.get(row.site_id), this, 'critical', 90, `A sign-in for ${row.actor} succeeded after ${row.prior_failures} failures for the account and ${row.address_failures} failures from ${row.src_ip ?? 'the same address'}.`, { actor: row.actor, srcIp: row.src_ip, priorFailures: row.prior_failures, addressFailures: row.address_failures, pattern }, [
            { label: 'Failure history', weight: 45, detail: `${row.prior_failures} failures for the account` },
            { label: 'Source history', weight: 25, detail: `${row.address_failures} failures from the address` },
            { label: 'Success after failure', weight: 20, detail: 'time ordered correlation' },
          ], { signature: `w-auth-003:${row.site_id}:${row.actor}:${pattern}:${BUCKET(30)}`, srcIp: row.src_ip, actorId: row.actor, eventId: row.id });
        });
    },
  },
  {
    key: 'w-auth-004',
    name: 'Multi-factor authentication failure burst',
    category: 'identity',
    severity: 'high',
    description: 'One account produced at least 5 failed multi-factor challenges within 10 minutes.',
    threshold: 5,
    windowMinutes: 10,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, user_email AS actor, COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL AND event_type = 'auth.mfa_failure'
            AND user_email IS NOT NULL AND occurred_at >= ?
          GROUP BY website_site_id, user_email HAVING COUNT(*) >= 5
          ORDER BY hits DESC LIMIT 20`,
        orgId, WINDOW(10),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', 84, `${row.hits} failed multi-factor challenges for one account from ${row.sources} address(es) in 10 minutes.`, { actor: row.actor, failures: row.hits, sources: row.sources }, [
        { label: 'Second factor failures', weight: 40, detail: `${row.hits} failures` },
        { label: 'Single account', weight: 20, detail: row.actor },
      ], { signature: `w-auth-004:${row.site_id}:${row.actor}:${BUCKET(10)}`, actorId: row.actor }));
    },
  },
  {
    key: 'w-req-001',
    name: 'Scanning pattern across many paths',
    category: 'application',
    severity: 'high',
    description: 'One client address requested at least 15 distinct paths through suspicious requests or access denials within 5 minutes.',
    threshold: 15,
    windowMinutes: 5,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, src_ip, COUNT(DISTINCT json_extract(raw, '$.request.path')) AS paths, COUNT(*) AS hits
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL
            AND event_type IN ('web.suspicious_request','authz.denied')
            AND src_ip IS NOT NULL AND occurred_at >= ?
          GROUP BY website_site_id, src_ip HAVING COUNT(DISTINCT json_extract(raw, '$.request.path')) >= 15
          ORDER BY paths DESC LIMIT 20`,
        orgId, WINDOW(5),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', 86, `${row.paths} distinct paths were requested by ${row.src_ip} in 5 minutes, the shape of an automated scan.`, { srcIp: row.src_ip, distinctPaths: row.paths, requests: row.hits }, [
        { label: 'Path diversity', weight: 45, detail: `${row.paths} distinct paths` },
        { label: 'Short window', weight: 20, detail: 'all within 5 minutes' },
      ], { signature: `w-req-001:${row.site_id}:${row.src_ip}:${BUCKET(5)}`, srcIp: row.src_ip }));
    },
  },
  {
    key: 'w-req-002',
    name: 'Sensitive path probe',
    category: 'application',
    severity: 'medium',
    description: 'A request targeted a path on the site sensitive list, such as a configuration file or an administration console.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const findings = [];
      for (const site of siteIndex(orgId).values()) {
        let paths = [];
        try { paths = JSON.parse(site.sensitive_paths || '[]'); } catch { paths = []; }
        for (const path of paths.slice(0, 40)) {
          const row = get(
            `SELECT id, src_ip, occurred_at, json_extract(raw, '$.request.path') AS path
               FROM security_events
              WHERE org_id = ? AND website_site_id = ?
                AND event_type IN ('web.suspicious_request','authz.denied')
                AND occurred_at >= ?
                AND (json_extract(raw, '$.request.path') = ? OR json_extract(raw, '$.request.path') LIKE ?)
              ORDER BY occurred_at DESC LIMIT 1`,
            orgId, site.id, WINDOW(30), path, `${path}%`,
          );
          if (!row) continue;
          findings.push(base(site, this, 'medium', 76, `${row.path} was requested on ${site.display_name}. The path is on the site sensitive list.`, { path: row.path, srcIp: row.src_ip, occurredAt: row.occurred_at }, [
            { label: 'Sensitive path', weight: 35, detail: row.path },
            { label: 'Configured list', weight: 15, detail: 'editable per website' },
          ], { signature: `w-req-002:${site.id}:${path}:${BUCKET(30)}`, srcIp: row.src_ip, eventId: row.id }));
          if (findings.length >= 20) return findings;
        }
      }
      return findings;
    },
  },
  {
    key: 'w-req-003',
    name: 'Injection attempt burst',
    category: 'application',
    severity: 'high',
    description: 'One client address produced at least 3 suspicious requests categorised as SQL injection, cross site scripting or path traversal within 10 minutes.',
    threshold: 3,
    windowMinutes: 10,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, src_ip, COUNT(*) AS hits,
                GROUP_CONCAT(DISTINCT json_extract(raw, '$.attributes.category')) AS categories
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL AND event_type = 'web.suspicious_request'
            AND src_ip IS NOT NULL AND occurred_at >= ?
            AND json_extract(raw, '$.attributes.category') IN ('sqli','xss','path_traversal')
          GROUP BY website_site_id, src_ip HAVING COUNT(*) >= 3
          ORDER BY hits DESC LIMIT 20`,
        orgId, WINDOW(10),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', 88, `${row.hits} injection attempts from ${row.src_ip} in 10 minutes (${row.categories}).`, { srcIp: row.src_ip, attempts: row.hits, categories: row.categories }, [
        { label: 'Injection categories', weight: 45, detail: row.categories },
        { label: 'Repeat attempts', weight: 25, detail: `${row.hits} requests in 10 minutes` },
      ], { signature: `w-req-003:${row.site_id}:${row.src_ip}:${BUCKET(10)}`, srcIp: row.src_ip }));
    },
  },
  {
    key: 'w-acc-001',
    name: 'Repeated access denials for one account',
    category: 'application',
    severity: 'high',
    description: 'One account was denied access at least 10 times within 10 minutes while requesting protected resources.',
    threshold: 10,
    windowMinutes: 10,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT website_site_id AS site_id, user_email AS actor, COUNT(*) AS hits
           FROM security_events
          WHERE org_id = ? AND website_site_id IS NOT NULL AND event_type = 'authz.denied'
            AND user_email IS NOT NULL AND occurred_at >= ?
          GROUP BY website_site_id, user_email HAVING COUNT(*) >= 10
          ORDER BY hits DESC LIMIT 20`,
        orgId, WINDOW(10),
      );
      return rows.map((row) => base(sites.get(row.site_id), this, 'high', 82, `${row.hits} authorization denials for one account in 10 minutes.`, { actor: row.actor, denials: row.hits }, [
        { label: 'Denial volume', weight: 40, detail: `${row.hits} denied requests` },
        { label: 'Single identity', weight: 20, detail: row.actor },
      ], { signature: `w-acc-001:${row.site_id}:${row.actor}:${BUCKET(10)}`, actorId: row.actor }));
    },
  },
  {
    key: 'w-intel-001',
    name: 'Request from a known bad address',
    category: 'threat-intelligence',
    severity: 'critical',
    description: 'A client address that produced website events matches an active indicator in the local threat intelligence store.',
    threshold: 1,
    windowMinutes: 30,
    evaluate(orgId) {
      const sites = siteIndex(orgId);
      const rows = all(
        `SELECT e.website_site_id AS site_id, e.src_ip, MAX(i.confidence) AS confidence, COUNT(*) AS hits
           FROM security_events e
           JOIN iocs i ON i.org_id = e.org_id AND i.type = 'ip' AND i.value = e.src_ip AND i.status = 'active'
          WHERE e.org_id = ? AND e.website_site_id IS NOT NULL
            AND e.src_ip IS NOT NULL AND e.occurred_at >= ?
          GROUP BY e.website_site_id, e.src_ip
          ORDER BY confidence DESC LIMIT 20`,
        orgId, WINDOW(30),
      );
      return rows.map((row) => {
        const severity = Number(row.confidence) >= 50 ? 'critical' : 'high';
        return base(sites.get(row.site_id), this, severity, Math.max(60, Number(row.confidence) || 60), `${row.hits} request(s) from ${row.src_ip}, which matches an active threat intelligence indicator (confidence ${row.confidence}).`, { srcIp: row.src_ip, confidence: row.confidence, requests: row.hits }, [
          { label: 'Indicator match', weight: 45, detail: `local indicator confidence ${row.confidence}` },
          { label: 'Observed traffic', weight: 15, detail: `${row.hits} requests` },
        ], { signature: `w-intel-001:${row.site_id}:${row.src_ip}:${BUCKET(30)}`, srcIp: row.src_ip });
      });
    },
  },
];

export const WEBSITE_RULE_KEYS = WEBSITE_RULES.map((rule) => rule.key);
