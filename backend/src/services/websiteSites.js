import { randomBytes } from 'node:crypto';
import { all, get, run, newId, nowIso, transaction } from '../db.js';
import { ApiError, notFound } from '../lib/http.js';
import { audit } from '../lib/audit.js';
import { purgeKeyCache } from '../lib/apiKeys.js';
import { normalizeWebsiteInput, challengeRecordName, challengeRecordValue, verificationName } from '../lib/websiteNormalize.js';
import { createTxtResolver, evaluateTxtRecords, classifyDnsError } from '../lib/dnsTxt.js';

export const PENDING_LIMIT = 10;
export const VERIFY_PER_SITE_HOUR = 6;
export const VERIFY_PER_ORG_DAY = 30;
export const CHALLENGE_TTL_DAYS = 7;
export const ACTIVE_KEY_LIMIT = 2;

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

export const verificationGraceDays = () => {
  const value = Number(process.env.SF_WEBSITE_VERIFICATION_GRACE_DAYS ?? 14);
  return Number.isFinite(value) && value >= 0 ? value : 14;
};

export const heartbeatSeconds = () => {
  const value = Number(process.env.SF_SDK_HEARTBEAT_SECONDS ?? 900);
  return Number.isFinite(value) && value >= 60 ? value : 900;
};

const CRITICALITY = ['low', 'low', 'low', 'medium', 'high', 'critical'];

export const criticalityLabel = (value) => CRITICALITY[Math.max(1, Math.min(5, Number(value) || 3))];
const criticalityNumber = (label) => ({ low: 1, medium: 3, high: 4, critical: 5 }[label] ?? 3);

export function getSite(orgId, siteId) {
  const site = get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', siteId, orgId);
  if (!site) throw notFound('Website not found');
  return site;
}

export function activeKeyCount(orgId, siteId) {
  return get(
    `SELECT COUNT(*) AS c FROM site_api_keys
      WHERE org_id = ? AND site_id = ? AND revoked_at IS NULL
        AND (expires_at IS NULL OR expires_at > ?)`,
    orgId, siteId, nowIso(),
  ).c;
}

/** Derived, never stored as truth: connection health always follows the evidence. */
export function connectionState(site) {
  if (site.status !== 'verified') {
    return { state: 'suspended', label: 'Suspended', reason: site.status === 'deleted' ? 'website deleted' : 'website is not verified' };
  }
  if (activeKeyCount(site.org_id, site.id) === 0) {
    return { state: 'suspended', label: 'No active key', reason: 'create an API key to allow ingestion' };
  }
  if (!site.connected_at) return { state: 'never_connected', label: 'Waiting for first event', reason: 'no event has been accepted yet' };
  const last = [site.last_event_at, site.last_heartbeat_at].filter(Boolean).sort().at(-1);
  if (!last) return { state: 'never_connected', label: 'Waiting for first event', reason: 'no event has been accepted yet' };
  const silentAfter = heartbeatSeconds() * 3 * 1000;
  if (Date.now() - new Date(last).getTime() > silentAfter) {
    return { state: 'silent', label: 'Silent', reason: `no event or heartbeat for more than ${Math.round(silentAfter / 60000)} minutes` };
  }
  return { state: 'connected', label: 'Connected', reason: null };
}

export function healthWarnings(site) {
  const warnings = [];
  const connection = connectionState(site);
  if (connection.state === 'silent') {
    warnings.push({ code: 'sdk_silent', label: 'The SDK stopped reporting', detail: connection.reason });
  }
  if (site.ip_event_count >= 20 && site.private_ip_count / site.ip_event_count > 0.5) {
    warnings.push({
      code: 'private_addresses',
      label: 'Most client addresses are private',
      detail: 'The SDK reports private client addresses. Check the proxy configuration so req.ip carries the real visitor address.',
    });
  }
  if (site.host_mismatch_count >= 5 && site.host_mismatch_last_at
      && Date.now() - new Date(site.host_mismatch_last_at).getTime() < DAY) {
    warnings.push({
      code: 'host_mismatch',
      label: 'Events rejected for a host mismatch',
      detail: 'The key may be installed on a different website, or the request host is rewritten by a proxy.',
    });
  }
  if (site.status === 'lapsed') {
    warnings.push({ code: 'lapsed', label: 'Ownership verification lapsed', detail: 'Publish the TXT record again, then verify.' });
  }
  if (site.status === 'pending_verification' && site.verification_failing_since) {
    warnings.push({ code: 'verification_failing', label: 'Verification is failing', detail: 'The TXT record was not found on the last checks.' });
  }
  return warnings;
}

export function dnsInstructions(site, verification) {
  if (!verification) return null;
  const fullName = verification.record_name;
  const relative = fullName.replace(`.${verificationName(site)}`, '');
  const remainingMs = new Date(verification.expires_at).getTime() - Date.now();
  return {
    type: 'TXT',
    relativeName: relative,
    fullName,
    value: challengeRecordValue(verification.token),
    ttl: 300,
    expiresAt: verification.expires_at,
    expiresInSeconds: Math.max(0, Math.floor(remainingMs / 1000)),
    sentence: 'Keep this record in place. SecureFlow re-checks it periodically to confirm you still control the domain.',
  };
}

export function siteJson(site, extra = {}) {
  const connection = connectionState(site);
  const asset = site.asset_id ? get('SELECT risk_score, criticality FROM assets WHERE id = ? AND org_id = ?', site.asset_id, site.org_id) : null;
  return {
    id: site.id,
    displayName: site.display_name,
    inputUrl: site.input_url,
    hostname: site.hostname,
    hostnameUnicode: site.hostname_unicode,
    scheme: site.scheme,
    scope: site.scope,
    registrableDomain: site.registrable_domain,
    criticality: site.criticality,
    criticalityLabel: criticalityLabel(site.criticality),
    status: site.status,
    verifiedAt: site.verified_at,
    lastVerificationOkAt: site.last_verification_ok_at,
    verificationFailingSince: site.verification_failing_since,
    lastEventAt: site.last_event_at,
    lastHeartbeatAt: site.last_heartbeat_at,
    connectedAt: site.connected_at,
    assetId: site.asset_id,
    riskScore: asset?.risk_score ?? null,
    connection,
    healthWarnings: healthWarnings(site),
    createdAt: site.created_at,
    deletedAt: site.deleted_at,
    ...extra,
  };
}

function pendingVerification(orgId, siteId) {
  return get(
    `SELECT * FROM domain_verifications WHERE org_id = ? AND site_id = ? AND status = 'pending'
      ORDER BY created_at DESC LIMIT 1`,
    orgId, siteId,
  );
}

function latestVerification(orgId, siteId) {
  return get(
    `SELECT * FROM domain_verifications WHERE org_id = ? AND site_id = ?
      ORDER BY created_at DESC LIMIT 1`,
    orgId, siteId,
  );
}

export function createChallenge(site) {
  run(`UPDATE domain_verifications SET status = 'superseded' WHERE org_id = ? AND site_id = ? AND status = 'pending'`, site.org_id, site.id);
  const token = randomBytes(32).toString('base64url');
  const id = newId('dver');
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_DAYS * DAY).toISOString();
  run(
    `INSERT INTO domain_verifications (id, org_id, site_id, method, record_name, token, status, expires_at, attempt_count, created_at)
     VALUES (?, ?, ?, 'dns_txt', ?, ?, 'pending', ?, 0, ?)`,
    id, site.org_id, site.id, challengeRecordName(site), token, expiresAt, nowIso(),
  );
  return get('SELECT * FROM domain_verifications WHERE id = ?', id);
}

export function countPendingSites(orgId) {
  return get(`SELECT COUNT(*) AS c FROM website_sites WHERE org_id = ? AND status = 'pending_verification'`, orgId).c;
}

function assertHostnameFree(orgId, hostname) {
  const existing = get(
    `SELECT id, status FROM website_sites WHERE org_id = ? AND hostname = ? AND status != 'deleted' ORDER BY created_at LIMIT 1`,
    orgId, hostname,
  );
  return existing ?? null;
}

/** Create a website and its first challenge in one transaction with one audit entry. */
export function createSite(req, body) {
  const orgId = req.user.orgId;
  const normalized = normalizeWebsiteInput(body.url, { env: process.env });
  if (!normalized.ok) throw new ApiError(400, normalized.code, normalized.message);
  const value = normalized.value;
  const scope = body.scope ?? 'host';
  if (!['host', 'domain'].includes(scope)) throw new ApiError(400, 'invalid_scope', 'Choose host or domain scope.');

  const existing = assertHostnameFree(orgId, value.hostname);
  if (existing && existing.status === 'pending_verification') {
    const site = get('SELECT * FROM website_sites WHERE id = ?', existing.id);
    const verification = pendingVerification(orgId, site.id) ?? createChallenge(site);
    return { site, verification, reused: true };
  }
  if (existing) throw new ApiError(409, 'site_conflict', 'This website is already registered in your workspace.');

  const crossOrg = get(`SELECT id FROM website_sites WHERE hostname = ? AND status = 'verified' LIMIT 1`, value.hostname);
  if (crossOrg) throw new ApiError(409, 'site_conflict', 'That hostname is already verified by another workspace.');

  if (countPendingSites(orgId) >= PENDING_LIMIT) {
    throw new ApiError(429, 'too_many_pending_sites', `At most ${PENDING_LIMIT} websites can wait for verification at once.`);
  }

  const id = newId('site');
  const ts = nowIso();
  const displayName = (body.display_name ?? value.hostname).trim().slice(0, 100) || value.hostname;
  const criticality = Math.max(1, Math.min(5, Number(body.criticality ?? 3)));

  const created = transaction(() => {
    run(
      `INSERT INTO website_sites (id, org_id, display_name, input_url, hostname, hostname_unicode, scheme, scope,
        registrable_domain, criticality, status, status_changed_at, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_verification', ?, ?, ?, ?)`,
      id, orgId, displayName, body.url.trim().slice(0, 2048), value.hostname, value.hostname_unicode,
      value.scheme, scope, value.registrable_domain, criticality, ts, req.user.id, ts, ts,
    );
    const site = get('SELECT * FROM website_sites WHERE id = ?', id);
    const verification = createChallenge(site);
    audit(req, 'website.created', 'website_site', id, {
      hostname: value.hostname, scope, criticality, verificationId: verification.id,
    });
    return { site, verification };
  });

  return { ...created, reused: false };
}

export function listSites(orgId, { status, q } = {}) {
  const where = ['org_id = ?', `status != 'deleted'`];
  const params = [orgId];
  if (status) { where.push('status = ?'); params.push(status); }
  if (q) {
    where.push('(display_name LIKE ? OR hostname LIKE ?)');
    const like = `%${String(q).slice(0, 80)}%`;
    params.push(like, like);
  }
  const rows = all(`SELECT * FROM website_sites WHERE ${where.join(' AND ')} ORDER BY created_at DESC`, ...params);
  return rows.map((site) => {
    const open = site.asset_id
      ? get(
        `SELECT COUNT(DISTINCT ie.incident_id) AS c FROM incident_entities ie
           JOIN incidents i ON i.id = ie.incident_id
          WHERE ie.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?
            AND i.status IN ('open','investigating')`,
        orgId, site.asset_id,
      ).c
      : 0;
    return siteJson(site, { openIncidents: open });
  });
}

export function siteDetail(orgId, siteId) {
  const site = getSite(orgId, siteId);
  const verification = pendingVerification(orgId, siteId) ?? latestVerification(orgId, siteId);
  const openIncidents = site.asset_id
    ? get(
      `SELECT COUNT(DISTINCT ie.incident_id) AS c FROM incident_entities ie
         JOIN incidents i ON i.id = ie.incident_id
        WHERE ie.org_id = ? AND ie.entity_type = 'site' AND ie.entity_value = ?
          AND i.status IN ('open','investigating')`,
      orgId, site.asset_id,
    ).c
    : 0;
  return siteJson(site, {
    openIncidents,
    keysActive: activeKeyCount(orgId, siteId),
    verification: verification ? {
      id: verification.id,
      status: verification.status,
      method: verification.method,
      recordName: verification.record_name,
      lastResult: verification.last_result,
      lastCheckedAt: verification.last_checked_at,
      attemptCount: verification.attempt_count,
      verifiedAt: verification.verified_at,
      expiresAt: verification.expires_at,
    } : null,
    dns: verification?.status === 'pending' ? dnsInstructions(site, verification) : null,
    sensitivePaths: (() => { try { return JSON.parse(site.sensitive_paths || '[]'); } catch { return []; } })(),
  });
}

export function manualAttemptBudget(orgId, siteId) {
  const hourAgo = new Date(Date.now() - HOUR).toISOString();
  const dayAgo = new Date(Date.now() - DAY).toISOString();
  const siteCount = get(
    `SELECT COUNT(*) AS c FROM website_verification_attempts WHERE site_id = ? AND source = 'manual' AND created_at >= ?`,
    siteId, hourAgo,
  ).c;
  const orgCount = get(
    `SELECT COUNT(*) AS c FROM website_verification_attempts WHERE org_id = ? AND source = 'manual' AND created_at >= ?`,
    orgId, dayAgo,
  ).c;
  return { siteCount, orgCount, siteRemaining: Math.max(0, VERIFY_PER_SITE_HOUR - siteCount), orgRemaining: Math.max(0, VERIFY_PER_ORG_DAY - orgCount) };
}

const nextCheckFor = (verification) => {
  const created = new Date(verification.created_at).getTime();
  const elapsed = Date.now() - created;
  const minutes = elapsed < 2 * HOUR ? 5 : 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
};

class ConflictDetected extends Error {}

function findOverlap(site) {
  if (site.scope === 'domain') {
    return get(
      `SELECT id FROM website_sites
        WHERE status = 'verified' AND org_id IS NOT NULL AND id != ?
          AND (hostname = ? OR hostname LIKE ?)
        LIMIT 1`,
      site.id, site.registrable_domain, `%.${site.registrable_domain}`,
    ) ?? null;
  }
  return get(
    `SELECT id FROM website_sites
      WHERE status = 'verified' AND id != ?
        AND (hostname = ? OR (scope = 'domain' AND registrable_domain = ?))
      LIMIT 1`,
    site.id, site.hostname, site.registrable_domain,
  ) ?? null;
}

function ensureAsset(site) {
  if (site.asset_id) return site.asset_id;
  const assetId = newId('ast');
  const ts = nowIso();
  run(
    `INSERT INTO assets (id, org_id, name, hostname, asset_type, criticality, risk_score, status, tags, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'website', ?, 0, 'online', ?, ?, ?, ?)`,
    assetId, site.org_id, site.display_name, site.hostname, criticalityLabel(site.criticality),
    JSON.stringify(['website', 'secureflow-sdk']), ts, ts, ts,
  );
  run('UPDATE website_sites SET asset_id = ?, updated_at = ? WHERE id = ? AND org_id = ?', assetId, ts, site.id, site.org_id);
  return assetId;
}

function markVerificationConflict(req, site, verification) {
  const result = transaction(() => {
    run(`UPDATE domain_verifications SET status = 'conflict', last_checked_at = ?, last_result = 'ok' WHERE id = ? AND org_id = ?`,
      nowIso(), verification.id, site.org_id);
    if (site.status === 'pending_verification') {
      run(`UPDATE website_sites SET status = 'expired', status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
        nowIso(), nowIso(), site.id, site.org_id);
    }
    audit(req, 'website.verification_conflict', 'website_site', site.id, { verificationId: verification.id });
    return true;
  });
  return result;
}

export function completeVerification(req, siteId, verification, resolver) {
  const orgId = req.user.orgId;
  let outcome;
  try {
    outcome = transaction(() => {
      const site = get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', siteId, orgId);
      if (!site) throw notFound('Website not found');
      const fresh = get(`SELECT * FROM domain_verifications WHERE id = ? AND status = 'pending'`, verification.id);
      if (!fresh) throw new ApiError(409, 'verification_superseded', 'This challenge was replaced. Start verification again.');
      if (new Date(fresh.expires_at).getTime() < Date.now()) {
        run(`UPDATE domain_verifications SET status = 'expired' WHERE id = ?`, fresh.id);
        run(`UPDATE website_sites SET status = 'expired', status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
          nowIso(), nowIso(), site.id, orgId);
        audit(req, 'website.verification_expired', 'website_site', site.id, { verificationId: fresh.id });
        return { expired: true };
      }
      if (findOverlap(site)) {
        throw new ConflictDetected('overlap');
      }
      const ts = nowIso();
      run(
        `UPDATE domain_verifications SET status = 'verified', verified_at = ?, last_checked_at = ?, last_result = 'ok', attempt_count = attempt_count + 1
          WHERE id = ?`,
        ts, ts, fresh.id,
      );
      run(
        `UPDATE website_sites SET status = 'verified', status_changed_at = ?, verified_at = ?, last_verification_ok_at = ?,
            verification_failing_since = NULL, updated_at = ? WHERE id = ? AND org_id = ?`,
        ts, ts, ts, ts, site.id, orgId,
      );
      const refreshed = get('SELECT * FROM website_sites WHERE id = ?', site.id);
      const assetId = ensureAsset(refreshed);
      run(`UPDATE assets SET criticality = ?, name = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
        criticalityLabel(refreshed.criticality), refreshed.display_name, ts, assetId, orgId);
      audit(req, site.status === 'lapsed' ? 'website.restored' : 'website.verified', 'website_site', site.id, { verificationId: fresh.id, hostname: site.hostname, scope: site.scope });
      return { verified: true, assetId };
    });
  } catch (error) {
    if (error instanceof ConflictDetected || /UNIQUE constraint failed/.test(error?.message ?? '')) {
      markVerificationConflict(req, get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', siteId, orgId), verification);
      return { status: 'conflict', result: 'ok', nextCheckAt: null };
    }
    throw error;
  }

  if (outcome.expired) return { status: 'expired', result: 'not_found', nextCheckAt: null };
  return { status: 'verified', result: 'ok', nextCheckAt: null };
}

export async function checkVerification(req, { siteId, source = 'manual', resolver = createTxtResolver() }) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);

  if (source === 'manual') {
    const budget = manualAttemptBudget(orgId, siteId);
    if (budget.siteCount >= VERIFY_PER_SITE_HOUR || budget.orgCount >= VERIFY_PER_ORG_DAY) {
      throw new ApiError(429, 'verification_rate_limited', 'Too many verification checks. Wait before trying again.');
    }
  }

  let verification = pendingVerification(orgId, siteId);
  if (!verification) {
    if (site.status === 'lapsed' || site.status === 'expired') {
      const previous = latestVerification(orgId, siteId);
      if (previous) {
        // Reuse the published token instead of issuing a new one: the owner may
        // still have the original record in place.
        run(
          `UPDATE domain_verifications SET status = 'pending', expires_at = ?, last_checked_at = NULL,
             last_result = NULL, attempt_count = 0 WHERE id = ?`,
          new Date(Date.now() + CHALLENGE_TTL_DAYS * DAY).toISOString(), previous.id,
        );
        verification = get('SELECT * FROM domain_verifications WHERE id = ?', previous.id);
      }
    }
    if (!verification) throw new ApiError(404, 'verification_not_found', 'This website has no pending challenge.');
  }

  if (new Date(verification.expires_at).getTime() < Date.now()) {
    transaction(() => {
      run(`UPDATE domain_verifications SET status = 'expired' WHERE id = ?`, verification.id);
      if (site.status === 'pending_verification') {
        run(`UPDATE website_sites SET status = 'expired', status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
          nowIso(), nowIso(), site.id, orgId);
      }
      if (source === 'manual') {
        audit(req, 'website.verification_expired', 'website_site', site.id, { verificationId: verification.id });
      }
    });
    return { status: 'expired', result: 'not_found', nextCheckAt: null };
  }

  run(
    `INSERT INTO website_verification_attempts (id, org_id, site_id, source, created_at) VALUES (?, ?, ?, ?, ?)`,
    newId('wva'), orgId, site.id, source, nowIso(),
  );
  if (source === 'manual') {
    audit(req, 'website.verification_requested', 'website_site', site.id, { verificationId: verification.id });
  }

  let result;
  try {
    const records = await resolver.resolveTxt(verification.record_name);
    result = evaluateTxtRecords(records, challengeRecordValue(verification.token));
  } catch (error) {
    result = classifyDnsError(error);
  }

  run(
    `UPDATE domain_verifications SET attempt_count = attempt_count + 1, last_checked_at = ?, last_result = ? WHERE id = ?`,
    nowIso(), result, verification.id,
  );

  if (result === 'ok') {
    return completeVerification(req, site.id, verification, resolver);
  }

  if (site.status === 'verified' && (result === 'not_found' || result === 'mismatch')) {
    run(`UPDATE website_sites SET verification_failing_since = COALESCE(verification_failing_since, ?), updated_at = ? WHERE id = ? AND org_id = ?`,
      nowIso(), nowIso(), site.id, orgId);
  }
  if (source === 'manual') {
    audit(req, 'website.verification_failed', 'website_site', site.id, { verificationId: verification.id, result });
  }
  return {
    status: result === 'resolver_error' ? 'pending_verification' : site.status,
    result,
    nextCheckAt: site.status === 'pending_verification' ? nextCheckFor(verification) : null,
  };
}

export function restartVerification(req, siteId) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);
  if (site.status === 'deleted') throw notFound('Website not found');
  const result = transaction(() => {
    const verification = createChallenge(site);
    if (site.status !== 'verified') {
      run(`UPDATE website_sites SET status = 'pending_verification', status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
        nowIso(), nowIso(), site.id, orgId);
    }
    audit(req, 'website.verification_requested', 'website_site', site.id, { verificationId: verification.id, restart: true });
    return verification;
  });
  return result;
}

export function updateSite(req, siteId, body) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);
  const fields = [];
  const params = [];
  if (body.display_name !== undefined) { fields.push('display_name = ?'); params.push(body.display_name.trim().slice(0, 100)); }
  if (body.criticality !== undefined) { fields.push('criticality = ?'); params.push(Math.max(1, Math.min(5, Number(body.criticality)))); }
  if (body.sensitive_paths !== undefined) {
    const cleaned = [...new Set(body.sensitive_paths.map((value) => String(value).trim()).filter((value) => value.startsWith('/') && value.length <= 128))].slice(0, 40);
    fields.push('sensitive_paths = ?');
    params.push(JSON.stringify(cleaned));
  }
  if (!fields.length) throw new ApiError(400, 'bad_request', 'Nothing to update.');
  fields.push('updated_at = ?');
  params.push(nowIso());
  run(`UPDATE website_sites SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, site.id, orgId);
  if (body.criticality !== undefined && site.asset_id) {
    run('UPDATE assets SET criticality = ?, updated_at = ? WHERE id = ? AND org_id = ?',
      criticalityLabel(body.criticality), nowIso(), site.asset_id, orgId);
  }
  if (body.display_name !== undefined && site.asset_id) {
    run('UPDATE assets SET name = ?, updated_at = ? WHERE id = ? AND org_id = ?', body.display_name.trim().slice(0, 100), nowIso(), site.asset_id, orgId);
  }
  audit(req, 'website.settings_changed', 'website_site', site.id, { fields: Object.keys(body) });
  return getSite(orgId, siteId);
}

export function softDeleteSite(req, siteId) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);
  const ts = nowIso();
  transaction(() => {
    const keys = all('SELECT key_id FROM site_api_keys WHERE org_id = ? AND site_id = ? AND revoked_at IS NULL', orgId, site.id);
    for (const key of keys) purgeKeyCache(key.key_id);
    run(
      `UPDATE site_api_keys SET revoked_at = ?, revoked_by = ?, revoke_reason = 'site_deleted'
        WHERE org_id = ? AND site_id = ? AND revoked_at IS NULL`,
      ts, req.user.id, orgId, site.id,
    );
    run(`UPDATE website_sites SET status = 'deleted', deleted_at = ?, status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
      ts, ts, ts, site.id, orgId);
    if (site.asset_id) {
      run(`UPDATE assets SET status = 'decommissioned', updated_at = ? WHERE id = ? AND org_id = ?`, ts, site.asset_id, orgId);
    }
    run(`UPDATE website_sites SET verification_failing_since = NULL WHERE id = ?`, site.id);
    run(`UPDATE domain_verifications SET status = 'superseded' WHERE org_id = ? AND site_id = ? AND status = 'pending'`, orgId, site.id);
    audit(req, 'website.deleted', 'website_site', site.id, { hostname: site.hostname, revokedKeys: keys.length });
  });
  return { id: site.id, deleted: true, revokedKeys: true };
}

/** Fail a site whose ownership proof has been failing for the grace period. */
export function lapseSite(req, site, { actorId = null } = {}) {
  const ts = nowIso();
  transaction(() => {
    run(`UPDATE website_sites SET status = 'lapsed', status_changed_at = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
      ts, ts, site.id, site.org_id);
    const latest = latestVerification(site.org_id, site.id);
    if (latest) {
      run(
        `UPDATE domain_verifications SET status = 'pending', expires_at = ?, last_checked_at = NULL,
           last_result = NULL, attempt_count = 0 WHERE id = ?`,
        new Date(Date.now() + CHALLENGE_TTL_DAYS * DAY).toISOString(), latest.id,
      );
    }
    audit(req, 'website.lapsed', 'website_site', site.id, { hostname: site.hostname, failingSince: site.verification_failing_since }, { orgId: site.org_id });
    run(
      `INSERT OR IGNORE INTO notifications (id, org_id, incident_id, site_id, kind, priority, channel, status, title, body, dedupe_key, created_at)
       VALUES (?, ?, NULL, ?, 'integration_health', 'P2', 'in_app', 'sent', ?, ?, ?, ?)`,
      newId('ntf'), site.org_id, site.id,
      `Ownership verification lapsed for ${site.display_name}`,
      `The TXT record for ${site.hostname} has been failing since ${site.verification_failing_since ?? 'an earlier check'}. API keys are suspended until the record is published again and verification succeeds.`,
      `lapse:${site.id}:${ts.slice(0, 10)}`, ts,
    );
  });
  return true;
}

export function restoreSite(req, siteId) {
  return checkVerification(req, { siteId, source: 'manual' });
}

/** Verify overlap helpers directly for tests and diagnostics. */
export const _internal = { findOverlap, criticalityNumber };
