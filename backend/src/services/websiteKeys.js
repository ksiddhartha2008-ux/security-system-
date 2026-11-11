import { ApiError } from '../lib/http.js';
import { purgeKeyCache } from '../lib/apiKeys.js';
import { get, run, all, newId, nowIso, transaction } from '../db.js';
import { audit } from '../lib/audit.js';
import { ACTIVE_KEY_LIMIT, activeKeyCount, getSite } from './websiteSites.js';
import { generateApiKey } from '../lib/apiKeys.js';

export function keyStatus(row) {
  if (row.revoked_at) return 'revoked';
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) return 'expired';
  return 'active';
}

export const keyMetadata = (row) => ({
  id: row.id,
  keyId: row.key_id,
  last4: row.last4,
  label: row.label,
  scopes: row.scopes,
  status: keyStatus(row),
  createdAt: row.created_at,
  createdBy: row.created_by,
  expiresAt: row.expires_at,
  lastUsedAt: row.last_used_at,
  revokedAt: row.revoked_at,
  revokeReason: row.revoke_reason,
});

/**
 * Only a verified site with fewer than two active keys can receive a new key.
 * The plaintext secret exists only in this function's stack and the response.
 */
export function createKey(req, siteId, { label, expiresAt } = {}) {
  const orgId = req.user.orgId;
  const site = getSite(orgId, siteId);
  if (site.status !== 'verified') throw new ApiError(403, 'site_not_verified', 'Verify ownership before creating a key.');

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const candidate = generateApiKey();
    let created = null;
    try {
      created = transaction(() => {
        if (activeKeyCount(orgId, siteId) >= ACTIVE_KEY_LIMIT) {
          throw new ApiError(409, 'key_limit_reached', `At most ${ACTIVE_KEY_LIMIT} active keys are allowed. Revoke one first.`);
        }
        const id = newId('key');
        run(
          `INSERT INTO site_api_keys (id, org_id, site_id, key_id, secret_hash, last4, label, scopes, created_by, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'events:write', ?, ?, ?)`,
          id, orgId, siteId, candidate.keyId, candidate.secretHash, candidate.last4,
          (label ?? 'default').trim().slice(0, 60) || 'default', req.user.id, expiresAt ?? null, nowIso(),
        );
        audit(req, 'website.key_created', 'site_api_key', id, { siteId, keyId: candidate.keyId, last4: candidate.last4 });
        return get('SELECT * FROM site_api_keys WHERE id = ?', id);
      });
    } catch (error) {
      if (/UNIQUE constraint failed/.test(error?.message ?? '')) continue;
      throw error;
    }
    return { ...keyMetadata(created), apiKey: candidate.apiKey };
  }
  throw new ApiError(500, 'service_unavailable', 'Could not allocate a unique key. Try again.');
}

export function listKeys(orgId, siteId) {
  getSite(orgId, siteId);
  return all('SELECT * FROM site_api_keys WHERE org_id = ? AND site_id = ? ORDER BY created_at DESC', orgId, siteId).map(keyMetadata);
}

export function revokeKey(req, siteId, keyId, reason = 'revoked_by_admin') {
  const orgId = req.user.orgId;
  getSite(orgId, siteId);
  const row = get('SELECT * FROM site_api_keys WHERE org_id = ? AND site_id = ? AND key_id = ?', orgId, siteId, keyId);
  if (!row) throw new ApiError(404, 'not_found', 'API key not found');
  if (row.revoked_at) return keyMetadata(row);
  run(
    `UPDATE site_api_keys SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE id = ? AND org_id = ?`,
    nowIso(), req.user.id, String(reason).slice(0, 60), row.id, orgId,
  );
  purgeKeyCache(row.key_id);
  audit(req, 'website.key_revoked', 'site_api_key', row.id, { siteId, keyId: row.key_id, reason });
  return keyMetadata(get('SELECT * FROM site_api_keys WHERE id = ?', row.id));
}
