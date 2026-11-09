import { createHash } from 'node:crypto';
import { get, run, all, newId, nowIso, parseJson } from '../db.js';

/** Canonical fields covered by the audit hash. Keep this stable across versions. */
function chainInput(prevHash, record) {
  return [
    prevHash,
    record.orgId,
    record.actorId ?? '',
    record.actorEmail ?? '',
    record.action,
    record.resourceType,
    record.resourceId ?? '',
    record.ip ?? '',
    record.result,
    record.metadata,
    record.createdAt,
  ].join('|');
}

const hashRecord = (prevHash, record) => createHash('sha256').update(chainInput(prevHash, record)).digest('hex');

/**
 * Append-only audit entry with a per-organization hash chain.
 * Failures throw: a critical action must not silently lose its audit record.
 */
export function audit(req, action, resourceType, resourceId, metadata = {}, { result = 'success', orgId } = {}) {
  const resolvedOrg = req.user?.orgId ?? orgId ?? 'system';
  const record = {
    orgId: resolvedOrg,
    actorId: req.user?.id ?? null,
    actorEmail: req.user?.email ?? 'system',
    action,
    resourceType,
    resourceId: resourceId ?? null,
    ip: req.ip ?? null,
    result,
    metadata: JSON.stringify(metadata ?? {}),
    createdAt: nowIso(),
  };
  const previous = get(
    'SELECT hash FROM audit_logs WHERE org_id = ? AND hash != \'\' ORDER BY rowid DESC LIMIT 1',
    resolvedOrg,
  );
  const prevHash = previous?.hash ?? '';
  const hash = hashRecord(prevHash, record);

  run(
    `INSERT INTO audit_logs (id, org_id, actor_id, actor_email, action, resource_type, resource_id, ip, metadata, result, request_id, prev_hash, hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('aud'), record.orgId, record.actorId, record.actorEmail, record.action, record.resourceType,
    record.resourceId, record.ip, record.metadata, record.result, req.requestId ?? null, prevHash, hash, record.createdAt,
  );
  return hash;
}

/**
 * Recompute the chain for one organization. Rows written before schema v3 have
 * no hash and are reported as legacy rather than as tampering.
 */
export function verifyAuditChain(orgId) {
  const rows = all('SELECT * FROM audit_logs WHERE org_id = ? ORDER BY rowid ASC', orgId);
  let previous = '';
  let checked = 0;
  let legacy = 0;
  for (const row of rows) {
    if (!row.hash) {
      legacy += 1;
      continue;
    }
    const record = {
      orgId: row.org_id,
      actorId: row.actor_id,
      actorEmail: row.actor_email,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      ip: row.ip,
      result: row.result ?? 'success',
      metadata: row.metadata,
      createdAt: row.created_at,
    };
    const expected = hashRecord(previous, record);
    if (expected !== row.hash) {
      return {
        ok: false,
        checked,
        legacy,
        total: rows.length,
        brokenAt: row.id,
        brokenAction: row.action,
        reason: 'hash_mismatch',
      };
    }
    previous = row.hash;
    checked += 1;
  }
  return { ok: true, checked, legacy, total: rows.length, brokenAt: null };
}

export { hashRecord as _hashAuditRecord };
