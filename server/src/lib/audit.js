import { run, newId, nowIso } from '../db.js';

/** Append-only audit trail for security sensitive actions. */
export function audit(req, action, resourceType, resourceId, metadata = {}) {
  try {
    run(
      `INSERT INTO audit_logs (id, org_id, actor_id, actor_email, action, resource_type, resource_id, ip, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      newId('aud'),
      req.user?.orgId ?? metadata.orgId ?? 'system',
      req.user?.id ?? null,
      req.user?.email ?? 'system',
      action,
      resourceType,
      resourceId ?? null,
      req.ip ?? null,
      JSON.stringify(metadata),
      nowIso(),
    );
  } catch (err) {
    console.error('[audit] failed to write entry', action, err.message);
  }
}
