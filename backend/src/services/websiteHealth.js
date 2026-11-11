import { all, run, newId, nowIso } from '../db.js';
import { connectionState } from './websiteSites.js';

/**
 * Integration health is derived from stored evidence and written as a
 * notification at most once per site per signal per day. A quiet website is not
 * a disconnected website: silence is measured from heartbeat and event
 * timestamps, never from business event volume alone.
 */
export function refreshIntegrationHealth(orgId) {
  const day = new Date().toISOString().slice(0, 10);
  const sites = all(
    `SELECT * FROM website_sites WHERE org_id = ? AND status IN ('verified','lapsed')`,
    orgId,
  );
  const created = [];
  for (const site of sites) {
    const connection = connectionState(site);
    const signals = [];
    if (connection.state === 'silent') {
      signals.push({
        code: 'sdk_silent',
        title: `No recent heartbeat from ${site.display_name}`,
        body: `The SDK last reported at ${site.last_heartbeat_at ?? site.last_event_at ?? 'an unknown time'}. Check that the process is running and that outbound HTTPS to the ingestion endpoint is allowed.`,
      });
    }
    if (site.ip_event_count >= 20 && site.private_ip_count / site.ip_event_count > 0.5) {
      signals.push({
        code: 'private_addresses',
        title: `Private client addresses reported by ${site.display_name}`,
        body: 'More than half of the reported client addresses are private. The SDK is probably reading the address of a proxy. IP based detection is reduced until this is fixed.',
      });
    }
    if (site.host_mismatch_count >= 5 && site.host_mismatch_last_at
        && Date.now() - new Date(site.host_mismatch_last_at).getTime() < 24 * 3600_000) {
      signals.push({
        code: 'host_mismatch',
        title: `Events rejected for a host mismatch on ${site.display_name}`,
        body: 'Five or more events were rejected because request.host did not match the verified website. The key may be installed on another site.',
      });
    }

    for (const signal of signals) {
      const dedupe = `health:${signal.code}:${site.id}:${day}`;
      const result = run(
        `INSERT OR IGNORE INTO notifications (id, org_id, incident_id, site_id, kind, priority, channel, status, title, body, dedupe_key, created_at)
         VALUES (?, ?, NULL, ?, 'integration_health', 'P3', 'in_app', 'sent', ?, ?, ?, ?)`,
        newId('ntf'), orgId, site.id, signal.title, signal.body, dedupe, nowIso(),
      );
      if (result.changes) created.push({ siteId: site.id, code: signal.code });
    }
  }
  return created;
}
