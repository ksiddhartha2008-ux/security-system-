import { isIP } from 'node:net';
import { ApiError } from '../lib/http.js';
import { get, run, newId, nowIso, transaction } from '../db.js';
import { touchKey } from '../lib/apiKeys.js';

export const EVENT_TYPES = {
  'auth.login_failed': { type: 'auth.failure', category: 'identity', outcome: 'failure', label: 'Failed sign-in' },
  'auth.login_succeeded': { type: 'auth.success', category: 'identity', outcome: 'success', label: 'Successful sign-in' },
  'auth.password_reset_requested': { type: 'auth.password_reset', category: 'identity', outcome: 'unknown', label: 'Password reset requested' },
  'auth.mfa_failed': { type: 'auth.mfa_failure', category: 'identity', outcome: 'failure', label: 'Failed multi-factor challenge' },
  'auth.signup': { type: 'auth.signup', category: 'identity', outcome: 'success', label: 'Account created' },
  'access.denied': { type: 'authz.denied', category: 'application', outcome: 'failure', label: 'Access denied' },
  'request.suspicious': { type: 'web.suspicious_request', category: 'application', outcome: 'unknown', label: 'Suspicious request' },
  'request.rate_limited': { type: 'api.rate_limit', category: 'application', outcome: 'unknown', label: 'Request rate limited' },
  'app.error': { type: 'app.error', category: 'application', outcome: 'failure', label: 'Application error' },
  'sdk.connectivity_test': { type: 'sdk.connectivity_test', category: 'application', outcome: 'success', label: 'SDK connectivity test' },
  'sdk.heartbeat': { type: 'sdk.heartbeat', category: 'application', outcome: 'unknown', label: 'SDK heartbeat' },
};

const REQUIRED = {
  'auth.login_failed': ['client.ip'],
  'auth.login_succeeded': ['client.ip', 'actor.id'],
  'auth.password_reset_requested': ['client.ip'],
  'auth.mfa_failed': ['client.ip', 'actor.id'],
  'auth.signup': ['client.ip'],
  'access.denied': ['client.ip', 'request.path'],
  'request.suspicious': ['client.ip', 'request.path', 'attributes.category'],
  'request.rate_limited': ['client.ip'],
  'app.error': ['request.path', 'attributes.error_class'],
  'sdk.connectivity_test': [],
  'sdk.heartbeat': [],
};

const CATEGORIES = new Set(['sqli', 'xss', 'path_traversal', 'scanner', 'bad_bot', 'other']);
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const MODES = new Set(['hash', 'raw', 'omit']);
const SENSITIVE = new Set([
  'password', 'passwd', 'secret', 'token', 'authorization', 'cookie', 'set-cookie',
  'api_key', 'apikey', 'session', 'card', 'cvv', 'ssn',
]);
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const CONTROL = /[\u0000-\u001f\u007f]/g;
const CONTROL_TEST = /[\u0000-\u001f\u007f]/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const strip = (value, max) => String(value).replace(CONTROL, '').slice(0, max);

export function hasForbiddenKey(value, depth = 0) {
  if (depth > 6) return true;
  if (Array.isArray(value)) return value.some((item) => hasForbiddenKey(item, depth + 1));
  if (!isObject(value)) return false;
  for (const [key, inner] of Object.entries(value)) {
    if (FORBIDDEN.has(key)) return true;
    if (hasForbiddenKey(inner, depth + 1)) return true;
  }
  return false;
}

export function isPrivateAddress(ip) {
  if (!ip) return false;
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (isIP(ip) === 6) {
    const value = ip.toLowerCase();
    if (value === '::1' || value === '::') return true;
    if (value.startsWith('fc') || value.startsWith('fd')) return true;
    if (value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb')) return true;
    if (value.startsWith('::ffff:')) return isPrivateAddress(value.slice(7));
    return false;
  }
  return false;
}

export function parseEnvelope(buffer, contentType) {
  if (!/^application\/json(\s*;.*)?$/i.test(contentType ?? '')) {
    throw new ApiError(415, 'unsupported_media_type', 'Send the batch as application/json.');
  }
  let body;
  try {
    body = JSON.parse(buffer.toString('utf8'));
  } catch {
    throw new ApiError(400, 'invalid_batch', 'The request body is not valid JSON.');
  }
  if (!isObject(body)) throw new ApiError(400, 'invalid_batch', 'The envelope must be a JSON object.');
  if (hasForbiddenKey(body)) throw new ApiError(400, 'invalid_batch', 'The envelope contains a forbidden key.');
  const allowed = new Set(['schema_version', 'sdk', 'sent_at', 'events']);
  if (Object.keys(body).some((key) => !allowed.has(key))) {
    throw new ApiError(400, 'invalid_batch', 'The envelope contains an unknown field.');
  }
  if (body.schema_version !== 1) throw new ApiError(400, 'invalid_batch', 'Unsupported schema_version.');
  if (!Array.isArray(body.events) || body.events.length === 0) {
    throw new ApiError(400, 'invalid_batch', 'events must be a non-empty array.');
  }
  if (body.events.length > 100) throw new ApiError(400, 'invalid_batch', 'At most 100 events per batch.');
  if (body.sdk !== undefined && (!isObject(body.sdk) || typeof body.sdk.name !== 'string')) {
    throw new ApiError(400, 'invalid_batch', 'sdk.name is required when sdk is present.');
  }
  if (body.sent_at !== undefined && (typeof body.sent_at !== 'string' || !RFC3339.test(body.sent_at))) {
    throw new ApiError(400, 'invalid_batch', 'sent_at must be an RFC 3339 UTC timestamp.');
  }
  return body;
}

function hostMatches(site, host) {
  const value = String(host).toLowerCase().replace(/\.$/, '');
  if (site.scope === 'host') return value === site.hostname;
  return value === site.registrable_domain || value.endsWith(`.${site.registrable_domain}`);
}

function validateEvent(raw, site) {
  let droppedFields = 0;
  if (!isObject(raw)) return { code: 'invalid_event' };
  const allowed = new Set(['event_id', 'type', 'occurred_at', 'actor', 'client', 'request', 'attributes']);
  if (Object.keys(raw).some((key) => !allowed.has(key))) return { code: 'unknown_field' };
  if (hasForbiddenKey(raw)) return { code: 'forbidden_key' };

  if (typeof raw.event_id !== 'string' || !(UUID_V4.test(raw.event_id) || ULID.test(raw.event_id))) {
    return { code: 'invalid_event_id' };
  }
  if (typeof raw.type !== 'string' || !EVENT_TYPES[raw.type]) return { code: 'unknown_event_type' };
  if (typeof raw.occurred_at !== 'string' || !RFC3339.test(raw.occurred_at)) return { code: 'invalid_timestamp' };
  const occurred = new Date(raw.occurred_at).getTime();
  if (!Number.isFinite(occurred)) return { code: 'invalid_timestamp' };
  const now = Date.now();
  if (occurred < now - 7 * 24 * 3600_000 || occurred > now + 5 * 60_000) {
    return { code: 'timestamp_out_of_range' };
  }

  const event = { event_id: raw.event_id, type: raw.type, occurred_at: raw.occurred_at };

  if (raw.actor !== undefined) {
    if (!isObject(raw.actor)) return { code: 'invalid_actor' };
    if (Object.keys(raw.actor).some((key) => !['id', 'id_mode'].includes(key))) return { code: 'unknown_field' };
    const mode = raw.actor.id_mode ?? 'raw';
    if (!MODES.has(mode)) return { code: 'invalid_actor_mode' };
    if (raw.actor.id !== undefined) {
      if (typeof raw.actor.id !== 'string' || raw.actor.id.length > 128 || CONTROL_TEST.test(raw.actor.id)) {
        return { code: 'invalid_actor' };
      }
      if (mode !== 'omit') event.actor = { id: raw.actor.id, id_mode: mode };
    }
  }

  if (raw.client !== undefined) {
    if (!isObject(raw.client)) return { code: 'invalid_client' };
    if (Object.keys(raw.client).some((key) => !['ip', 'user_agent'].includes(key))) return { code: 'unknown_field' };
    if (raw.client.ip !== undefined) {
      if (typeof raw.client.ip !== 'string' || isIP(raw.client.ip) === 0) {
        droppedFields += 1;
      } else {
        event.client = { ip: raw.client.ip };
      }
    }
    if (raw.client.user_agent !== undefined) {
      if (typeof raw.client.user_agent !== 'string') {
        droppedFields += 1;
      } else {
        event.client = { ...(event.client ?? {}), user_agent: strip(raw.client.user_agent, 256) };
      }
    }
  }

  if (raw.request !== undefined) {
    if (!isObject(raw.request)) return { code: 'invalid_request' };
    if (Object.keys(raw.request).some((key) => !['host', 'method', 'path', 'status'].includes(key))) return { code: 'unknown_field' };
    const request = {};
    if (raw.request.host !== undefined) {
      if (typeof raw.request.host !== 'string' || raw.request.host.length > 253) return { code: 'invalid_request' };
      if (!hostMatches(site, raw.request.host)) return { code: 'host_mismatch' };
      request.host = raw.request.host.toLowerCase();
    }
    if (raw.request.method !== undefined) {
      if (!METHODS.has(raw.request.method)) return { code: 'invalid_method' };
      request.method = raw.request.method;
    }
    if (raw.request.path !== undefined) {
      if (typeof raw.request.path !== 'string' || !raw.request.path.startsWith('/')) return { code: 'invalid_path' };
      const path = strip(raw.request.path.split('?')[0].split('#')[0], 512);
      if (!path.startsWith('/')) return { code: 'invalid_path' };
      request.path = path;
    }
    if (raw.request.status !== undefined) {
      if (!Number.isInteger(raw.request.status) || raw.request.status < 100 || raw.request.status > 599) {
        return { code: 'invalid_status' };
      }
      request.status = raw.request.status;
    }
    if (raw.type === 'access.denied' && request.status !== undefined && ![401, 403].includes(request.status)) {
      return { code: 'invalid_status' };
    }
    if (Object.keys(request).length) event.request = request;
  }

  if (raw.attributes !== undefined) {
    if (!isObject(raw.attributes)) return { code: 'invalid_attributes' };
    const keys = Object.keys(raw.attributes);
    if (keys.length > 20) return { code: 'too_many_attributes' };
    const attributes = {};
    for (const key of keys) {
      if (!/^[a-z][a-z0-9_.]{0,63}$/.test(key)) return { code: 'invalid_attribute_key' };
      if (SENSITIVE.has(key)) { droppedFields += 1; continue; }
      const value = raw.attributes[key];
      if (typeof value === 'string') {
        if (value.length > 512) { droppedFields += 1; continue; }
        attributes[key] = strip(value, 512);
      } else if (typeof value === 'number') {
        if (!Number.isFinite(value)) { droppedFields += 1; continue; }
        attributes[key] = value;
      } else if (typeof value === 'boolean') {
        attributes[key] = value;
      } else {
        droppedFields += 1;
      }
    }
    if (Object.keys(attributes).length) event.attributes = attributes;
  }

  for (const field of REQUIRED[raw.type]) {
    const [group, key] = field.split('.');
    const value = key ? event[group]?.[key] : event[group];
    if (value === undefined || value === '') return { code: 'missing_field' };
  }
  if (raw.type === 'request.suspicious' && !CATEGORIES.has(event.attributes?.category)) {
    return { code: 'invalid_category' };
  }
  if (raw.type === 'app.error') {
    const stackLike = Object.keys(raw.attributes ?? {}).filter((key) => /stack|message|trace/i.test(key));
    if (stackLike.length) return { code: 'invalid_attributes' };
  }

  return { event, droppedFields };
}

function quotaExceeded(siteId, keyId) {
  const minute = Math.floor(Date.now() / 60000);
  const day = new Date().toISOString().slice(0, 10);
  const keyBucket = `k:${keyId}:${minute}`;
  const dayBucket = `s:d:${day}`;
  const keyCount = get('SELECT count FROM website_usage WHERE site_id = ? AND bucket = ?', siteId, keyBucket)?.count ?? 0;
  const siteCount = get('SELECT count FROM website_usage WHERE site_id = ? AND bucket = ?', siteId, dayBucket)?.count ?? 0;
  if (keyCount >= 600) {
    return { bucket: 'key', retryAfter: 60 - (Math.floor(Date.now() / 1000) % 60) };
  }
  if (siteCount >= 100_000) {
    return { bucket: 'site', retryAfter: 3600 };
  }
  return null;
}

function bumpUsage(siteId, keyId, amount) {
  const minute = Math.floor(Date.now() / 60000);
  const day = new Date().toISOString().slice(0, 10);
  for (const bucket of [`k:${keyId}:${minute}`, `s:d:${day}`]) {
    run(
      `INSERT INTO website_usage (site_id, bucket, count, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(site_id, bucket) DO UPDATE SET count = count + excluded.count, updated_at = excluded.updated_at`,
      siteId, bucket, amount, nowIso(),
    );
  }
}

/**
 * Validate every event, then persist accepted events, the idempotency keys and
 * the site counters in one transaction. Nothing is written for a rejected event.
 */
export function ingestBatch({ site, key, envelope }) {
  const orgId = site.org_id;
  const quota = quotaExceeded(site.id, key.key_id);
  if (quota) {
    const error = new ApiError(429, 'rate_limited', 'The ingestion rate limit for this key or site was reached.');
    error.retryAfter = quota.retryAfter;
    throw error;
  }

  const rejected = [];
  const valid = [];
  let droppedFields = 0;
  envelope.events.forEach((raw, index) => {
    const result = validateEvent(raw, site);
    if (result.code) {
      rejected.push({ index, event_id: typeof raw?.event_id === 'string' ? raw.event_id.slice(0, 64) : null, code: result.code });
      return;
    }
    droppedFields += result.droppedFields;
    valid.push({ event: result.event, raw });
  });

  const hostMismatches = rejected.filter((item) => item.code === 'host_mismatch').length;
  if (hostMismatches) {
    run(
      `UPDATE website_sites SET host_mismatch_count = host_mismatch_count + ?, host_mismatch_last_at = ?, updated_at = ?
        WHERE id = ? AND org_id = ?`,
      hostMismatches, nowIso(), nowIso(), site.id, orgId,
    );
  }

  if (!valid.length) {
    bumpUsage(site.id, key.key_id, rejected.length);
    return { accepted: 0, duplicates: 0, rejected, droppedFields };
  }

  let accepted = 0;
  let duplicates = 0;
  transaction(() => {
    const ts = nowIso();
    let lastEventAt = null;
    let heartbeat = false;
    let privateCount = 0;
    let ipCount = 0;

    for (const item of valid) {
      const { event, raw } = item;
      const marker = run(
        `INSERT OR IGNORE INTO website_event_ids (site_id, event_id, org_id, received_at) VALUES (?, ?, ?, ?)`,
        site.id, event.event_id, orgId, ts,
      );
      if (!marker.changes) { duplicates += 1; continue; }

      const mapping = EVENT_TYPES[event.type];
      const ip = event.client?.ip ?? null;
      if (ip) {
        ipCount += 1;
        if (isPrivateAddress(ip)) privateCount += 1;
      }
      const payload = {
        ...event,
        ip_class: ip ? (isPrivateAddress(ip) ? 'private' : 'public') : null,
        received_at: ts,
        sdk: envelope.sdk ?? null,
      };
      const id = newId('evt');
      run(
        `INSERT INTO security_events (id, org_id, event_type, source, severity, category, title, description,
           src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at,
           trust_level, website_site_id, dedupe_key)
         VALUES (?, ?, ?, 'secureflow-sdk', 'info', ?, ?, ?, ?, NULL, ?, ?, ?, 'new', ?, ?, 'server_sdk', ?, ?)`,
        id, orgId, mapping.type, mapping.category, mapping.label,
        `${event.type} reported by the website SDK for ${site.hostname}.`,
        ip, event.actor?.id ?? null, site.asset_id ?? null, JSON.stringify(payload),
        event.occurred_at, ts, site.id, `wsite:${site.id}:${event.event_id}`,
      );
      accepted += 1;
      if (!lastEventAt || event.occurred_at > lastEventAt) lastEventAt = event.occurred_at;
      if (event.type === 'sdk.heartbeat') heartbeat = true;
    }

    if (accepted || duplicates) {
      run(
        `UPDATE website_sites SET
           last_event_at = CASE WHEN ? IS NULL THEN last_event_at WHEN last_event_at IS NULL OR ? > last_event_at THEN ? ELSE last_event_at END,
           last_heartbeat_at = CASE WHEN ? = 1 THEN ? ELSE last_heartbeat_at END,
           connected_at = COALESCE(connected_at, ?),
           private_ip_count = private_ip_count + ?,
           ip_event_count = ip_event_count + ?,
           updated_at = ?
         WHERE id = ? AND org_id = ?`,
        lastEventAt, lastEventAt, lastEventAt, heartbeat ? 1 : 0, ts, ts, privateCount, ipCount, ts, site.id, orgId,
      );
    }
    bumpUsage(site.id, key.key_id, accepted + duplicates + rejected.length);

    if (touchKey(key)) {
      run('UPDATE site_api_keys SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)', ts, key.id, ts);
    }
  });

  return { accepted, duplicates, rejected, droppedFields };
}
