import { createHash, randomBytes } from 'node:crypto';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { badRequest, forbidden, notFound, unauthorized } from '../lib/http.js';
import { evaluateRules } from './detection.js';
import { evaluateEventForBlock } from './trishieldPolicy.js';

const MAX_BATCH = 500;
const MAX_RAW = 8000;

const SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical'];

function clampText(value, max = 200) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}

function safeIp(value) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  if (!/^[0-9a-f:.]+$/i.test(text) || text.length > 64) return null;
  return text;
}

function sanitizeRaw(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return value ?? null;
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeRaw(item, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (/pass(word)?|secret|token|authorization|cookie|api[_-]?key/i.test(key)) continue;
      out[key] = sanitizeRaw(item, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') return clampText(value, MAX_RAW);
  return value;
}

function severityFromLevel(level) {
  const n = Number(level);
  if (!Number.isFinite(n)) return 'info';
  if (n >= 12) return 'critical';
  if (n >= 8) return 'high';
  if (n >= 5) return 'medium';
  if (n >= 3) return 'low';
  return 'info';
}

function parseDate(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) throw badRequest('Invalid event timestamp');
  return date.toISOString();
}

function dedupeHash(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);
}

export function parseSuricataRecord(record) {
  if (!record || typeof record !== 'object') throw badRequest('Suricata record must be an object');
  const type = String(record.event_type ?? '').toLowerCase();
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(type)) throw badRequest('Suricata event_type is invalid');
  const srcIp = safeIp(record.src_ip);
  const destIp = safeIp(record.dest_ip);
  if ((record.src_ip && !srcIp) || (record.dest_ip && !destIp)) throw badRequest('Suricata record has an invalid address');
  const alert = record.alert ?? {};
  const severity = type === 'alert' ? (['critical', 'high', 'medium', 'low'][Number(alert.severity) - 1] ?? 'medium') : 'info';
  const timestamp = parseDate(record.timestamp);
  const dedupeKey = `suricata:${record.event_id ?? dedupeHash([type, timestamp, srcIp ?? '', destIp ?? '', alert.signature_id ?? '', alert.signature ?? ''])}`;
  return {
    eventType: `suricata.${type}`,
    source: 'suricata',
    severity,
    category: 'network',
    title: clampText(alert.signature ?? `Suricata ${type} event`, 200),
    description: clampText(alert.category ?? `Suricata ${type} record`, 500),
    srcIp,
    destIp,
    assetId: null,
    occurredAt: timestamp,
    dedupeKey,
    network: type === 'flow' ? {
      srcIp, destIp,
      srcPort: Number(record.src_port) || null,
      destPort: Number(record.dest_port) || null,
      protocol: clampText(record.proto ?? 'unknown', 20),
      bytesOut: Number(record.flow?.bytes_toserver) || 0,
      bytesIn: Number(record.flow?.bytes_toclient) || 0,
      verdict: 'allowed',
    } : null,
    raw: sanitizeRaw({
      event_type: type, timestamp, src_ip: srcIp, dest_ip: destIp, proto: record.proto,
      src_port: record.src_port, dest_port: record.dest_port,
      signature: alert.signature, signature_id: alert.signature_id, category: alert.category,
      severity: alert.severity, flow_id: record.flow_id, in_iface: record.in_iface,
    }),
  };
}

export function parseWazuhRecord(record) {
  if (!record || typeof record !== 'object') throw badRequest('Wazuh record must be an object');
  const agent = record.agent ?? {};
  const rule = record.rule ?? {};
  const agentId = clampText(agent.id ?? 'unknown', 80);
  if (!agentId) throw badRequest('Wazuh record has no agent id');
  const severity = severityFromLevel(rule.level);
  const timestamp = parseDate(record.timestamp);
  const dedupeKey = `wazuh:${agentId}:${rule.id ?? 'rule'}:${timestamp}:${dedupeHash([rule.description ?? ''])}`;
  return {
    eventType: `wazuh.${clampText((rule.groups ?? ['alert'])[0] ?? 'alert', 40).replace(/[^a-z0-9._-]/gi, '_')}`,
    source: 'wazuh',
    severity,
    category: 'endpoint',
    title: clampText(rule.description ?? 'Wazuh alert', 200),
    description: clampText(record.full_log ?? rule.description ?? '', 500),
    srcIp: safeIp(agent.ip),
    destIp: null,
    occurredAt: timestamp,
    dedupeKey,
    agent: {
      agentId,
      hostname: clampText(agent.name ?? '', 120),
      os: clampText((agent.os?.name ?? agent.os?.platform ?? ''), 80) || null,
      ip: safeIp(agent.ip),
    },
    raw: sanitizeRaw({
      agent: { id: agentId, name: agent.name, ip: agent.ip },
      rule: { id: rule.id, level: rule.level, description: rule.description, groups: rule.groups },
      location: record.location,
    }),
  };
}

const WAF_CATEGORIES = new Set(['sqli', 'xss', 'path_traversal', 'bot', 'flood', 'auth_abuse', 'protocol', 'other']);
const WAF_ACTIONS = new Set(['blocked', 'challenged', 'allowed']);

export function parseWafRecord(record) {
  if (!record || typeof record !== 'object') throw badRequest('WAF record must be an object');
  const provider = clampText(record.provider ?? 'unknown', 40);
  const category = String(record.category ?? 'other').toLowerCase();
  const action = String(record.action ?? 'blocked').toLowerCase();
  if (!WAF_CATEGORIES.has(category)) throw badRequest('WAF category is invalid');
  if (!WAF_ACTIONS.has(action)) throw badRequest('WAF action is invalid');
  const srcIp = safeIp(record.sourceIp ?? record.src_ip);
  const timestamp = parseDate(record.observedAt ?? record.timestamp);
  const severity = category === 'sqli' && action === 'blocked' ? 'critical'
    : ['xss', 'path_traversal'].includes(category) && action !== 'allowed' ? 'high'
      : action === 'blocked' ? 'medium' : 'low';
  const dedupeKey = `waf:${provider}:${record.id ?? dedupeHash([provider, category, timestamp, srcIp ?? '', record.path ?? '', record.ruleId ?? ''])}`;
  return {
    eventType: `waf.${category}`,
    source: `waf:${provider}`,
    severity,
    category: 'application',
    title: clampText(`${provider} ${action} ${category}`, 200),
    description: clampText(record.message ?? `${provider} ${action} ${category} request`, 500),
    srcIp,
    destIp: safeIp(record.destIp),
    occurredAt: timestamp,
    dedupeKey,
    raw: sanitizeRaw({
      provider, category, action, ruleId: record.ruleId, path: clampText(record.path, 300),
      method: clampText(record.method, 12), status: record.status, host: record.host,
    }),
  };
}

function storeEvent(orgId, event) {
  const duplicate = get(
    `SELECT id FROM security_events WHERE org_id = ? AND json_extract(raw, '$.dedupeKey') = ? LIMIT 1`,
    orgId, event.dedupeKey,
  );
  if (duplicate) return { duplicate: true, id: duplicate.id };
  const id = newId('evt');
  const occurredAt = event.occurredAt ?? nowIso();
  run(
    `INSERT INTO security_events (id, org_id, event_type, source, severity, category, title, description,
       src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 'new', ?, ?)`,
    id, orgId, event.eventType, event.source, event.severity, event.category, event.title,
    event.description ?? null, event.srcIp ?? null, event.destIp ?? null, event.assetId ?? null,
    JSON.stringify({ ...event.raw, dedupeKey: event.dedupeKey }), occurredAt, nowIso(),
  );
  if (event.network?.srcIp && event.network?.destIp) {
    run(
      `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'inbound', ?, ?, ?, ?)`,
      newId('net'), orgId, event.network.srcIp, event.network.srcPort, event.network.destIp, event.network.destPort,
      event.network.protocol, event.network.bytesOut, event.network.bytesIn, event.network.verdict,
      event.assetId ?? null, occurredAt, nowIso(),
    );
  }
  return { duplicate: false, id };
}

function touchCollector(collectorId, orgId) {
  run('UPDATE trishield_collectors SET last_seen_at = ?, updated_at = ? WHERE id = ?', nowIso(), nowIso(), collectorId);
  const key = `trishield-${get('SELECT kind FROM trishield_collectors WHERE id = ?', collectorId)?.kind ?? 'collector'}`;
  const existing = get('SELECT id FROM integration_configs WHERE org_id = ? AND key = ?', orgId, key);
  if (existing) {
    run('UPDATE integration_configs SET status = \'connected\', last_sync_at = ?, last_error = NULL, updated_at = ? WHERE id = ?',
      nowIso(), nowIso(), existing.id);
  } else {
    run(
      `INSERT INTO integration_configs (id, org_id, key, name, category, status, config, last_sync_at, last_error, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'trishield', 'connected', '{}', ?, NULL, ?, ?)`,
      newId('int'), orgId, key, key.replace('trishield-', '').replace(/^./, (c) => c.toUpperCase()), nowIso(), nowIso(), nowIso(),
    );
  }
}

export async function ingestProviderRecords({ orgId, collector, kind, records }) {
  if (!Array.isArray(records) || !records.length) throw badRequest('At least one record is required');
  if (records.length > MAX_BATCH) throw badRequest(`A batch is limited to ${MAX_BATCH} records`);
  const parser = kind === 'suricata' ? parseSuricataRecord : kind === 'wazuh' ? parseWazuhRecord : parseWafRecord;
  let accepted = 0;
  let duplicates = 0;
  const rejected = [];
  const acceptedEvents = [];
  for (const [index, record] of records.entries()) {
    try {
      const parsed = parser(record);
      const result = storeEvent(orgId, parsed);
      if (result.duplicate) duplicates += 1;
      else { accepted += 1; acceptedEvents.push(parsed); }
      if (kind === 'wazuh' && parsed.agent) {
        const existing = get('SELECT id FROM endpoint_agents WHERE org_id = ? AND provider = ? AND agent_id = ?', orgId, 'wazuh', parsed.agent.agentId);
        if (existing) {
          run('UPDATE endpoint_agents SET hostname = ?, os = ?, ip_address = ?, status = \'online\', last_seen_at = ?, updated_at = ? WHERE id = ?',
            parsed.agent.hostname, parsed.agent.os, parsed.agent.ip, parsed.occurredAt, nowIso(), existing.id);
        } else {
          run(
            `INSERT INTO endpoint_agents (id, org_id, provider, agent_id, hostname, os, ip_address, status, last_seen_at, asset_id, metadata, created_at, updated_at)
             VALUES (?, ?, 'wazuh', ?, ?, ?, ?, 'online', ?, NULL, '{}', ?, ?)`,
            newId('epa'), orgId, parsed.agent.agentId, parsed.agent.hostname, parsed.agent.os,
            parsed.agent.ip, parsed.occurredAt, nowIso(), nowIso(),
          );
        }
      }
    } catch (error) {
      rejected.push({ index, message: String(error.message).slice(0, 200) });
    }
  }
  touchCollector(collector.id, orgId);
  if (accepted) evaluateRules(orgId);
  const policy = [];
  for (const event of acceptedEvents) {
    if (!event.srcIp || !['network', 'application'].includes(event.category)) continue;
    try {
      const decision = await evaluateEventForBlock({ orgId, event });
      if (decision.decision !== 'none') policy.push({ event: event.dedupeKey, ...decision });
    } catch (error) {
      policy.push({ event: event.dedupeKey, decision: 'error', detail: String(error.message).slice(0, 200) });
    }
  }
  return { accepted, duplicates, rejected, policy, collector: collector.name, kind };
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function createCollector(orgId, { kind, name, user }) {
  if (!['suricata', 'wazuh', 'waf'].includes(kind)) throw badRequest('Collector kind must be suricata, wazuh or waf');
  const token = `tsk_${randomBytes(24).toString('base64url')}`;
  const id = newId('col');
  run(
    `INSERT INTO trishield_collectors (id, org_id, kind, name, token_hash, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
    id, orgId, kind, clampText(name, 80) || `${kind} collector`, hashToken(token), nowIso(), nowIso(),
  );
  return { id, kind, name: clampText(name, 80), token, note: 'Copy this token now. It is stored as a hash and shown once.' };
}

export function listCollectors(orgId) {
  return all('SELECT id, org_id, kind, name, status, last_seen_at, created_at, updated_at FROM trishield_collectors WHERE org_id = ? ORDER BY created_at DESC', orgId)
    .map((row) => ({ id: row.id, kind: row.kind, name: row.name, status: row.status, lastSeenAt: row.last_seen_at, createdAt: row.created_at }));
}

export function revokeCollector(orgId, id) {
  const row = get('SELECT id FROM trishield_collectors WHERE id = ? AND org_id = ?', id, orgId);
  if (!row) throw notFound('Collector not found');
  run('UPDATE trishield_collectors SET status = \'disabled\', updated_at = ? WHERE id = ?', nowIso(), id);
  return { id, status: 'disabled' };
}

export function authenticateCollector(header) {
  const match = /^Bearer (tsk_[A-Za-z0-9_-]+)$/.exec(String(header ?? '').trim());
  if (!match) throw unauthorized('Collector token required');
  const row = get('SELECT * FROM trishield_collectors WHERE token_hash = ?', hashToken(match[1]));
  if (!row || row.status !== 'active') throw unauthorized('Collector token is invalid');
  return row;
}

export function endpointSummary(orgId) {
  const agents = all('SELECT * FROM endpoint_agents WHERE org_id = ? ORDER BY last_seen_at DESC LIMIT 100', orgId);
  const now = Date.now();
  return agents.map((row) => ({
    id: row.id, provider: row.provider, agentId: row.agent_id, hostname: row.hostname, os: row.os,
    ipMasked: row.ip_address ? String(row.ip_address).replace(/(\d+)$/, 'xxx') : null,
    status: row.last_seen_at && now - new Date(row.last_seen_at).getTime() > 15 * 60_000 ? 'stale' : row.status,
    lastSeenAt: row.last_seen_at, assetId: row.asset_id,
  }));
}

export function collectorHealth(orgId) {
  return listCollectors(orgId).map((collector) => {
    const stale = !collector.lastSeenAt || Date.now() - new Date(collector.lastSeenAt).getTime() > 15 * 60_000;
    // Same vocabulary as the integration health engine. VERIFIED means data
    // actually arrived recently, not that a token exists.
    const state = collector.status === 'disabled'
      ? 'UNAVAILABLE'
      : !collector.lastSeenAt
        ? 'CONFIGURED'
        : stale ? 'DEGRADED' : 'VERIFIED';
    return {
      ...collector,
      state,
      health: state,
      detail: state === 'VERIFIED'
        ? 'Events arrived within the last 15 minutes'
        : state === 'DEGRADED'
          ? 'No event in the last 15 minutes'
          : state === 'UNAVAILABLE' ? 'Collector token revoked' : 'No event received yet',
    };
  });
}
