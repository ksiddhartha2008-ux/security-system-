/**
 * TriShield integration health.
 *
 * One state model for every integration. A card never says ACTIVE because an
 * environment variable exists: the state either comes from a recorded real check
 * or from live collector telemetry, and both are visible with their timestamp.
 *
 * States: NOT CONFIGURED, CONFIGURED, CONNECTED, VERIFIED, DEGRADED, ERROR,
 * UNAVAILABLE.
 */
import { all, get, run, newId, nowIso } from '../db.js';
import { badRequest, notFound } from '../lib/http.js';
import { firewallProviders, providerConnector } from './firewall.js';
import { listCollectors } from './trishieldIngest.js';
import { parseClamHost, readVersion } from '../lib/clamav.js';
import { createWazuhClient, wazuhConfig } from '../lib/wazuh.js';

const STALE_MS = 15 * 60_000;

const SETUP = {
  nftables: {
    windows: [
      'nftables is Linux only. On Windows run the API in WSL2 or a Linux container; this process reports UNAVAILABLE and never runs nft.',
      'Use the Windows workspace for development with TRISHIELD_FIREWALL_APPLY=false.',
    ],
    linux: [
      'Install nftables: apt install nftables (Debian or Ubuntu) or dnf install nftables (Fedora).',
      'Grant the API process CAP_NET_ADMIN, for example with a systemd AmbientCapabilities line, or run it in a dedicated network namespace.',
      'Set TRISHIELD_FIREWALL_APPLY=true only after a manual check on a disposable host.',
      'Press Test connection to provision inet secureflow and verify the drop rules.',
    ],
    cloud: ['Nothing to configure. This connector is host local by design.'],
  },
  cloudflare: {
    windows: [
      'Create a token with Account Firewall Access Rules edit permission for the target account.',
      'Set SF_CLOUDFLARE_API_TOKEN and SF_CLOUDFLARE_ACCOUNT_ID in the server environment, then restart.',
      'Account access rules are not zone level WAF rules. The WAF feed is a separate collector.',
    ],
    linux: [
      'Inject the token from your secret store at process start; never commit it or expose it to the browser.',
      'Keep TRISHIELD_FIREWALL_APPLY=false until a test connection succeeds.',
      'Press Test connection to read the account rule list.',
    ],
    cloud: ['Works from any host with outbound HTTPS to api.cloudflare.com.'],
  },
  suricata: {
    windows: [
      'Suricata does not run natively here. Use a Linux sensor and forward events to this API.',
      'Create a Suricata collector, copy the token once, and run scripts/trishield-eve-tail.mjs on the sensor.',
    ],
    linux: [
      'Enable EVE JSON output in suricata.yaml (eve-log: enabled: yes, filename: eve.json).',
      'Create a collector in this page, then run: TRISHIELD_URL=... TRISHIELD_TOKEN=tsk_... node scripts/trishield-eve-tail.mjs --file /var/log/suricata/eve.json --follow',
      'The tailer keeps an offset file so a restart does not duplicate events.',
    ],
    cloud: ['The sensor needs outbound HTTPS to the API. Inline IPS requires a traffic path and is not enabled by this product.'],
  },
  wazuh: {
    windows: [
      'The Wazuh agent runs on the endpoint; the manager is separate. Point WAZUH_API_URL at the manager API, for example https://wazuh.example:55000.',
      'Set WAZUH_API_USER and WAZUH_API_PASSWORD, or WAZUH_API_TOKEN, then restart.',
    ],
    linux: [
      'Use the manager API on port 55000 and a read only API user.',
      'Trust the manager certificate with NODE_EXTRA_CA_CERTS instead of disabling TLS verification.',
      'Alternatively leave the API unset and use a Wazuh collector token; events then arrive without an API connection.',
    ],
    cloud: ['The manager API must be reachable from this host over HTTPS.'],
  },
  waf: {
    windows: [
      'A WAF collector receives normalised events from Cloudflare, ModSecurity or Coraza.',
      'Create a WAF collector and post to /api/trishield/ingest/waf with the token.',
    ],
    linux: [
      'For ModSecurity, forward the audit log through the collector token and the normaliser.',
      'Unknown categories are refused, so the sender must map to sqli, xss, path_traversal, bot, flood, auth_abuse, protocol_anomaly or suspicious.',
    ],
    cloud: ['Cloudflare log push or a Worker can post normalised events to the WAF ingest route.'],
  },
  clamav: {
    windows: [
      'clamd does not run natively here. Use a Linux host or a container and point CLAMAV_HOST at it, for example clamav:3310.',
      'This page reports NOT CONFIGURED until a host is set; a failed scanner is never reported as clean.',
    ],
    linux: [
      'Install clamav-daemon, keep TCPAddr on the private interface only, and never publish port 3310.',
      'Set CLAMAV_HOST=host:3310 and restart the API.',
      'Press Test connection. The VERSION reply proves the engine and signature database are alive.',
    ],
    cloud: ['Keep the daemon on a private network shared with the API only.'],
  },
};

const DEFINITIONS = [
  {
    key: 'nftables',
    name: 'Linux nftables',
    layer: 'perimeter',
    category: 'firewall',
    docs: '/docs/trishield/INTEGRATIONS.md#linux-nftables',
    requirements: ['Linux kernel with nftables', 'nft binary on PATH', 'CAP_NET_ADMIN for the API process', 'TRISHIELD_FIREWALL_APPLY=true for live changes'],
  },
  {
    key: 'cloudflare',
    name: 'Cloudflare account firewall',
    layer: 'perimeter',
    category: 'firewall',
    docs: '/docs/trishield/INTEGRATIONS.md#cloudflare-firewall-access-rules',
    requirements: ['SF_CLOUDFLARE_API_TOKEN', 'SF_CLOUDFLARE_ACCOUNT_ID', 'Token permission: Account Firewall Access Rules edit', 'Outbound HTTPS to api.cloudflare.com'],
  },
  {
    key: 'suricata',
    name: 'Suricata sensor',
    layer: 'perimeter',
    category: 'ids',
    docs: '/docs/trishield/INTEGRATIONS.md#suricata-ids-and-ips',
    requirements: ['A Suricata sensor with EVE JSON output', 'A Suricata collector token', 'scripts/trishield-eve-tail.mjs running on the sensor', 'Events within the last 15 minutes'],
  },
  {
    key: 'waf',
    name: 'WAF event feed',
    layer: 'perimeter',
    category: 'waf',
    docs: '/docs/trishield/INTEGRATIONS.md#waf-cloudflare-modsecurity-and-compatible',
    requirements: ['A WAF collector token', 'A sender that normalises provider events', 'Events within the last 15 minutes'],
  },
  {
    key: 'wazuh',
    name: 'Wazuh manager',
    layer: 'endpoint',
    category: 'endpoint',
    docs: '/docs/trishield/INTEGRATIONS.md#wazuh',
    requirements: ['WAZUH_API_URL', 'WAZUH_API_USER and WAZUH_API_PASSWORD, or WAZUH_API_TOKEN', 'Trusted manager certificate', 'Network access to port 55000'],
  },
  {
    key: 'clamav',
    name: 'ClamAV scanner',
    layer: 'endpoint',
    category: 'malware',
    docs: '/docs/trishield/INTEGRATIONS.md#clamav-yara-and-falco',
    requirements: ['A clamd instance with INSTREAM enabled', 'CLAMAV_HOST set to host or host:port', 'Private network only, never a public port', 'Signature database updated by freshclam'],
  },
];

function definitionFor(key) {
  const definition = DEFINITIONS.find((item) => item.key === key);
  if (!definition) throw notFound('Unknown integration');
  return definition;
}

function latestChecks(orgId, integration, limit = 5) {
  return all(
    `SELECT state, ok, latency_ms, detail, version, checked_at FROM trishield_health_checks
      WHERE org_id = ? AND integration = ? ORDER BY checked_at DESC, rowid DESC LIMIT ?`,
    orgId, integration, limit,
  );
}

function lastOf(orgId, integration, ok) {
  return get(
    `SELECT checked_at, detail FROM trishield_health_checks
      WHERE org_id = ? AND integration = ? AND ok = ? ORDER BY checked_at DESC, rowid DESC LIMIT 1`,
    orgId, integration, ok ? 1 : 0,
  ) ?? null;
}

function collectorFor(orgId, kind) {
  return listCollectors(orgId).filter((collector) => collector.kind === kind);
}

function collectorState(collectors, now = Date.now()) {
  const active = collectors.filter((collector) => collector.status !== 'disabled');
  if (!active.length) {
    return {
      state: collectors.length ? 'UNAVAILABLE' : 'NOT CONFIGURED',
      detail: collectors.length ? 'Every collector token for this feed is revoked' : 'No collector token exists yet',
      lastEventAt: null,
    };
  }
  const newest = active
    .map((collector) => collector.lastSeenAt)
    .filter(Boolean)
    .sort()
    .pop() ?? null;
  if (!newest) {
    return { state: 'CONFIGURED', detail: 'Collector token exists but no event has arrived yet', lastEventAt: null };
  }
  const age = now - new Date(newest).getTime();
  return {
    state: age <= STALE_MS ? 'VERIFIED' : 'DEGRADED',
    detail: age <= STALE_MS
      ? 'Events arrived within the last 15 minutes'
      : `No event for ${Math.round(age / 60_000)} minutes; the sensor may be down`,
    lastEventAt: newest,
  };
}

function nextActionFor(key, state, missing) {
  if (state === 'VERIFIED') return 'Nothing to do. Re-check after a configuration change.';
  if (missing.length) return `Missing requirement: ${missing[0]}.`;
  if (state === 'NOT CONFIGURED') {
    return key === 'suricata' || key === 'waf' ? 'Create a collector token, then start the sender.' : 'Set the required environment variables, then restart the API.';
  }
  if (state === 'DEGRADED') {
    if (key === 'nftables') return 'Run Test connection to provision inet secureflow, or enable TRISHIELD_FIREWALL_APPLY.';
    if (key === 'suricata' || key === 'waf') return 'Check the sensor process and its outbound connection to this API.';
    return 'Read the detail, fix the provider, then test again.';
  }
  if (state === 'ERROR') return 'Fix the connection problem shown in the detail, then test again.';
  if (state === 'UNAVAILABLE') return 'Run this integration on a supported host, or remove it from the deployment.';
  return 'Press Test connection.';
}

async function runNftables({ env, deps }) {
  const platform = deps.platform ?? process.platform;
  const provider = (deps.firewallProviders ?? firewallProviders)(env).find((item) => item.key === 'nftables');
  if (platform !== 'linux') {
    return {
      state: 'UNAVAILABLE', ok: false, latencyMs: null, version: null,
      detail: 'Linux nftables requires a Linux host. This API process is not on Linux, so nft is never executed.',
    };
  }
  const connector = (deps.providerConnector ?? providerConnector)('nftables', { applyEnabled: env.TRISHIELD_FIREWALL_APPLY === 'true' });
  const started = performance.now();
  const health = await connector.health();
  const latencyMs = Math.round(performance.now() - started);
  if (!health.ok && health.code === 'unprovisioned') {
    return { state: 'DEGRADED', ok: false, latencyMs, version: null, detail: health.detail };
  }
  if (!health.ok) return { state: 'ERROR', ok: false, latencyMs, version: null, detail: health.detail };
  if (env.TRISHIELD_FIREWALL_APPLY !== 'true') {
    return { state: 'DEGRADED', ok: true, latencyMs, version: null, detail: 'Table and drop rules are present, but live changes are disabled by TRISHIELD_FIREWALL_APPLY.' };
  }
  return { state: 'VERIFIED', ok: true, latencyMs, version: null, detail: health.detail };
}

async function runCloudflare({ env, deps }) {
  const provider = (deps.firewallProviders ?? firewallProviders)(env).find((item) => item.key === 'cloudflare');
  if (!provider?.available) {
    return { state: 'NOT CONFIGURED', ok: false, latencyMs: null, version: null, detail: 'SF_CLOUDFLARE_API_TOKEN and SF_CLOUDFLARE_ACCOUNT_ID are not both set.' };
  }
  const connector = (deps.providerConnector ?? providerConnector)('cloudflare', { applyEnabled: env.TRISHIELD_FIREWALL_APPLY === 'true' });
  const started = performance.now();
  const health = await connector.health();
  const latencyMs = Math.round(performance.now() - started);
  if (!health.ok) return { state: 'ERROR', ok: false, latencyMs, version: null, detail: health.detail };
  if (env.TRISHIELD_FIREWALL_APPLY !== 'true') {
    return { state: 'DEGRADED', ok: true, latencyMs, version: null, detail: 'The account rule list is readable, but apply is disabled by TRISHIELD_FIREWALL_APPLY.' };
  }
  return { state: 'VERIFIED', ok: true, latencyMs, version: null, detail: health.detail };
}

async function runClamav({ env, deps }) {
  const clam = (deps.parseClamHost ?? parseClamHost)(env.CLAMAV_HOST);
  if (!clam) {
    return { state: 'NOT CONFIGURED', ok: false, latencyMs: null, version: null, detail: 'CLAMAV_HOST is not set, so evidence uploads are stored unscanned and marked not_scanned.' };
  }
  const started = performance.now();
  const result = await (deps.readVersion ?? readVersion)({ ...clam, timeoutMs: 4000 });
  const latencyMs = Math.round(performance.now() - started);
  if (!result.ok) return { state: 'ERROR', ok: false, latencyMs, version: null, detail: `${clam.host}:${clam.port} did not answer VERSION: ${result.detail}` };
  return {
    state: 'VERIFIED', ok: true, latencyMs,
    version: `ClamAV ${result.engine} / signatures ${result.signatures}`,
    detail: `ClamAV ${result.engine}, ${result.signatures} signatures dated ${result.signatureDate}`,
  };
}

async function runWazuh({ orgId, env, deps }) {
  const config = (deps.wazuhConfig ?? wazuhConfig)(env);
  if (config.configured) {
    const client = (deps.createWazuhClient ?? createWazuhClient)({ ...config, fetchImpl: deps.fetchImpl ?? fetch });
    const started = performance.now();
    const health = await client.health();
    const latencyMs = health.latencyMs ?? Math.round(performance.now() - started);
    if (!health.ok) return { state: 'ERROR', ok: false, latencyMs, version: health.version ?? null, detail: health.detail };
    let agents = null;
    try { agents = await client.agents({ limit: 200 }); } catch { agents = null; }
    return {
      state: 'VERIFIED', ok: true, latencyMs,
      version: health.version ? `Wazuh ${health.version}` : null,
      detail: health.detail + (agents ? `. ${agents.length} agent record(s) returned by the manager.` : ''),
      agents,
    };
  }
  const collectors = collectorFor(orgId, 'wazuh');
  const live = collectorState(collectors);
  return { state: live.state, ok: live.state === 'VERIFIED', latencyMs: null, version: null, detail: live.detail, lastEventAt: live.lastEventAt };
}

async function runCollectorFeed({ orgId, kind }) {
  const live = collectorState(collectorFor(orgId, kind));
  return { state: live.state, ok: live.state === 'VERIFIED', latencyMs: null, version: null, detail: live.detail, lastEventAt: live.lastEventAt };
}

const RUNNERS = {
  nftables: runNftables,
  cloudflare: runCloudflare,
  clamav: runClamav,
  wazuh: runWazuh,
  suricata: (context) => runCollectorFeed({ ...context, kind: 'suricata' }),
  waf: (context) => runCollectorFeed({ ...context, kind: 'waf' }),
};

export function recordHealthCheck(orgId, integration, result) {
  const ts = nowIso();
  run(
    `INSERT INTO trishield_health_checks (id, org_id, integration, state, ok, latency_ms, detail, version, checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('thc'), orgId, integration, result.state, result.ok ? 1 : 0,
    Number.isFinite(result.latencyMs) ? Math.round(result.latencyMs) : null,
    String(result.detail ?? '').slice(0, 400), result.version ? String(result.version).slice(0, 120) : null, ts,
  );
  // Keep the history bounded per integration.
  run(
    `DELETE FROM trishield_health_checks WHERE org_id = ? AND integration = ? AND id NOT IN (
       SELECT id FROM trishield_health_checks WHERE org_id = ? AND integration = ? ORDER BY checked_at DESC, rowid DESC LIMIT 200
     )`,
    orgId, integration, orgId, integration,
  );
  return ts;
}

export async function checkIntegration(orgId, key, { env = process.env, deps = {} } = {}) {
  const definition = definitionFor(key);
  const runner = RUNNERS[key];
  if (!runner) throw badRequest('This integration has no check');
  const result = await runner({ orgId, env, deps });
  const checkedAt = recordHealthCheck(orgId, key, result);
  return { ...definition, ...result, checkedAt, key };
}

function configurationMissing(key, env, orgId) {
  const missing = [];
  if (key === 'nftables') {
    if (process.platform !== 'linux') missing.push('A Linux host');
  }
  if (key === 'cloudflare') {
    if (!env.SF_CLOUDFLARE_API_TOKEN) missing.push('SF_CLOUDFLARE_API_TOKEN');
    if (!env.SF_CLOUDFLARE_ACCOUNT_ID) missing.push('SF_CLOUDFLARE_ACCOUNT_ID');
  }
  if (key === 'suricata' && !collectorFor(orgId, 'suricata').length) missing.push('A Suricata collector token');
  if (key === 'waf' && !collectorFor(orgId, 'waf').length) missing.push('A WAF collector token');
  if (key === 'wazuh') {
    const config = wazuhConfig(env);
    if (!config.configured) {
      if (!config.baseUrl) missing.push('WAZUH_API_URL');
      if (!config.token && !config.username) missing.push('WAZUH_API_USER and WAZUH_API_PASSWORD');
      if (!collectorFor(orgId, 'wazuh').length) missing.push('A Wazuh collector token or the manager API');
    }
  }
  if (key === 'clamav' && !env.CLAMAV_HOST) missing.push('CLAMAV_HOST');
  return missing;
}

/** Read only view. It never performs a network call. */
export function integrationHealth(orgId, { env = process.env } = {}) {
  return DEFINITIONS.map((definition) => {
    const history = latestChecks(orgId, definition.key, 5);
    const last = history[0] ?? null;
    const success = lastOf(orgId, definition.key, true);
    const failure = lastOf(orgId, definition.key, false);
    const missing = configurationMissing(definition.key, env, orgId);
    let state;
    if (definition.key === 'nftables' && process.platform !== 'linux') state = 'UNAVAILABLE';
    else if (definition.key === 'suricata' || definition.key === 'waf') {
      state = collectorState(collectorFor(orgId, definition.key)).state;
    } else if (definition.key === 'wazuh' && !wazuhConfig(env).configured) {
      state = collectorState(collectorFor(orgId, 'wazuh')).state;
    } else state = last?.state ?? (missing.length ? 'NOT CONFIGURED' : 'CONFIGURED');

    if (state === 'VERIFIED' && missing.length) state = 'DEGRADED';
    return {
      ...definition,
      state,
      ok: last?.ok === 1,
      detail: last?.detail ?? '',
      latencyMs: last?.latency_ms ?? null,
      version: last?.version ?? null,
      lastCheckedAt: last?.checked_at ?? null,
      lastSuccessAt: success?.checked_at ?? null,
      lastFailureAt: failure?.checked_at ?? null,
      history: history.map((row) => ({ state: row.state, ok: row.ok === 1, checkedAt: row.checked_at, latencyMs: row.latency_ms })),
      requirements: definition.requirements,
      missing,
      nextAction: nextActionFor(definition.key, state, missing),
      setup: SETUP[definition.key],
    };
  });
}

export function healthSummary(orgId, { env = process.env } = {}) {
  const cards = integrationHealth(orgId, { env });
  const counts = {
    verified: cards.filter((card) => card.state === 'VERIFIED').length,
    connected: cards.filter((card) => card.state === 'CONNECTED').length,
    degraded: cards.filter((card) => card.state === 'DEGRADED').length,
    error: cards.filter((card) => card.state === 'ERROR').length,
    notConfigured: cards.filter((card) => card.state === 'NOT CONFIGURED').length,
    unavailable: cards.filter((card) => card.state === 'UNAVAILABLE').length,
    total: cards.length,
  };
  return { counts, cards };
}

export const INTEGRATION_KEYS = DEFINITIONS.map((definition) => definition.key);
