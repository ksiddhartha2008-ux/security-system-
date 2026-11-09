import { all, get, run, newId, nowIso, transaction, parseJson } from '../db.js';
import { conflict, badRequest } from '../lib/http.js';
import { evaluateRules, refreshAssetRisk } from './detection.js';
import { correlateDetections } from './correlation.js';

/* ------------------------------------------------------------------ *
 * Demo data system.
 * Everything created here is tagged data_origin = DEMO with a batch id,
 * so a reset can remove exactly these rows and never touch real telemetry.
 * ------------------------------------------------------------------ */

const DEMO_BATCH_PREFIX = 'demo';

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (rng, list) => list[Math.floor(rng() * list.length) % list.length];

const ASSET_TYPES = [
  { prefix: 'win-fin', os: 'Windows 11 Enterprise', type: 'workstation', criticality: ['high', 'medium'], owner: 'Finance', tags: ['pii'] },
  { prefix: 'win-ops', os: 'Windows 11 Enterprise', type: 'workstation', criticality: ['medium', 'low'], owner: 'Operations', tags: [] },
  { prefix: 'web-srv', os: 'Ubuntu 24.04 LTS', type: 'server', criticality: ['critical'], owner: 'Platform', tags: ['internet-facing', 'pci'] },
  { prefix: 'app-srv', os: 'Amazon Linux 2023', type: 'server', criticality: ['high'], owner: 'Applications', tags: ['production'] },
  { prefix: 'db-srv', os: 'Debian 12', type: 'database', criticality: ['critical'], owner: 'Data', tags: ['pii', 'pci'] },
  { prefix: 'net-edge', os: 'Cisco IOS XE', type: 'network', criticality: ['high'], owner: 'Network', tags: ['internet-facing'] },
  { prefix: 'cloud-svc', os: 'Managed cloud service', type: 'cloud', criticality: ['medium', 'high'], owner: 'Cloud', tags: ['cloud'] },
];

const HISTORY_TYPES = [
  { type: 'auth.success', severity: 'info', category: 'identity', source: 'identity-provider', title: 'Successful sign-in', weight: 18 },
  { type: 'auth.failure', severity: 'low', category: 'identity', source: 'identity-provider', title: 'Failed sign-in attempt', weight: 18 },
  { type: 'endpoint.process_start', severity: 'info', category: 'endpoint', source: 'sysmon', title: 'Process started', weight: 12 },
  { type: 'file.access', severity: 'info', category: 'endpoint', source: 'edr', title: 'File accessed', weight: 8 },
  { type: 'api.request', severity: 'info', category: 'application', source: 'api-gateway', title: 'API request', weight: 14 },
  { type: 'email.received', severity: 'info', category: 'email', source: 'mail-gateway', title: 'Message delivered', weight: 10 },
  { type: 'authz.denied', severity: 'low', category: 'application', source: 'application', title: 'Authorization denied', weight: 3 },
  { type: 'network.connection', severity: 'info', category: 'network', source: 'suricata', title: 'Outbound connection allowed', weight: 10 },
  { type: 'email.click', severity: 'medium', category: 'email', source: 'mail-gateway', title: 'Recipient clicked a rewritten link', weight: 2 },
  { type: 'malware.detected', severity: 'critical', category: 'endpoint', source: 'edr', title: 'Malware detected on endpoint', weight: 1 },
  { type: 'web.sql_injection', severity: 'critical', category: 'application', source: 'waf', title: 'SQL injection payload blocked', weight: 1 },
  { type: 'auth.privileged_login', severity: 'high', category: 'identity', source: 'identity-provider', title: 'Privileged account sign-in', weight: 1 },
  { type: 'vulnerability.detected', severity: 'medium', category: 'vulnerability', source: 'scanner-import', title: 'Vulnerability reported by scanner', weight: 1 },
];

const pickHistory = (rng) => {
  const total = HISTORY_TYPES.reduce((sum, entry) => sum + entry.weight, 0);
  let roll = rng() * total;
  for (const entry of HISTORY_TYPES) {
    roll -= entry.weight;
    if (roll <= 0) return entry;
  }
  return HISTORY_TYPES[0];
};

function insertAsset(orgId, batchId, rng, index) {
  const template = ASSET_TYPES[index % ASSET_TYPES.length];
  const sequence = Math.floor(index / ASSET_TYPES.length) + 1;
  const id = newId('ast');
  const criticality = template.criticality[index % template.criticality.length];
  const risk = 10 + Math.floor(rng() * 35);
  run(
    `INSERT INTO assets (id, org_id, name, hostname, ip_address, mac_address, os, asset_type, criticality, owner, risk_score, status, tags, last_seen_at, created_at, updated_at, data_origin, demo_batch_id)
     VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, 'DEMO', ?)`,
    id, orgId,
    `${template.prefix.replace(/-/g, ' ')} ${String(sequence).padStart(2, '0')}`,
    `${template.prefix}-${String(sequence).padStart(2, '0')}`,
    `192.0.2.${10 + index}`,
    template.os, template.type, criticality, template.owner, risk,
    JSON.stringify(template.tags), new Date(Date.now() - Math.floor(rng() * 45) * 60_000).toISOString(),
    nowIso(), nowIso(), batchId,
  );
  return { id, hostname: `${template.prefix}-${String(sequence).padStart(2, '0')}`, type: template.type, criticality };
}

function insertEvent(orgId, batchId, event) {
  const id = newId('evt');
  run(
    `INSERT INTO security_events (id, org_id, event_type, source, severity, category, title, description, src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at, data_origin, demo_batch_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, 'DEMO', ?)`,
    id, orgId, event.type, event.source, event.severity, event.category, event.title,
    event.description ?? `${event.title} recorded by ${event.source}.`,
    event.srcIp ?? null, event.destIp ?? null, event.userEmail ?? null, event.assetId ?? null,
    JSON.stringify({ synthetic: true, dataOrigin: 'DEMO', demoBatchId: batchId, ...(event.raw ?? {}) }),
    event.occurredAt, nowIso(), batchId,
  );
  return id;
}

export function getDemoStatus(orgId) {
  const countByOrigin = (table) => {
    const rows = all(`SELECT data_origin, COUNT(*) AS c FROM ${table} WHERE org_id = ? GROUP BY data_origin`, orgId);
    return Object.fromEntries(rows.map((row) => [row.data_origin, row.c]));
  };
  const assets = countByOrigin('assets');
  const events = countByOrigin('security_events');
  const detections = countByOrigin('detections');
  const incidents = countByOrigin('incidents');
  const vulnerabilities = countByOrigin('vulnerabilities');
  const networkEvents = countByOrigin('network_events');
  const batchRow = get(
    `SELECT demo_batch_id, COUNT(*) AS c FROM security_events
      WHERE org_id = ? AND data_origin = 'DEMO' AND demo_batch_id IS NOT NULL
      GROUP BY demo_batch_id ORDER BY c DESC LIMIT 1`,
    orgId,
  );
  const runs = all('SELECT * FROM demo_runs WHERE org_id = ? ORDER BY created_at DESC LIMIT 12', orgId);
  return {
    counts: { assets, events, detections, incidents, vulnerabilities, networkEvents },
    hasDemoData: Boolean((assets.DEMO ?? 0) > 0 || (events.DEMO ?? 0) > 0),
    batchId: batchRow?.demo_batch_id ?? null,
    runs: runs.map((row) => ({
      id: row.id, action: row.action, batchId: row.batch_id,
      counts: parseJson(row.counts, {}), createdAt: row.created_at,
    })),
  };
}

/**
 * Generate a deterministic demo workspace: 45 assets, ~250 events, 14
 * vulnerabilities, network telemetry, then detections and incidents through the
 * real engine. Refuses to stack a second batch on top of existing demo data.
 */
export function generateDemoData({ orgId, userId }) {
  const status = getDemoStatus(orgId);
  if (status.hasDemoData) {
    throw conflict('Demo data already exists in this workspace. Reset it before generating a new batch.');
  }
  const batchId = `${DEMO_BATCH_PREFIX}-${Date.now().toString(36)}`;
  const rng = mulberry32(20261109);
  const incidentsBefore = get('SELECT COUNT(*) AS c FROM incidents WHERE org_id = ?', orgId).c;

  const summary = transaction(() => {
    const assets = [];
    for (let i = 0; i < 45; i += 1) assets.push(insertAsset(orgId, batchId, rng, i));
    const workstations = assets.filter((asset) => asset.type === 'workstation');
    const webServers = assets.filter((asset) => asset.hostname.startsWith('web-srv'));
    const databases = assets.filter((asset) => asset.type === 'database');

    const users = ['j.reyes', 'a.miller', 's.patel', 'l.chen', 'm.vale', 'd.okafor'].map((name) => `${name}@demo.local`);
    const external = ['203.0.113.77', '198.51.100.23', '192.0.2.200', '198.51.100.90'];

    // 14 days of background telemetry, 235 events.
    for (let i = 0; i < 235; i += 1) {
      const template = pickHistory(rng);
      const asset = pick(rng, assets);
      const daysAgo = Math.floor(rng() * 14);
      const occurred = new Date();
      occurred.setUTCDate(occurred.getUTCDate() - daysAgo);
      occurred.setUTCHours(6 + Math.floor(rng() * 14), Math.floor(rng() * 60), 0, 0);
      insertEvent(orgId, batchId, {
        type: template.type, source: template.source, severity: template.severity,
        category: template.category, title: template.title,
        description: `${template.title} on ${asset.hostname}.`,
        srcIp: rng() < 0.55 ? `192.0.2.${10 + Math.floor(rng() * 45)}` : pick(rng, external),
        destIp: '192.0.2.10', userEmail: rng() < 0.55 ? pick(rng, users) : null,
        assetId: asset.id, occurredAt: occurred.toISOString(),
      });
    }

    // Deterministic bursts in the live detection window.
    const bruteTarget = pick(rng, webServers).id;
    for (let i = 0; i < 14; i += 1) {
      insertEvent(orgId, batchId, {
        type: 'auth.failure', source: 'identity-provider', severity: 'medium', category: 'identity',
        title: 'Failed sign-in attempt', description: 'Password rejected during a repeated authentication burst.',
        srcIp: '203.0.113.77', destIp: '192.0.2.12', userEmail: users[i % 4], assetId: bruteTarget,
        occurredAt: new Date(Date.now() - (7 - i * 0.4) * 60_000).toISOString(),
      });
    }
    insertEvent(orgId, batchId, {
      type: 'auth.success', source: 'identity-provider', severity: 'high', category: 'identity',
      title: 'Successful sign-in after repeated failures', description: 'A valid credential was accepted from the same source.',
      srcIp: '203.0.113.77', destIp: '192.0.2.12', userEmail: users[3], assetId: bruteTarget,
      occurredAt: new Date(Date.now() - 2 * 60_000).toISOString(),
    });

    const phishingAsset = pick(rng, workstations).id;
    insertEvent(orgId, batchId, {
      type: 'email.click', source: 'mail-gateway', severity: 'high', category: 'email',
      title: 'Payroll link clicked in a lookalike domain message',
      description: 'Recipient opened a link to a two day old lookalike payroll domain.',
      srcIp: '192.0.2.31', userEmail: users[1], assetId: phishingAsset,
      occurredAt: new Date(Date.now() - 20 * 60_000).toISOString(),
    });
    insertEvent(orgId, batchId, {
      type: 'email.credential_submit', source: 'mail-gateway', severity: 'critical', category: 'email',
      title: 'Credentials submitted to a lookalike domain',
      description: 'A password was posted to the phishing page before the message was quarantined.',
      srcIp: '192.0.2.31', userEmail: users[1], assetId: phishingAsset,
      occurredAt: new Date(Date.now() - 17 * 60_000).toISOString(),
    });

    const malwareAsset = pick(rng, workstations).id;
    insertEvent(orgId, batchId, {
      type: 'malware.detected', source: 'edr', severity: 'critical', category: 'endpoint',
      title: 'Malware detected in an invoice attachment',
      description: 'The endpoint sensor quarantined a loader dropped from a signed installer.',
      srcIp: '192.0.2.31', assetId: malwareAsset,
      occurredAt: new Date(Date.now() - 14 * 60_000).toISOString(),
    });
    insertEvent(orgId, batchId, {
      type: 'file.encrypt', source: 'edr', severity: 'critical', category: 'endpoint',
      title: 'Mass file rename with .locked extension',
      description: '120 files were renamed on the mapped finance share.',
      srcIp: '192.0.2.31', assetId: malwareAsset,
      occurredAt: new Date(Date.now() - 12 * 60_000).toISOString(),
    });

    const webAsset = pick(rng, webServers).id;
    for (let i = 0; i < 3; i += 1) {
      insertEvent(orgId, batchId, {
        type: 'web.sql_injection', source: 'waf', severity: 'critical', category: 'application',
        title: 'SQL injection payload against the customer search endpoint',
        description: 'The WAF matched a UNION based injection payload in the q parameter.',
        srcIp: '198.51.100.23', destIp: '192.0.2.12', assetId: webAsset,
        occurredAt: new Date(Date.now() - (22 - i * 2) * 60_000).toISOString(),
        raw: { path: '/api/customers?q=1%20UNION%20SELECT', statusCode: 403 },
      });
    }

    insertEvent(orgId, batchId, {
      type: 'auth.privileged_login', source: 'identity-provider', severity: 'high', category: 'identity',
      title: 'Domain administrator signed in from an unusual address',
      description: 'The administrative account authenticated from a range never seen for this identity.',
      srcIp: '198.51.100.66', userEmail: 'admin@demo.local', assetId: pick(rng, databases).id,
      occurredAt: new Date(Date.now() - 9 * 60_000).toISOString(),
    });

    // Vulnerabilities, including well known CVE identifiers with accurate titles.
    const vulnerabilitySeeds = [
      ['CVE-2021-44228', 'Apache Log4j2 JNDI remote code execution', 'critical', 10.0],
      ['CVE-2024-3400', 'PAN-OS GlobalProtect command injection', 'critical', 10.0],
      ['CVE-2023-4966', 'Citrix NetScaler session token disclosure', 'critical', 9.4],
      ['CVE-2023-34362', 'MOVEit Transfer SQL injection', 'critical', 9.8],
      ['CVE-2022-22965', 'Spring Framework remote code execution', 'critical', 9.8],
      ['CVE-2020-1472', 'Netlogon elevation of privilege (Zerologon)', 'critical', 10.0],
      ['CVE-2021-34527', 'Windows Print Spooler remote code execution', 'high', 8.8],
      ['CVE-2024-6387', 'OpenSSH signal handler race condition', 'high', 8.1],
      ['CVE-2023-44487', 'HTTP/2 rapid reset denial of service', 'high', 7.5],
      ['CVE-2024-21762', 'FortiOS out-of-bounds write', 'critical', 9.8],
      ['CVE-2022-1388', 'F5 iControl REST authentication bypass', 'critical', 9.8],
      ['CVE-2019-0708', 'Remote Desktop Services remote code execution', 'critical', 9.8],
      ['CVE-2025-0001', 'Illustrative demo finding: outdated TLS configuration', 'medium', 5.3],
      ['CVE-2025-0002', 'Illustrative demo finding: permissive file share ACL', 'medium', 6.1],
    ];
    for (let i = 0; i < vulnerabilitySeeds.length; i += 1) {
      const [cve, title, severity, cvss] = vulnerabilitySeeds[i];
      run(
        `INSERT INTO vulnerabilities (id, org_id, cve_id, title, description, severity, cvss, asset_id, status, remediation, due_at, discovered_at, created_at, updated_at, data_origin, demo_batch_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'DEMO', ?)`,
        newId('vuln'), orgId, cve, title, `${title}. Demo finding used for triage practice.`,
        severity, cvss, pick(rng, assets).id, i % 4 === 0 ? 'in_progress' : 'open',
        'Patch to the vendor supported release and verify the exposed surface.',
        new Date(Date.now() + 14 * 86400_000).toISOString(), new Date(Date.now() - (5 + i) * 86400_000).toISOString(),
        nowIso(), nowIso(), batchId,
      );
    }

    // Network telemetry, including a port sweep and a large outbound transfer.
    for (let i = 0; i < 80; i += 1) {
      const occurred = new Date(Date.now() - Math.floor(rng() * 10) * 86400_000);
      run(
        `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at, data_origin, demo_batch_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'outbound', 'allowed', ?, ?, ?, 'DEMO', ?)`,
        newId('net'), orgId, `192.0.2.${10 + Math.floor(rng() * 45)}`, 30000 + Math.floor(rng() * 20000),
        pick(rng, external), pick(rng, [443, 80, 53, 22]), pick(rng, ['TLS', 'TCP', 'UDP']),
        Math.floor(rng() * 2_000_000), Math.floor(rng() * 4_000_000), pick(rng, assets).id,
        occurred.toISOString(), nowIso(), batchId,
      );
    }
    for (let i = 0; i < 16; i += 1) {
      run(
        `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at, data_origin, demo_batch_id)
         VALUES (?, ?, '192.0.2.77', ?, '192.0.2.16', ?, 'TCP', 64, 0, 'inbound', 'suspicious', NULL, ?, ?, 'DEMO', ?)`,
        newId('net'), orgId, 41000 + i, 20 + i * 3,
        new Date(Date.now() - (8 - i * 0.3) * 60_000).toISOString(), nowIso(), batchId,
      );
    }
    run(
      `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at, data_origin, demo_batch_id)
       VALUES (?, ?, '192.0.2.30', 51544, '198.51.100.90', 443, 'TLS', 73400320, 2048, 'outbound', 'suspicious', ?, ?, ?, 'DEMO', ?)`,
      newId('net'), orgId, pick(rng, databases).id, new Date(Date.now() - 35 * 60_000).toISOString(), nowIso(), batchId,
    );

    return { assets: assets.length, batchId };
  });

  // Detection and correlation run outside the insert transaction.
  const detected = evaluateRules(orgId, { dataOrigin: 'DEMO', demoBatchId: summary.batchId });
  const incidents = correlateDetections(orgId, { limit: 10 });
  refreshAssetRisk(orgId);

  const counts = {
    assets: summary.assets,
    events: get(`SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    detections: get(`SELECT COUNT(*) AS c FROM detections WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    incidents: get(`SELECT COUNT(*) AS c FROM incidents WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    vulnerabilities: get(`SELECT COUNT(*) AS c FROM vulnerabilities WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    networkEvents: get(`SELECT COUNT(*) AS c FROM network_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    newDetections: detected.length,
    newIncidents: incidents.length,
    incidentsBefore,
  };

  run(
    `INSERT INTO demo_runs (id, org_id, action, batch_id, counts, actor_id, created_at) VALUES (?, ?, 'generate', ?, ?, ?, ?)`,
    newId('drun'), orgId, batchId, JSON.stringify(counts), userId ?? null, nowIso(),
  );

  return { batchId, counts, detections: detected, incidents };
}

/** Delete only DEMO rows in this organization. Real and simulated data stay. */
export function resetDemoData({ orgId, userId }) {
  const before = {
    assets: get(`SELECT COUNT(*) AS c FROM assets WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    events: get(`SELECT COUNT(*) AS c FROM security_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    detections: get(`SELECT COUNT(*) AS c FROM detections WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    incidents: get(`SELECT COUNT(*) AS c FROM incidents WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    vulnerabilities: get(`SELECT COUNT(*) AS c FROM vulnerabilities WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
    networkEvents: get(`SELECT COUNT(*) AS c FROM network_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).c,
  };
  if (!before.events && !before.assets && !before.incidents) {
    return { deleted: before, nothingToDo: true };
  }

  transaction(() => {
    const incidentIds = all(`SELECT id FROM incidents WHERE org_id = ? AND data_origin = 'DEMO'`, orgId).map((row) => row.id);
    for (const id of incidentIds) run('DELETE FROM incident_events WHERE incident_id = ? AND org_id = ?', id, orgId);
    run(`DELETE FROM incidents WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
    run(`DELETE FROM detections WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
    run(`DELETE FROM security_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
    run(`DELETE FROM network_events WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
    run(`DELETE FROM vulnerabilities WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
    run(`DELETE FROM assets WHERE org_id = ? AND data_origin = 'DEMO'`, orgId);
  });

  run(
    `INSERT INTO demo_runs (id, org_id, action, batch_id, counts, actor_id, created_at) VALUES (?, ?, 'reset', NULL, ?, ?, ?)`,
    newId('drun'), orgId, JSON.stringify(before), userId ?? null, nowIso(),
  );
  return { deleted: before, nothingToDo: false };
}

/** Guard used by the scenario endpoints so only known simulation keys are run. */
export function assertDemoScenario(key, scenarios) {
  if (!scenarios.some((scenario) => scenario.key === key)) {
    throw badRequest('Unknown simulation scenario');
  }
  return key;
}
