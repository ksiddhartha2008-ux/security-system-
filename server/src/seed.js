import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { db, all, get, run, migrate, newId, nowIso, rootDir, transaction } from './db.js';
import { hashPassword } from './lib/auth.js';
import { ensureRules, evaluateRules, refreshAssetRisk } from './services/detection.js';
import { createSimulation, runToCompletionSync } from './services/simulation.js';
import { DEMO_ACCOUNTS } from './lib/demo.js';
import { buildReport } from './services/reports.js';

const minutesAgo = (m) => new Date(Date.now() - m * 60_000).toISOString();
const daysAgo = (d, h = 9) => {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() - d);
  date.setUTCHours(h, Math.floor(Math.random() * 59), 0, 0);
  return date.toISOString();
};

const DEMO_ORG = { id: 'org_meridian', name: 'Meridian Demo Workspace', slug: 'meridian-demo' };

const TABLES = [
  'custody_records', 'forensic_evidence', 'workflow_executions', 'response_workflows',
  'simulation_reports', 'simulation_events', 'simulation_agents', 'simulations',
  'reports', 'network_events', 'vulnerabilities', 'phishing_scans', 'intel_lookups',
  'iocs', 'investigation_notes', 'investigations', 'incident_events', 'incidents',
  'detections', 'detection_rules', 'security_events', 'assets', 'integration_configs',
  'audit_logs', 'login_attempts', 'sessions', 'users', 'organizations',
];

function reset() {
  db.exec('PRAGMA foreign_keys = OFF;');
  for (const table of TABLES) db.exec(`DELETE FROM ${table};`);
  db.exec('PRAGMA foreign_keys = ON;');
}

function seedOrg() {
  const ts = nowIso();
  run(
    `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at) VALUES (?, ?, ?, 'team', ?, ?, ?)`,
    DEMO_ORG.id, DEMO_ORG.name, DEMO_ORG.slug,
    JSON.stringify({ timezone: 'UTC', retentionDays: 90, demoMode: true, dataResidency: 'local' }), ts, ts,
  );
}

const USERS = DEMO_ACCOUNTS.map((account, index) => ({
  email: account.email,
  name: ['Priya Raman', 'Marcus Vale', 'Dana Okafor'][index] ?? account.role,
  role: account.email.startsWith('admin') ? 'admin' : account.email.startsWith('analyst') ? 'analyst' : 'viewer',
  password: account.password,
}));

function seedUsers() {
  const ts = nowIso();
  const ids = {};
  for (const user of USERS) {
    const id = newId('usr');
    run(
      `INSERT INTO users (id, org_id, email, name, password_hash, role, status, last_login_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
      id, DEMO_ORG.id, user.email, user.name, hashPassword(user.password), user.role, minutesAgo(35), ts, ts,
    );
    ids[user.role] = id;
  }
  return ids;
}

const ASSET_SEED = [
  { name: 'Production web front end', hostname: 'web-prod-01', ip: '10.20.1.11', os: 'Ubuntu 24.04 LTS', type: 'server', criticality: 'critical', owner: 'Platform', tags: ['pci', 'internet-facing'] },
  { name: 'API gateway', hostname: 'api-gw-02', ip: '10.20.1.12', os: 'Amazon Linux 2023', type: 'server', criticality: 'critical', owner: 'Platform', tags: ['pci', 'internet-facing'] },
  { name: 'Primary PostgreSQL', hostname: 'db-primary-01', ip: '10.20.2.21', os: 'Debian 12', type: 'database', criticality: 'critical', owner: 'Data', tags: ['pci', 'pii'] },
  { name: 'VPN concentrator', hostname: 'vpn-edge-01', ip: '10.20.1.5', os: 'FortiOS 7.4', type: 'network', criticality: 'high', owner: 'Network', tags: ['internet-facing'] },
  { name: 'Finance workstation', hostname: 'ws-fin-114', ip: '10.20.3.114', os: 'Windows 11 Enterprise', type: 'workstation', criticality: 'high', owner: 'Finance', tags: ['pii'] },
  { name: 'People operations workstation', hostname: 'ws-people-207', ip: '10.20.3.207', os: 'Windows 11 Enterprise', type: 'workstation', criticality: 'medium', owner: 'People', tags: ['pii'] },
  { name: 'Kubernetes worker 3', hostname: 'k8s-node-3', ip: '10.20.4.33', os: 'Flatcar 3975', type: 'container host', criticality: 'high', owner: 'Platform', tags: ['production'] },
  { name: 'Audit log bucket', hostname: 's3-audit-logs', ip: null, os: 'Object storage', type: 'cloud', criticality: 'high', owner: 'Security', tags: ['logs'] },
  { name: 'Mail relay', hostname: 'mail-relay-01', ip: '10.20.1.25', os: 'Postfix on Ubuntu 22.04', type: 'server', criticality: 'high', owner: 'IT', tags: ['email'] },
  { name: 'Build runner', hostname: 'build-runner-04', ip: '10.20.4.44', os: 'Ubuntu 24.04 LTS', type: 'server', criticality: 'medium', owner: 'Engineering', tags: ['ci'] },
  { name: 'Department file server', hostname: 'file-server-02', ip: '10.20.2.30', os: 'Windows Server 2022', type: 'server', criticality: 'high', owner: 'IT', tags: ['file-share'] },
  { name: 'Executive laptop', hostname: 'laptop-exec-01', ip: '10.20.5.9', os: 'macOS 15', type: 'workstation', criticality: 'high', owner: 'Executive', tags: ['byod'] },
  { name: 'Plant gateway', hostname: 'ot-gw-01', ip: '10.30.0.2', os: 'Siemens firmware', type: 'ot', criticality: 'critical', owner: 'Operations', tags: ['ot', 'isolated'] },
  { name: 'Print server', hostname: 'print-srv-02', ip: '10.20.2.55', os: 'Windows Server 2019', type: 'server', criticality: 'low', owner: 'IT', tags: [] },
];

function seedAssets() {
  const ts = nowIso();
  const ids = [];
  for (const a of ASSET_SEED) {
    const id = newId('ast');
    ids.push({ id, ...a });
    run(
      `INSERT INTO assets (id, org_id, name, hostname, ip_address, mac_address, os, asset_type, criticality, owner, risk_score, status, tags, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?)`,
      id, DEMO_ORG.id, a.name, a.hostname, a.ip, a.type === 'cloud' ? null : `00:1a:${Math.floor(Math.random() * 90 + 10)}:${Math.floor(Math.random() * 90 + 10)}:${Math.floor(Math.random() * 90 + 10)}:${Math.floor(Math.random() * 90 + 10)}`,
      a.os, a.type, a.criticality, a.owner, 0, JSON.stringify(a.tags), minutesAgo(Math.floor(Math.random() * 30)), ts, ts,
    );
  }
  return ids;
}

const EVENT_TEMPLATES = [
  { type: 'auth.success', source: 'identity-provider', severity: 'info', category: 'identity', title: 'Successful sign-in', weight: 22 },
  { type: 'auth.failure', source: 'identity-provider', severity: 'low', category: 'identity', title: 'Failed sign-in attempt', weight: 18 },
  { type: 'auth.mfa_challenge', source: 'identity-provider', severity: 'info', category: 'identity', title: 'MFA challenge issued', weight: 8 },
  { type: 'endpoint.process_start', source: 'sysmon', severity: 'info', category: 'endpoint', title: 'Process started', weight: 14 },
  { type: 'endpoint.usb_mount', source: 'sysmon', severity: 'low', category: 'endpoint', title: 'Removable media mounted', weight: 3 },
  { type: 'email.received', source: 'mail-gateway', severity: 'info', category: 'email', title: 'Message delivered', weight: 12 },
  { type: 'email.click', source: 'mail-gateway', severity: 'medium', category: 'email', title: 'Recipient clicked a rewritten link', weight: 2 },
  { type: 'api.request', source: 'api-gateway', severity: 'info', category: 'application', title: 'API request', weight: 16 },
  { type: 'authz.denied', source: 'application', severity: 'low', category: 'application', title: 'Authorization denied', weight: 3 },
  { type: 'network.connection', source: 'suricata', severity: 'info', category: 'network', title: 'Outbound connection allowed', weight: 15 },
  { type: 'file.access', source: 'edr', severity: 'info', category: 'endpoint', title: 'File accessed', weight: 8 },
  { type: 'vulnerability.detected', source: 'scanner-import', severity: 'medium', category: 'vulnerability', title: 'Vulnerability reported by scanner import', weight: 2 },
];

function pickWeighted(rng) {
  const total = EVENT_TEMPLATES.reduce((s, t) => s + t.weight, 0);
  let roll = rng() * total;
  for (const t of EVENT_TEMPLATES) {
    roll -= t.weight;
    if (roll <= 0) return t;
  }
  return EVENT_TEMPLATES[0];
}

function eventRow(e) {
  run(
    `INSERT INTO security_events (id, org_id, event_type, source, severity, category, title, description, src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('evt'), DEMO_ORG.id, e.type, e.source, e.severity, e.category, e.title, e.description ?? null,
    e.srcIp ?? null, e.destIp ?? null, e.userEmail ?? null, e.assetId ?? null,
    JSON.stringify({ synthetic: true, seeded: true, ...(e.raw ?? {}) }), e.status ?? 'new', e.occurredAt, nowIso(),
  );
}

function seedEvents(assets) {
  const ts = nowIso();
  const rng = (() => { let s = 42; return () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; }; })();
  const ips = ['10.20.3.114', '10.20.3.207', '10.20.4.44', '10.20.5.9', '10.20.1.11', '10.20.2.21'];
  const users = ['j.reyes@meridian.demo', 'a.miller@meridian.demo', 's.patel@meridian.demo', 'l.chen@meridian.demo', 'm.vale@meridian.demo'];
  const external = ['203.0.113.44', '198.51.100.23', '192.0.2.77', '198.51.100.90'];

  // Historical background, 14 days
  for (let i = 0; i < 190; i += 1) {
    const t = pickWeighted(rng);
    const day = Math.floor(rng() * 14);
    eventRow({
      type: t.type, source: t.source, severity: t.severity, category: t.category, title: t.title,
      description: `${t.title} recorded by ${t.source}.`,
      srcIp: rng() < 0.5 ? ips[Math.floor(rng() * ips.length)] : external[Math.floor(rng() * external.length)],
      destIp: '10.20.1.12',
      userEmail: rng() < 0.6 ? users[Math.floor(rng() * users.length)] : null,
      assetId: assets[Math.floor(rng() * assets.length)].id,
      occurredAt: daysAgo(day, 6 + Math.floor(rng() * 14)),
      status: rng() < 0.3 ? 'closed' : 'new',
    });
  }

  // Live window bursts that the deterministic rules can see
  for (let i = 0; i < 14; i += 1) {
    eventRow({
      type: 'auth.failure', source: 'identity-provider', severity: 'low', category: 'identity',
      title: 'Failed sign-in attempt',
      description: 'Password rejected for a valid account name.',
      srcIp: '203.0.113.44', destIp: '10.20.1.11',
      userEmail: users[i % 4], assetId: assets[0].id,
      occurredAt: minutesAgo(6 - (i % 6) * 0.6),
    });
  }
  for (let i = 0; i < 62; i += 1) {
    eventRow({
      type: 'api.request', source: 'api-gateway', severity: i % 9 === 0 ? 'medium' : 'info', category: 'application',
      title: 'API request to /v1/customers/{id}',
      description: 'Sequential identifier requested by a single client.',
      srcIp: '198.51.100.23', destIp: '10.20.1.12', userEmail: null, assetId: assets[1].id,
      occurredAt: minutesAgo(4 - (i % 4) * 0.05),
      raw: { endpoint: '/v1/customers/{id}', statusCode: i % 7 === 0 ? 429 : 200 },
    });
  }
  for (let i = 0; i < 6; i += 1) {
    eventRow({
      type: 'authz.denied', source: 'application', severity: 'low', category: 'application',
      title: 'Authorization denied', description: 'Role viewer attempted a write operation on assets.',
      srcIp: '10.20.3.207', userEmail: 's.patel@meridian.demo', assetId: assets[5].id,
      occurredAt: minutesAgo(5 - i * 0.4),
    });
  }
  eventRow({
    type: 'process.shadow_copy_delete', source: 'sysmon', severity: 'critical', category: 'endpoint',
    title: 'Shadow copies deleted on ws-fin-114',
    description: 'vssadmin delete shadows /all /quiet executed by an unsigned parent process.',
    srcIp: '10.20.3.114', userEmail: 'j.reyes@meridian.demo', assetId: assets[4].id, occurredAt: minutesAgo(12),
    raw: { commandLine: 'vssadmin delete shadows /all /quiet', parent: 'invoice_2026.exe' },
  });
  eventRow({
    type: 'file.encrypt', source: 'edr', severity: 'critical', category: 'endpoint',
    title: 'Mass file rename with .locked extension',
    description: '214 files renamed in 90 seconds on the mapped finance share.',
    srcIp: '10.20.3.114', assetId: assets[10].id, occurredAt: minutesAgo(11),
    raw: { files: 214, extension: '.locked' },
  });
  eventRow({
    type: 'email.click', source: 'mail-gateway', severity: 'high', category: 'email',
    title: 'Rewritten payroll link clicked',
    description: 'Recipient opened a lookalike payroll domain registered two days ago.',
    srcIp: '10.20.3.114', userEmail: 'a.miller@meridian.demo', assetId: assets[4].id, occurredAt: minutesAgo(20),
  });
  eventRow({
    type: 'auth.success', source: 'identity-provider', severity: 'high', category: 'identity',
    title: 'Sign-in from an unusual country',
    description: 'Successful sign-in from an address never seen for this account.',
    srcIp: '203.0.113.44', userEmail: 'l.chen@meridian.demo', assetId: assets[0].id, occurredAt: minutesAgo(3),
  });
}

function seedNetwork(assets) {
  const rng = (() => { let s = 7; return () => { s = (s * 48271) % 2147483647; return s / 2147483647; }; })();
  const internal = ['10.20.1.11', '10.20.1.12', '10.20.2.21', '10.20.3.114', '10.20.3.207', '10.20.4.44'];
  const external = ['198.51.100.23', '203.0.113.44', '192.0.2.77', '198.51.100.90', '192.0.2.10'];
  const protocols = ['TCP', 'TCP', 'TCP', 'UDP', 'TLS'];
  for (let i = 0; i < 150; i += 1) {
    run(
      `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      newId('net'), DEMO_ORG.id, internal[Math.floor(rng() * internal.length)], 30000 + Math.floor(rng() * 30000),
      external[Math.floor(rng() * external.length)], [443, 80, 22, 53, 8080][Math.floor(rng() * 5)],
      protocols[Math.floor(rng() * protocols.length)], Math.floor(rng() * 2_000_000), Math.floor(rng() * 5_000_000),
      rng() < 0.7 ? 'outbound' : 'inbound', rng() < 0.08 ? 'suspicious' : 'allowed',
      assets[Math.floor(rng() * assets.length)].id,
      daysAgo(Math.floor(rng() * 10), 7 + Math.floor(rng() * 12)), nowIso(),
    );
  }
  // Port scan window: 18 distinct ports from one source in the last 8 minutes
  for (let i = 0; i < 18; i += 1) {
    run(
      `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'TCP', 64, 0, 'inbound', 'suspicious', ?, ?, ?)`,
      newId('net'), DEMO_ORG.id, '192.0.2.77', 41000 + i, '10.20.1.5', 20 + i * 3, assets[3].id, minutesAgo(8 - i * 0.3), nowIso(),
    );
  }
  // Bulk outbound transfer
  run(
    `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at)
     VALUES (?, ?, '10.20.2.30', 51544, '198.51.100.90', 443, 'TLS', 92405760, 2048, 'outbound', 'suspicious', ?, ?, ?)`,
    newId('net'), DEMO_ORG.id, assets[10].id, minutesAgo(35), nowIso(),
  );
}

function seedIocs() {
  const rows = [
    { type: 'ip', value: '203.0.113.44', threat: 'credential stuffing', confidence: 88, source: 'simulation', description: 'Source used in the credential stuffing simulation run.' },
    { type: 'ip', value: '192.0.2.77', threat: 'port scanning', confidence: 74, source: 'suricata', description: 'Sequential port sweep against the VPN edge.' },
    { type: 'ip', value: '198.51.100.90', threat: 'data exfiltration', confidence: 81, source: 'netflow', description: 'Destination of a 88 MB outbound transfer.' },
    { type: 'domain', value: 'payroll-verify.example', threat: 'phishing', confidence: 91, source: 'mail-gateway', description: 'Lookalike payroll domain registered two days ago.' },
    { type: 'domain', value: 'cdn-update.example', threat: 'malware distribution', confidence: 66, source: 'osint-feed', description: 'Hosts a loader payload in the same campaign.' },
    { type: 'url', value: 'https://payroll-verify.example/login', threat: 'phishing', confidence: 93, source: 'mail-gateway', description: 'Credential capture page used in the payroll campaign.' },
    { type: 'sha256', value: '9f2c1c0b7d4a5e6f8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f7', threat: 'ransomware', confidence: 95, source: 'edr', description: 'Loader dropped on the finance workstation.' },
    { type: 'sha256', value: '3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b', threat: 'trojan', confidence: 70, source: 'osint-feed', description: 'Signed installer abused for proxy execution.' },
    { type: 'email', value: 'payroll@payroll-verify.example', threat: 'phishing', confidence: 84, source: 'mail-gateway', description: 'Sender address of the payroll campaign.' },
    { type: 'ip', value: '198.51.100.23', threat: 'api abuse', confidence: 62, source: 'api-gateway', description: 'Client enumerating customer identifiers.' },
    { type: 'domain', value: 'invoice-share.example', threat: 'phishing', confidence: 55, source: 'manual', description: 'Reported by a user, awaiting enrichment.' },
    { type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e', threat: 'unknown', confidence: 20, source: 'manual', description: 'Placeholder hash captured during triage.' },
  ];
  for (const r of rows) {
    run(
      `INSERT INTO iocs (id, org_id, type, value, threat_type, confidence, source, description, status, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
      newId('ioc'), DEMO_ORG.id, r.type, r.value, r.threat, r.confidence, r.source, r.description, minutesAgo(90), nowIso(), nowIso(),
    );
  }
}

function seedVulnerabilities(assets) {
  const rows = [
    { cve: 'CVE-2021-44228', title: 'Apache Log4j2 JNDI remote code execution', severity: 'critical', cvss: 10.0, asset: 1, status: 'in_progress', remediation: 'Upgrade log4j-core to 2.17.1 and rebuild the gateway image.' },
    { cve: 'CVE-2024-3400', title: 'PAN-OS GlobalProtect command injection', severity: 'critical', cvss: 10.0, asset: 3, status: 'open', remediation: 'Apply the vendor hotfix and rotate device credentials.' },
    { cve: 'CVE-2023-4966', title: 'Citrix NetScaler session token disclosure', severity: 'critical', cvss: 9.4, asset: 3, status: 'in_progress', remediation: 'Patch and invalidate all active sessions.' },
    { cve: 'CVE-2023-34362', title: 'MOVEit Transfer SQL injection', severity: 'critical', cvss: 9.8, asset: 10, status: 'remediated', remediation: 'Patched to 2023.0.1 and reviewed transfer logs.' },
    { cve: 'CVE-2022-22965', title: 'Spring Framework remote code execution', severity: 'critical', cvss: 9.8, asset: 1, status: 'remediated', remediation: 'Framework upgraded; WAR deployments converted to the embedded server.' },
    { cve: 'CVE-2020-1472', title: 'Netlogon elevation of privilege (Zerologon)', severity: 'critical', cvss: 10.0, asset: 6, status: 'open', remediation: 'Enforce secure RPC and patch domain controllers.' },
    { cve: 'CVE-2021-34527', title: 'Windows Print Spooler remote code execution', severity: 'high', cvss: 8.8, asset: 13, status: 'open', remediation: 'Disable the spooler on servers that do not print.' },
    { cve: 'CVE-2024-6387', title: 'OpenSSH signal handler race condition (regreSSHion)', severity: 'high', cvss: 8.1, asset: 2, status: 'in_progress', remediation: 'Upgrade OpenSSH and restrict exposure to the management network.' },
    { cve: 'CVE-2023-44487', title: 'HTTP/2 rapid reset denial of service', severity: 'high', cvss: 7.5, asset: 0, status: 'remediated', remediation: 'Rate limits applied at the edge and server updated.' },
    { cve: 'CVE-2024-21762', title: 'FortiOS out-of-bounds write', severity: 'critical', cvss: 9.8, asset: 3, status: 'in_progress', remediation: 'Vendor update scheduled in the next maintenance window.' },
    { cve: 'CVE-2022-1388', title: 'F5 iControl REST authentication bypass', severity: 'critical', cvss: 9.8, asset: 1, status: 'accepted', remediation: 'Compensating control: management interface restricted to the bastion.' },
    { cve: 'CVE-2019-0708', title: 'Remote Desktop Services remote code execution', severity: 'critical', cvss: 9.8, asset: 13, status: 'open', remediation: 'Network level authentication enforced; patch pending reboot.' },
  ];
  for (const r of rows) {
    run(
      `INSERT INTO vulnerabilities (id, org_id, cve_id, title, description, severity, cvss, asset_id, status, remediation, due_at, discovered_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      newId('vuln'), DEMO_ORG.id, r.cve, r.title, `${r.title}. Tracked from a scanner import and triaged by the security team.`,
      r.severity, r.cvss, assets[r.asset]?.id ?? null, r.status, r.remediation,
      daysAgo(-14, 12), daysAgo(21 + Math.floor(Math.random() * 30), 10), nowIso(), nowIso(),
    );
  }
}

function seedIncidents(users, assets) {
  const rows = [
    { title: 'Ransomware behaviour on finance workstation', severity: 'critical', priority: 'P1', status: 'investigating', assignee: 'analyst', desc: 'Shadow copy deletion followed by mass file rename on ws-fin-114. Host isolated, restore from immutable backup prepared.' },
    { title: 'Credential stuffing against the sign-in service', severity: 'high', priority: 'P2', status: 'contained', assignee: 'admin', desc: 'Fourteen failed sign-ins across four accounts from 203.0.113.44. Source blocked at the edge, affected sessions revoked.' },
    { title: 'API enumeration of customer identifiers', severity: 'medium', priority: 'P3', status: 'open', assignee: 'analyst', desc: 'A single client requested 62 sequential customer records in four minutes, bypassing pagination hints.' },
    { title: 'Payroll phishing campaign reported by staff', severity: 'high', priority: 'P2', status: 'investigating', assignee: 'analyst', desc: 'Lookalike domain registered two days before delivery. One credential submission reported; reset completed.' },
    { title: 'Port sweep against VPN concentrator', severity: 'medium', priority: 'P3', status: 'resolved', assignee: 'admin', desc: 'Eighteen ports probed from 192.0.2.77. Source blocked, no successful session observed.' },
    { title: 'Bulk export by a departing employee', severity: 'high', priority: 'P2', status: 'investigating', assignee: 'analyst', desc: 'Four hundred customer rows exported over three sessions, one write to removable media. Access review opened with HR.' },
    { title: 'Unpatched Log4j in the API gateway image', severity: 'critical', priority: 'P2', status: 'contained', assignee: 'admin', desc: 'Image rebuild completed; deployment to production scheduled. Edge rules block JNDI payloads in the meantime.' },
    { title: 'Repeated authorization denials from a viewer account', severity: 'low', priority: 'P4', status: 'closed', assignee: 'admin', desc: 'A viewer used an old bookmark to a write endpoint. Explained and closed without further action.' },
  ];
  const ids = [];
  rows.forEach((r, index) => {
    const id = newId('inc');
    ids.push(id);
    const detected = daysAgo(Math.min(9, index + (index > 4 ? 1 : 0)), 8 + index);
    run(
      `INSERT INTO incidents (id, org_id, ref, title, description, severity, priority, status, assignee_id, created_by, detected_at, due_at, resolved_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id, DEMO_ORG.id, `INC-2026-${1001 + index}`, r.title, r.desc, r.severity, r.priority, r.status,
      users[r.assignee], users.admin, detected, daysAgo(-3, 18),
      ['resolved', 'closed'].includes(r.status) ? daysAgo(Math.max(0, 6 - index), 16) : null, detected, nowIso(),
    );
    const timeline = [
      { type: 'created', message: `Incident opened from a ${r.severity} detection.` },
      { type: 'assignment', message: `Assigned to ${r.assignee === 'analyst' ? 'Marcus Vale' : 'Priya Raman'}.` },
    ];
    if (['investigating', 'contained', 'resolved', 'closed'].includes(r.status)) timeline.push({ type: 'note', message: 'Initial triage complete. Evidence collected from endpoint and network telemetry.' });
    if (['contained', 'resolved', 'closed'].includes(r.status)) timeline.push({ type: 'status', message: 'Status changed to contained after the affected host was isolated.' });
    if (['resolved', 'closed'].includes(r.status)) timeline.push({ type: 'status', message: 'Resolution recorded: control applied and verified.' });
    timeline.forEach((t, i) => {
      run(
        `INSERT INTO incident_events (id, org_id, incident_id, type, message, actor_id, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?, '{}', ?)`,
        newId('ince'), DEMO_ORG.id, id, t.type, t.message, users[i === 0 ? 'admin' : 'analyst'], minutesAgo(600 - index * 20 - i * 5),
      );
    });
  });
  return ids;
}

function seedInvestigations(users, incidents) {
  const rows = [
    { title: 'How did the ransomware loader reach ws-fin-114?', hypothesis: 'A signed installer delivered the loader after a user opened an invoice attachment.', severity: 'critical', incident: 0 },
    { title: 'Is the payroll domain linked to earlier campaigns?', hypothesis: 'The lookalike domain shares infrastructure with the invoice campaign seen last month.', severity: 'high', incident: 3 },
    { title: 'Scope of the customer identifier enumeration', hypothesis: 'The client harvested fewer than 200 records before the quota took effect.', severity: 'medium', incident: 2 },
    { title: 'Departing employee data movement', hypothesis: 'The export was copied to removable media but not transferred externally.', severity: 'high', incident: 5 },
  ];
  const ids = [];
  rows.forEach((r, i) => {
    const id = newId('inv');
    ids.push(id);
    run(
      `INSERT INTO investigations (id, org_id, ref, title, hypothesis, status, severity, owner_id, incident_id, findings, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id, DEMO_ORG.id, `INV-2026-${201 + i}`, r.title, r.hypothesis, i === 3 ? 'active' : i === 2 ? 'concluded' : 'active',
      r.severity, users.analyst, incidents[r.incident] ?? null,
      i === 2 ? 'Enumeration stopped at 62 requests. No evidence of data retrieval beyond the first page.' : '',
      daysAgo(3 + i, 10), nowIso(),
    );
    const notes = [
      'Pulled the last 24 hours of telemetry for the affected asset and correlated it with the detection timeline.',
      i === 2 ? 'Confirmed the client received 429 responses after the quota was applied.' : 'Requested the mailbox export for the affected user and queued it for review.',
    ];
    notes.forEach((body, n) => {
      run(
        `INSERT INTO investigation_notes (id, org_id, investigation_id, author_id, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
        newId('note'), DEMO_ORG.id, id, users.analyst, body, minutesAgo(300 - i * 10 - n * 3),
      );
    });
  });
  return ids;
}

function seedHistoricalDetections(assets) {
  const rows = [
    { title: 'Repeated authentication failures from 198.51.100.23', severity: 'medium', risk: 58, status: 'confirmed', days: 4 },
    { title: 'Outbound transfer above baseline to an unknown host', severity: 'high', risk: 76, status: 'confirmed', days: 6 },
    { title: 'Suspicious PowerShell encoded command', severity: 'medium', risk: 61, status: 'false_positive', days: 8, note: 'Signed administrative script from the IT automation account.' },
    { title: 'Mailbox rule created to forward external mail', severity: 'high', risk: 72, status: 'confirmed', days: 9 },
    { title: 'Unusual service account interactive logon', severity: 'low', risk: 34, status: 'closed', days: 11 },
  ];
  rows.forEach((r, i) => {
    const detected = daysAgo(r.days, 11);
    run(
      `INSERT INTO detections (id, org_id, rule_id, event_id, asset_id, title, description, severity, risk_score, confidence, status, explanation, detected_at, created_at, updated_at)
       VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, 72, ?, ?, ?, ?, ?)`,
      newId('det'), DEMO_ORG.id, assets[i % assets.length].id, r.title,
      r.note ? `Analyst feedback: ${r.note}` : 'Matched a deterministic rule during the historical replay.',
      r.severity, r.risk, r.status,
      JSON.stringify({ ruleKey: 'historical-replay', factors: [{ label: 'Historical replay', weight: 20, detail: 'recorded before this workspace was reset' }], deterministic: true }),
      detected, detected, nowIso(),
    );
  });
}

function seedWorkflows(users, incidents) {
  const workflows = [
    { name: 'Isolate host on critical ransomware detection', trigger: 'detection.ransomware', actions: [{ type: 'isolate_host', target: 'detection.asset' }, { type: 'open_incident', severity: 'critical' }, { type: 'notify', channel: 'security-oncall' }], approval: 1 },
    { name: 'Block source IP after credential stuffing', trigger: 'detection.credential_stuffing', actions: [{ type: 'block_ip', target: 'detection.srcIp' }, { type: 'notify', channel: 'identity-team' }], approval: 0 },
    { name: 'Disable account on confirmed phishing submission', trigger: 'detection.phishing', actions: [{ type: 'disable_user', target: 'detection.user' }, { type: 'force_password_reset', target: 'detection.user' }, { type: 'notify', channel: 'helpdesk' }], approval: 1 },
    { name: 'Quarantine asset with unpatched critical CVE', trigger: 'vulnerability.critical', actions: [{ type: 'tag_asset', target: 'vulnerability.asset' }, { type: 'open_ticket', queue: 'patch-management' }], approval: 0 },
  ];
  const ids = [];
  for (const w of workflows) {
    const id = newId('wf');
    ids.push(id);
    run(
      `INSERT INTO response_workflows (id, org_id, name, description, trigger_type, trigger_config, actions, requires_approval, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
      id, DEMO_ORG.id, w.name, 'Simulated response actions. Actions are recorded, not executed against production systems.',
      w.trigger, JSON.stringify({}), JSON.stringify(w.actions), w.approval, nowIso(), nowIso(),
    );
  }
  const executions = [
    { wf: 0, status: 'completed', incident: incidents[0], log: [
      { step: 1, action: 'isolate_host', status: 'simulated', detail: 'Isolation recorded for ws-fin-114. No endpoint integration is configured.' },
      { step: 2, action: 'open_incident', status: 'completed', detail: 'Incident INC-2026-1001 linked.' },
      { step: 3, action: 'notify', status: 'simulated', detail: 'Notification would be sent to security-oncall.' },
    ] },
    { wf: 1, status: 'completed', incident: incidents[1], log: [
      { step: 1, action: 'block_ip', status: 'simulated', detail: 'Block recorded for 203.0.113.44. No firewall integration is configured.' },
      { step: 2, action: 'notify', status: 'simulated', detail: 'Notification would be sent to identity-team.' },
    ] },
    { wf: 2, status: 'pending_approval', incident: incidents[3], log: [
      { step: 1, action: 'disable_user', status: 'awaiting_approval', detail: 'Requires approval before touching an identity account.' },
    ] },
  ];
  for (const e of executions) {
    run(
      `INSERT INTO workflow_executions (id, org_id, workflow_id, incident_id, status, current_step, log, started_by, approved_by, started_at, finished_at, error, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      newId('wfx'), DEMO_ORG.id, ids[e.wf], e.incident ?? null, e.status, e.log.length,
      JSON.stringify(e.log), users.admin, e.status === 'completed' ? users.admin : null,
      minutesAgo(400), e.status === 'completed' ? minutesAgo(398) : null, minutesAgo(400),
    );
  }
}

function seedEvidence(users) {
  const dir = join(rootDir, 'data', 'evidence');
  mkdirSync(dir, { recursive: true });
  const files = [
    { name: 'ws-fin-114-memory-note.txt', desc: 'Analyst note describing volatile memory capture on the isolated workstation.', content: 'Volatile memory capture requested for ws-fin-114 at 09:14 UTC. Capture performed with the approved tool. Hash recorded before transfer.' },
    { name: 'mail-gateway-phishing-headers.txt', desc: 'Sanitised message headers from the reported payroll phishing campaign.', content: 'From: payroll@payroll-verify.example\nReply-To: payroll@payroll-verify.example\nSubject: Action required: payroll details\nReceived: from unknown (198.51.100.23)\nAuthentication-Results: spf=fail dkim=none dmarc=fail' },
    { name: 'api-gateway-access-log-excerpt.txt', desc: 'Excerpt of gateway access logs covering the enumeration window.', content: 'GET /v1/customers/1042 200\nGET /v1/customers/1043 200\nGET /v1/customers/1044 200\nGET /v1/customers/1045 429\nGET /v1/customers/1046 429' },
    { name: 'file-server-02-share-listing.txt', desc: 'Directory listing captured after containment on the finance share.', content: 'share\\finance\\invoices\nshare\\finance\\reports\nshare\\finance\\budget-2027.xlsx.locked\nshare\\finance\\payroll-q4.xlsx.locked' },
  ];
  for (const f of files) {
    const id = newId('evi');
    const buffer = Buffer.from(f.content, 'utf8');
    const sha = createHash('sha256').update(buffer).digest('hex');
    const storage = join(dir, `${id}-${f.name}`);
    writeFileSync(storage, buffer);
    run(
      `INSERT INTO forensic_evidence (id, org_id, case_ref, filename, description, mime_type, size_bytes, sha256, storage_path, collected_from, collected_by, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'text/plain', ?, ?, ?, ?, ?, 'sealed', ?)`,
      id, DEMO_ORG.id, 'CASE-2026-014', f.name, f.desc, buffer.length, sha, storage, 'meridian-demo', users.analyst, daysAgo(2, 9),
    );
    run(
      `INSERT INTO custody_records (id, org_id, evidence_id, action, actor_id, note, hash_at_action, created_at)
       VALUES (?, ?, ?, 'collected', ?, 'Initial collection, hash computed on intake.', ?, ?)`,
      newId('cus'), DEMO_ORG.id, id, users.analyst, sha, daysAgo(2, 9),
    );
  }
}

function seedIntegrations() {
  const env = process.env;
  const defs = [
    { key: 'wazuh', name: 'Wazuh', category: 'siem', configured: Boolean(env.WAZUH_API_URL) },
    { key: 'sysmon', name: 'Sysmon', category: 'endpoint', configured: Boolean(env.SYSMON_COLLECTOR_URL) },
    { key: 'suricata', name: 'Suricata', category: 'network', configured: Boolean(env.SURICATA_EVE_PATH) },
    { key: 'zeek', name: 'Zeek', category: 'network', configured: Boolean(env.ZEEK_LOG_PATH) },
    { key: 'clamav', name: 'ClamAV', category: 'malware', configured: Boolean(env.CLAMAV_HOST) },
    { key: 'yara', name: 'YARA', category: 'malware', configured: Boolean(env.YARA_RULES_PATH) },
    { key: 'virustotal', name: 'VirusTotal', category: 'threat-intel', configured: Boolean(env.VIRUSTOTAL_API_KEY) },
    { key: 'abuseipdb', name: 'AbuseIPDB', category: 'threat-intel', configured: Boolean(env.ABUSEIPDB_API_KEY) },
    { key: 'mirofish', name: 'MiroFish', category: 'simulation', configured: Boolean(env.MIROFISH_BASE_URL) },
    { key: 'api-anything', name: 'API Anything', category: 'developer-tool', configured: Boolean(env.API_ANYTHING_ENABLED === 'true') },
  ];
  for (const d of defs) {
    run(
      `INSERT INTO integration_configs (id, org_id, key, name, category, status, config, last_sync_at, last_error, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, '{}', NULL, NULL, ?, ?)`,
      newId('int'), DEMO_ORG.id, d.key, d.name, d.category, d.configured ? 'configured' : 'unconfigured', nowIso(), nowIso(),
    );
  }
}

function seedAudit(users) {
  const rows = [
    { action: 'organization.created', resource: 'organization', id: DEMO_ORG.id, actor: 'admin' },
    { action: 'user.registered', resource: 'user', id: users.admin, actor: 'admin' },
    { action: 'detection.rule.enabled', resource: 'detection_rule', id: 'credential-stuffing', actor: 'admin' },
    { action: 'incident.created', resource: 'incident', id: 'INC-2026-1001', actor: 'analyst' },
    { action: 'simulation.completed', resource: 'simulation', id: 'SIM-2026-1001', actor: 'analyst' },
  ];
  rows.forEach((r, i) => {
    run(
      `INSERT INTO audit_logs (id, org_id, actor_id, actor_email, action, resource_type, resource_id, ip, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, '127.0.0.1', '{}', ?)`,
      newId('aud'), DEMO_ORG.id, users[r.actor], USERS.find((u) => u.role === r.actor)?.email ?? 'system',
      r.action, r.resource, r.id, minutesAgo(120 - i * 5),
    );
  });
}

export function seed({ force = process.argv.includes('--force') } = {}) {
  migrate();
  const existing = get('SELECT id FROM organizations WHERE id = ?', DEMO_ORG.id);
  if (existing && !force) {
    console.log('[seed] demo workspace already present, nothing to do');
    return { seeded: false };
  }
  if (existing) reset();

  transaction(() => {
    seedOrg();
  });
  const users = seedUsers();
  const assets = seedAssets();
  ensureRules(DEMO_ORG.id);
  seedEvents(assets);
  seedNetwork(assets);
  seedIocs();
  seedVulnerabilities(assets);
  const incidents = seedIncidents(users, assets);
  seedInvestigations(users, incidents);
  seedHistoricalDetections(assets);
  seedWorkflows(users, incidents);
  seedEvidence(users);
  seedIntegrations();
  seedAudit(users);

  // Everything created by the demo seeder is demo data with its own batch id.
  for (const table of ['assets', 'security_events', 'incidents', 'vulnerabilities', 'network_events']) {
    run(`UPDATE ${table} SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = ?`, DEMO_ORG.id);
  }

  const produced = evaluateRules(DEMO_ORG.id, { dataOrigin: 'DEMO', demoBatchId: 'seed-v1' });
  refreshAssetRisk(DEMO_ORG.id);

  // Two genuinely executed simulation runs plus one draft.
  for (const [scenario, seedValue] of [['credential-stuffing', 20261108], ['ransomware', 771903]]) {
    const sim = createSimulation(DEMO_ORG.id, users.analyst, {
      scenario, seed: seedValue, totalRounds: 8,
      name: `${scenario.replace('-', ' ')} rehearsal`,
    });
    runToCompletionSync(DEMO_ORG.id, sim.id);
  }
  createSimulation(DEMO_ORG.id, users.admin, {
    scenario: 'phishing', seed: 88123, totalRounds: 7, name: 'Phishing readiness check (draft)',
  });

  // Reports built from the data that now exists.
  for (const type of ['executive', 'simulations']) {
    const report = buildReport(DEMO_ORG.id, type, {});
    run(
      `INSERT INTO reports (id, org_id, type, title, params, status, summary, body_md, generated_by, created_at)
       VALUES (?, ?, ?, ?, '{}', 'ready', ?, ?, ?, ?)`,
      newId('rpt'), DEMO_ORG.id, type, report.title, JSON.stringify(report.summary), report.body_md, users.admin, nowIso(),
    );
  }

  const counts = {
    assets: all('SELECT COUNT(*) c FROM assets WHERE org_id = ?', DEMO_ORG.id)[0].c,
    events: all('SELECT COUNT(*) c FROM security_events WHERE org_id = ?', DEMO_ORG.id)[0].c,
    detections: all('SELECT COUNT(*) c FROM detections WHERE org_id = ?', DEMO_ORG.id)[0].c,
    incidents: all('SELECT COUNT(*) c FROM incidents WHERE org_id = ?', DEMO_ORG.id)[0].c,
  };
  console.log('[seed] demo workspace ready', counts, 'new detections:', produced.length);
  return { seeded: true, counts, detections: produced.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  seed({ force: process.argv.includes('--force') });
}

export { DEMO_ORG, USERS };
