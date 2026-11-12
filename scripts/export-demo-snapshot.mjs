#!/usr/bin/env node
/**
 * Build a sanitized demo database snapshot.
 *
 * Source: backend/data/secureflow.db (never modified)
 * Output: demo/secureflow-demo.db
 *
 * The snapshot keeps only the Meridian demo workspace and removes every
 * session, login attempt, MFA challenge, audit row, website key and evidence
 * record. It refuses to finish if a non-demo user or organization remains.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const root = process.cwd();
const source = process.env.SF_DB_PATH || join(root, 'backend', 'data', 'secureflow.db');
const output = join(root, 'demo', 'secureflow-demo.db');
const DEMO_ORG = 'org_meridian';

if (!existsSync(source)) {
  console.error(`Source database not found: ${source}`);
  process.exit(1);
}
mkdirSync(dirname(output), { recursive: true });
if (existsSync(output)) {
  console.error(`Refusing to overwrite ${output}. Remove it first.`);
  process.exit(1);
}

const db = new DatabaseSync(source);
const escaped = resolve(output).replace(/'/g, "''").replace(/\\/g, '/');
db.exec(`VACUUM INTO '${escaped}'`);
db.close();

const snap = new DatabaseSync(output);
snap.exec('PRAGMA foreign_keys = OFF;');
snap.exec('BEGIN IMMEDIATE;');

const tables = snap.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map((row) => row.name);
const orgTables = [];
for (const table of tables) {
  const columns = snap.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
  if (columns.includes('org_id')) orgTables.push(table);
}

for (const table of orgTables) {
  snap.prepare(`DELETE FROM ${table} WHERE org_id != ?`).run(DEMO_ORG);
}

for (const table of ['sessions', 'login_attempts', 'mfa_challenges', 'audit_logs', 'site_api_keys', 'forensic_evidence', 'custody_records']) {
  if (tables.includes(table)) snap.exec(`DELETE FROM ${table};`);
}

snap.prepare('DELETE FROM users WHERE org_id != ?').run(DEMO_ORG);
snap.prepare('DELETE FROM organizations WHERE id != ?').run(DEMO_ORG);

// Rows that carry a site but not an org id.
for (const table of ['website_usage']) {
  if (tables.includes(table)) {
    snap.exec(`DELETE FROM ${table} WHERE site_id NOT IN (SELECT id FROM website_sites);`);
  }
}

snap.exec('COMMIT;');
snap.exec('PRAGMA foreign_keys = ON;');

const failures = [];
const scalar = (sql, ...params) => snap.prepare(sql).get(...params)?.c ?? 0;
if (scalar('SELECT COUNT(*) AS c FROM organizations') !== 1) failures.push('more than one organization remains');
if (scalar('SELECT COUNT(*) AS c FROM users WHERE org_id != ?', DEMO_ORG) !== 0) failures.push('a non-demo user remains');
if (scalar('SELECT COUNT(*) AS c FROM users WHERE email NOT LIKE ?', '%@secureflow.dev') !== 0) failures.push('a non-demo email remains');
for (const table of ['sessions', 'login_attempts', 'mfa_challenges', 'audit_logs', 'site_api_keys', 'forensic_evidence', 'custody_records']) {
  if (tables.includes(table) && scalar(`SELECT COUNT(*) AS c FROM ${table}`) !== 0) failures.push(`${table} is not empty`);
}

if (failures.length) {
  snap.close();
  console.error('Snapshot failed validation:');
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}

const counts = {};
for (const table of ['organizations', 'users', 'assets', 'security_events', 'detections', 'incidents', 'vulnerabilities', 'network_events', 'iocs', 'simulations', 'reports', 'website_sites', 'domain_verifications']) {
  if (tables.includes(table)) counts[table] = scalar(`SELECT COUNT(*) AS c FROM ${table}`);
}

const verification = snap.prepare(
  `SELECT record_name, token FROM domain_verifications
    WHERE org_id = ? AND status IN ('pending','verified') ORDER BY created_at DESC LIMIT 1`,
).get(DEMO_ORG);
if (verification) {
  writeFileSync(join(root, 'demo', 'demo-dns.json'), JSON.stringify({
    records: { [verification.record_name]: [`secureflow-site-verification=${verification.token}`] },
    errors: {},
  }, null, 2));
}

snap.exec('VACUUM;');
snap.close();

console.log('Sanitized demo snapshot written:', output);
console.log(JSON.stringify(counts, null, 2));
console.log('Removed: sessions, login attempts, MFA challenges, audit logs, API keys, evidence and custody records.');
