import test from 'node:test';
import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import { newDb, DataType } from 'pg-mem';
import { buildPostgresSchema, schemaReport, translateStatement } from '../scripts/pg/schema.mjs';
import { planMigration, parseArgs } from '../scripts/pg/migrate-data.mjs';

const demo = resolve(process.cwd(), '..', 'demo', 'secureflow-demo.db');

test('the generated schema preserves every table and index', () => {
  const report = schemaReport(demo);
  assert.equal(report.tables, 41);
  assert.ok(report.indexes >= 40);
  assert.equal(report.sql.includes('PRAGMA'), false);
  assert.equal(/\bTEXT\b/.test(report.sql), false, 'SQLite types are translated');
  assert.equal(report.sql.includes('CREATE TABLE users'), true);
  assert.equal(report.sql.includes('CREATE INDEX'), true);
  assert.ok(report.tenantTables.length >= 20, 'tenant owned tables are enumerated');
});

test('the PostgreSQL schema applies in a PostgreSQL engine', () => {
  const { sql } = buildPostgresSchema(demo);
  const db = newDb();
  db.public.registerFunction({
    name: 'length', args: [DataType.text], returns: DataType.integer, implementation: (value) => (value ?? '').length,
  });
  db.public.none(sql);
  for (const table of ['organizations', 'users', 'incidents', 'detections', 'security_events', 'audit_logs', 'sessions']) {
    const rows = db.public.many(`SELECT COUNT(*)::int AS c FROM ${table}`);
    assert.equal(rows[0].c, 0, `${table} exists and is empty`);
  }
});

test('check constraints and foreign keys survive the translation', () => {
  const { sql } = buildPostgresSchema(demo);
  assert.match(sql, /CHECK \(role IN \('admin','analyst','viewer'\)\)/);
  assert.match(sql, /REFERENCES organizations\(id\) ON DELETE CASCADE/);
});

test('translation leaves ordinary SQL untouched apart from column types', () => {
  const input = "CREATE TABLE t (\n  id TEXT PRIMARY KEY,\n  score INTEGER NOT NULL DEFAULT 0,\n  note TEXT\n);";
  const output = translateStatement(input);
  assert.equal(output.includes('id text PRIMARY KEY'), true);
  assert.equal(output.includes('score bigint NOT NULL DEFAULT 0'), true);
});

test('the migration plan orders parents before children', () => {
  const plan = planMigration(demo);
  assert.equal(plan.tables.length, 41);
  const position = Object.fromEntries(plan.order.map((table, index) => [table, index]));
  assert.ok(position.organizations < position.users, 'organizations before users');
  assert.ok(position.users < position.sessions, 'users before sessions');
  assert.ok(position.incidents < position.incident_events, 'incidents before their events');
  assert.ok(position.website_sites < position.site_api_keys, 'sites before their API keys');
});

test('the plan reports real row counts from the sanitized demo database', () => {
  const plan = planMigration(demo);
  const byTable = Object.fromEntries(plan.tables.map((table) => [table.table, table]));
  assert.equal(byTable.organizations.total, 1);
  assert.equal(byTable.users.total, 3);
  assert.equal(byTable.incidents.total, 9);
  assert.equal(byTable.sessions.total, 0);
  assert.ok(plan.totalRows > 700);
});

test('the CLI parser refuses unknown flags and understands the safe modes', () => {
  assert.deepEqual(parseArgs(['--dry-run']).dryRun, true);
  const parsed = parseArgs(['--source', 'a.db', '--target', 'postgres://x', '--batch-size', '250']);
  assert.equal(parsed.source, 'a.db');
  assert.equal(parsed.batchSize, 250);
  assert.throws(() => parseArgs(['--drop-everything']), /Unknown argument/);
});
