#!/usr/bin/env node
/**
 * Copy a SQLite SecureFlow database into PostgreSQL.
 *
 *   node backend/scripts/pg/migrate-data.mjs --source demo/secureflow-demo.db --target "$DATABASE_URL" --dry-run
 *   node backend/scripts/pg/migrate-data.mjs --source <db> --target <url> --verify
 *
 * Safety:
 * - the source is opened read only and never modified
 * - the schema is applied by 001_schema.sql first; this tool never drops objects
 * - rows are copied inside one transaction; a failure rolls the whole import back
 * - --truncate is opt in and only allowed with --confirm-empty-target
 * - row values are never logged, only counts and table names
 *
 * This copies data. Running the application against PostgreSQL also needs the
 * asynchronous data layer described in docs/remediation/DATABASE_MIGRATION_REPORT.md.
 */
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

export function parseArgs(argv) {
  const args = { dryRun: false, verify: false, truncate: false, batchSize: 500 };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--source') args.source = argv[++i];
    else if (token === '--target') args.target = argv[++i];
    else if (token === '--dry-run') args.dryRun = true;
    else if (token === '--verify') args.verify = true;
    else if (token === '--truncate') args.truncate = true;
    else if (token === '--confirm-empty-target') args.confirmEmpty = true;
    else if (token === '--batch-size') args.batchSize = Number(argv[++i]) || 500;
    else if (token === '--help' || token === '-h') args.help = true;
    else throw new Error(`Unknown argument: ${token}`);
  }
  return args;
}

/** Tables ordered so a parent is copied before every child. */
export function migrationOrder(db) {
  const tables = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
  ).all().map((row) => row.name);
  const deps = new Map();
  for (const table of tables) {
    const parents = db.prepare(`PRAGMA foreign_key_list(${table})`).all()
      .map((fk) => fk.table)
      .filter((parent) => parent !== table && tables.includes(parent));
    deps.set(table, new Set(parents));
  }
  const ordered = [];
  const remaining = new Set(tables);
  while (remaining.size) {
    const ready = [...remaining].filter((table) => [...deps.get(table)].every((parent) => !remaining.has(parent)));
    if (!ready.length) {
      // A cycle: keep deterministic order rather than fail silently.
      ordered.push(...[...remaining].sort());
      break;
    }
    ready.sort();
    for (const table of ready) { ordered.push(table); remaining.delete(table); }
  }
  return ordered;
}

export function planMigration(dbPath, { batchSize = 500 } = {}) {
  if (!existsSync(dbPath)) throw new Error(`Source database not found: ${dbPath}`);
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const order = migrationOrder(db);
    const tables = order.map((table) => {
      const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
      const total = db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get().c;
      return { table, columns, total, batches: Math.ceil(total / batchSize) };
    });
    return {
      order,
      tables,
      totalRows: tables.reduce((sum, t) => sum + t.total, 0),
      batchSize,
    };
  } finally {
    db.close();
  }
}

function loadPg() {
  // Loaded lazily so --dry-run works without a database driver installed.
  return import('pg');
}

async function copyTable(client, source, { table, columns, total }, batchSize) {
  if (!total) return 0;
  let copied = 0;
  for (let offset = 0; offset < total; offset += batchSize) {
    const rows = source.prepare(`SELECT * FROM ${table} LIMIT ? OFFSET ?`).all(batchSize, offset);
    if (!rows.length) break;
    const params = [];
    const tuples = rows.map((row) => `(${columns.map((column) => {
      params.push(row[column]);
      return `$${params.length}`;
    }).join(', ')})`);
    const sql = `INSERT INTO ${table} (${columns.join(', ')}) VALUES ${tuples.join(', ')}`;
    await client.query(sql, params);
    copied += rows.length;
  }
  return copied;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.dryRun && !args.verify && !args.target)) {
    console.log('Usage: node backend/scripts/pg/migrate-data.mjs --source <sqlite> --target <postgres url> [--dry-run|--verify] [--truncate --confirm-empty-target]');
    return;
  }
  const source = resolve(root, args.source ?? join('backend', 'data', 'secureflow.db'));
  const plan = planMigration(source, { batchSize: args.batchSize });

  console.log(`Source: ${source}`);
  console.log(`Tables: ${plan.tables.length}. Rows: ${plan.totalRows}.`);
  for (const table of plan.tables) console.log(`  ${table.table}: ${table.total} rows`);

  if (args.dryRun) {
    console.log('Dry run complete. Nothing was written.');
    return;
  }
  if (!args.target) throw new Error('--target is required unless --dry-run is set');

  const { Client } = await loadPg();
  const client = new Client({ connectionString: args.target });
  await client.connect();
  try {
    const schemaFile = join(root, 'backend', 'src', 'migrations', 'postgres', '001_schema.sql');
    const schema = readFileSync(schemaFile, 'utf8');

    if (args.verify) {
      const mismatches = [];
      for (const table of plan.tables) {
        const result = await client.query(`SELECT COUNT(*)::bigint AS c FROM ${table.table}`);
        const targetCount = Number(result.rows[0].c);
        if (targetCount !== table.total) mismatches.push(`${table.table}: source ${table.total}, target ${targetCount}`);
      }
      if (mismatches.length) {
        console.error('Count verification failed:');
        for (const line of mismatches) console.error(`  ${line}`);
        process.exitCode = 1;
      } else {
        console.log(`Verified ${plan.tables.length} tables with ${plan.totalRows} rows.`);
      }
      return;
    }

    if (args.truncate) {
      if (!args.confirmEmpty) throw new Error('Refusing to truncate without --confirm-empty-target');
      const tables = plan.order.map((table) => `"${table}"`).join(', ');
      await client.query(`TRUNCATE ${tables} RESTART IDENTITY CASCADE`);
      console.log('Target tables truncated.');
    }

    await client.query(schema);
    const sourceDb = new DatabaseSync(source, { readOnly: true });
    let inserted = 0;
    try {
      await client.query('BEGIN');
      for (const table of plan.tables) {
        const existing = await client.query(`SELECT COUNT(*)::bigint AS c FROM ${table.table}`);
        if (Number(existing.rows[0].c) > 0) {
          throw new Error(`Target table ${table.table} is not empty. Use --truncate --confirm-empty-target on a fresh database.`);
        }
        inserted += await copyTable(client, sourceDb, table, plan.batchSize);
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      sourceDb.close();
    }
    console.log(`Copied ${inserted} rows into ${plan.tables.length} tables.`);
  } finally {
    await client.end().catch(() => {});
  }
}

const isDirectRun = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  main().catch((err) => {
    console.error(`Migration failed: ${err.message}`);
    process.exit(1);
  });
}
