/**
 * Backup and restore for the SQLite database.
 *
 * A backup is only useful if it can be restored, so this module verifies the
 * copy with PRAGMA integrity_check and a SHA-256 sidecar, and the restore path
 * verifies both before replacing anything.
 */
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

export function integrityCheck(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const row = db.prepare('PRAGMA integrity_check').get();
    const value = row?.integrity_check ?? Object.values(row ?? {})[0];
    return { ok: value === 'ok', detail: value };
  } finally {
    db.close();
  }
}

export function createBackup({ source, outDir, label = 'manual', keep = 7 }) {
  if (!existsSync(source)) throw new Error(`Database not found: ${source}`);
  mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const target = join(outDir, `${basename(source, '.db')}-${stamp}-${label}.db`);
  const db = new DatabaseSync(source);
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    db.exec(`VACUUM INTO '${resolve(target).replace(/'/g, "''").replace(/\\/g, '/')}';`);
  } finally {
    db.close();
  }
  const check = integrityCheck(target);
  if (!check.ok) {
    rmSync(target, { force: true });
    throw new Error(`Backup failed its integrity check: ${check.detail}`);
  }
  const digest = sha256(target);
  writeFileSync(`${target}.sha256`, `${digest}  ${basename(target)}\n`, 'utf8');
  const size = statSync(target).size;

  const pattern = new RegExp(`^${basename(source, '.db')}-.*\\.db$`);
  const backups = readdirSync(outDir)
    .filter((name) => pattern.test(name))
    .map((name) => ({ name, at: statSync(join(outDir, name)).mtimeMs }))
    .sort((a, b) => b.at - a.at);
  for (const stale of backups.slice(keep)) {
    rmSync(join(outDir, stale.name), { force: true });
    rmSync(join(outDir, `${stale.name}.sha256`), { force: true });
  }
  return { path: target, sha256: digest, size, integrity: check.detail, pruned: Math.max(0, backups.length - keep) };
}

export function verifyBackup(path) {
  if (!existsSync(path)) throw new Error(`Backup not found: ${path}`);
  const sidecar = `${path}.sha256`;
  if (existsSync(sidecar)) {
    const expected = readFileSync(sidecar, 'utf8').trim().split(/\s+/)[0];
    const actual = sha256(path);
    if (expected !== actual) {
      return { ok: false, reason: 'checksum_mismatch', expected, actual };
    }
  }
  const integrity = integrityCheck(path);
  return { ok: integrity.ok, reason: integrity.ok ? null : 'integrity_check_failed', integrity: integrity.detail };
}

export function restoreBackup({ backup, target, force = false }) {
  const verification = verifyBackup(backup);
  if (!verification.ok) throw new Error(`Refusing to restore: ${verification.reason}`);
  if (existsSync(target) && !force) {
    throw new Error('Target database exists. Pass --force after taking a backup of it.');
  }
  mkdirSync(dirname(resolve(target)), { recursive: true });
  const staging = `${target}.restore-${Date.now()}`;
  copyFileSync(backup, staging);
  const staged = integrityCheck(staging);
  if (!staged.ok) {
    rmSync(staging, { force: true });
    throw new Error('The copied database failed its integrity check');
  }
  let previous = null;
  if (existsSync(target)) {
    previous = `${target}.pre-restore-${Date.now()}`;
    renameSync(target, previous);
  }
  renameSync(staging, target);
  return { ok: true, target, previous };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--source') args.source = argv[++i];
    else if (token === '--out-dir') args.outDir = argv[++i];
    else if (token === '--label') args.label = argv[++i];
    else if (token === '--keep') args.keep = Number(argv[++i]);
    else if (token === '--backup') args.backup = argv[++i];
    else if (token === '--target') args.target = argv[++i];
    else if (token === '--force') args.force = true;
    else if (token === '--verify') args.verify = true;
  }
  return args;
}

const isDirectRun = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.verify) {
      const result = verifyBackup(args.backup);
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.ok ? 0 : 1);
    }
    if (args.backup && args.target) {
      const result = restoreBackup({ backup: args.backup, target: args.target, force: args.force });
      console.log(JSON.stringify(result, null, 2));
    } else {
      const result = createBackup({
        source: args.source ?? join(process.cwd(), 'backend', 'data', 'secureflow.db'),
        outDir: args.outDir ?? join(process.cwd(), 'backups'),
        label: args.label ?? 'manual',
        keep: args.keep ?? 7,
      });
      console.log(JSON.stringify(result, null, 2));
    }
  } catch (err) {
    console.error(`Backup command failed: ${err.message}`);
    process.exit(1);
  }
}
