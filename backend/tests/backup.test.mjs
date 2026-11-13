import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createBackup, integrityCheck, restoreBackup, verifyBackup } from '../scripts/backup.mjs';

const demo = resolve(process.cwd(), '..', 'demo', 'secureflow-demo.db');
const scratch = () => mkdtempSync(join(tmpdir(), 'sf-backup-'));

const counts = (path) => {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return {
      organizations: db.prepare('SELECT COUNT(*) AS c FROM organizations').get().c,
      users: db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
      incidents: db.prepare('SELECT COUNT(*) AS c FROM incidents').get().c,
    };
  } finally { db.close(); }
};

test('a backup is written, hashed and passes an integrity check', () => {
  const dir = scratch();
  try {
    const result = createBackup({ source: demo, outDir: dir, label: 'test', keep: 3 });
    assert.ok(result.size > 0);
    assert.equal(result.integrity, 'ok');
    assert.equal(result.sha256.length, 64);
    const sidecar = readFileSync(`${result.path}.sha256`, 'utf8');
    assert.ok(sidecar.includes(result.sha256));
    assert.equal(integrityCheck(result.path).ok, true);
    assert.equal(verifyBackup(result.path).ok, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a restore reproduces the same record counts', () => {
  const dir = scratch();
  try {
    const backup = createBackup({ source: demo, outDir: dir, label: 'restore', keep: 3 });
    const target = join(dir, 'restored.db');
    const result = restoreBackup({ backup: backup.path, target });
    assert.equal(result.ok, true);
    assert.deepEqual(counts(target), counts(demo));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a tampered checksum blocks the restore', () => {
  const dir = scratch();
  try {
    const backup = createBackup({ source: demo, outDir: dir, label: 'tamper', keep: 3 });
    writeFileSync(`${backup.path}.sha256`, `${'0'.repeat(64)}  file.db\n`, 'utf8');
    const check = verifyBackup(backup.path);
    assert.equal(check.ok, false);
    assert.equal(check.reason, 'checksum_mismatch');
    assert.throws(() => restoreBackup({ backup: backup.path, target: join(dir, 'never.db') }), /checksum_mismatch/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an existing target is not overwritten without force, and a safety copy is kept when forced', () => {
  const dir = scratch();
  try {
    const backup = createBackup({ source: demo, outDir: dir, label: 'guard', keep: 3 });
    const target = join(dir, 'live.db');
    writeFileSync(target, 'not a database', 'utf8');
    assert.throws(() => restoreBackup({ backup: backup.path, target }), /Target database exists/);
    const forced = restoreBackup({ backup: backup.path, target, force: true });
    assert.ok(forced.previous);
    assert.deepEqual(counts(target), counts(demo));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('retention keeps only the requested number of backups', () => {
  const dir = scratch();
  try {
    for (let index = 0; index < 4; index += 1) {
      createBackup({ source: demo, outDir: dir, label: `rotation-${index}`, keep: 2 });
    }
    const left = readdirSync(dir).filter((name) => name.endsWith('.db'));
    assert.ok(left.length <= 2, `expected at most two backups, found ${left.length}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
