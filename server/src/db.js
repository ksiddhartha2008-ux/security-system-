import { DatabaseSync } from 'node:sqlite';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
export const rootDir = join(here, '..');
export const dataDir = process.env.SF_DATA_DIR || join(rootDir, 'data');

mkdirSync(dataDir, { recursive: true });

export const dbPath = process.env.SF_DB_PATH || join(dataDir, 'secureflow.db');

export const db = new DatabaseSync(dbPath);

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA busy_timeout = 5000;');

/** Apply SQL migrations once, tracked with PRAGMA user_version. */
export function migrate() {
  let current = db.prepare('PRAGMA user_version').get().user_version ?? 0;
  if (current < 1) {
    const sql = readFileSync(join(here, 'migrations', '001_init.sql'), 'utf8');
    db.exec(sql);
    db.exec('PRAGMA user_version = 1');
    current = 1;
    console.log('[db] schema v1 applied');
  }
  if (current < 2) {
    const sql = readFileSync(join(here, 'migrations', '002_mfa.sql'), 'utf8');
    db.exec(sql);
    db.exec('PRAGMA user_version = 2');
    console.log('[db] schema v2 applied (TOTP MFA)');
  }
}

export const all = (sql, ...params) => db.prepare(sql).all(...params);
export const get = (sql, ...params) => db.prepare(sql).get(...params);
export const run = (sql, ...params) => db.prepare(sql).run(...params);

export function transaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw err;
  }
}

const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
export function newId(prefix = 'id', size = 12) {
  const bytes = randomBytes(size);
  let out = '';
  for (let i = 0; i < size; i += 1) out += ALPHABET[bytes[i] % ALPHABET.length];
  return `${prefix}_${out}`;
}

export const iso = (date = new Date()) => new Date(date).toISOString();
export const nowIso = () => new Date().toISOString();

export function parseJson(value, fallback) {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return fallback; }
}

export const toBool = (v) => v === 1 || v === true;

