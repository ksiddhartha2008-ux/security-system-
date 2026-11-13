#!/usr/bin/env node
/** Write the PostgreSQL schema for the applied SQLite schema. */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPostgresSchema } from './schema.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const source = process.env.SF_DB_PATH || join(root, 'backend', 'data', 'secureflow.db');
const output = process.env.SF_PG_SCHEMA || join(root, 'backend', 'src', 'migrations', 'postgres', '001_schema.sql');

const { sql, tables, indexes } = buildPostgresSchema(source);
mkdirSync(dirname(resolve(output)), { recursive: true });
writeFileSync(output, sql, 'utf8');
console.log(`PostgreSQL schema written: ${output}`);
console.log(`Tables: ${tables}. Indexes: ${indexes}.`);
