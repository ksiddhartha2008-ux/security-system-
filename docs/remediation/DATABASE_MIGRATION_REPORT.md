# PostgreSQL migration report

## Status

| Item | Status |
| --- | --- |
| PostgreSQL schema generated from the applied SQLite schema | IMPLEMENTED, TESTED against pg-mem |
| Data copy tool with dry run and verification | IMPLEMENTED, TESTED for planning; live copy NOT VERIFIED |
| Runtime support for PostgreSQL | NOT IMPLEMENTED |
| Verification against a real PostgreSQL server | BLOCKED, no server on this host |
| Tenant isolation design (RLS plus application scoping) | DESIGNED, NOT IMPLEMENTED |

## 1. Inventory

Read from `sqlite_master` of the sanitized demo database:

- Tables: 41
- Secondary indexes: 44
- Schema version: 5
- Tenant-owned tables: 23 (every table with `org_id`)
- Foreign keys: declared inline in the migrations and preserved by the generator
- Triggers: none
- Views: none
- Generated columns: none

The application uses SQLite only through `node:sqlite`. There are 667 synchronous `all` / `get` / `run` / `transaction` call sites. No ORM or query builder is present.

## 2. Compatibility analysis

| Area | SQLite behaviour | PostgreSQL handling |
| --- | --- | --- |
| Types | `TEXT`, `INTEGER`, `REAL` | translated to `text`, `bigint`, `double precision` |
| Identifiers | text ids such as `inc_ab12...` | unchanged, no sequences needed |
| Timestamps | ISO 8601 strings, no timezone type | kept as `text` to preserve exact values; a later phase can move to `timestamptz` |
| Booleans | `INTEGER` 0/1 | kept as `bigint` 0/1 |
| JSON | `TEXT` holding JSON | kept as `text`; `jsonb` is a later optimisation |
| Defaults | string and numeric literals | unchanged |
| Check constraints | inline | preserved verbatim |
| Foreign keys | inline, `ON DELETE` actions | preserved verbatim |
| Partial indexes | `CREATE INDEX ... WHERE` | supported by PostgreSQL |
| `PRAGMA` statements | page and journal settings | removed, they have no meaning |
| Autoincrement | not used | not needed |
| Locking | `BEGIN IMMEDIATE` | PostgreSQL transactions plus explicit `FOR UPDATE` where needed |

The generated file is `backend/src/migrations/postgres/001_schema.sql`. It is produced by `backend/scripts/pg/generate-schema.mjs` from the schema that is actually applied, so a database that stopped at an older version cannot silently produce the wrong target.

## 3. Verification performed

`backend/tests/postgres-schema.test.mjs` runs seven checks:

1. All 41 tables and at least 40 indexes are present, no `PRAGMA`, no SQLite type names remain.
2. The generated DDL applies in a PostgreSQL engine (pg-mem) and the core tables exist afterwards.
3. Check constraints and `ON DELETE CASCADE` survive translation.
4. Type translation leaves ordinary SQL intact.
5. The migration plan orders every parent before its children.
6. Row counts come from the real sanitized database (1 organization, 3 users, 9 incidents, 0 sessions).
7. The CLI parser rejects unknown flags and understands dry run and batch size.

pg-mem is a compatibility emulator, not PostgreSQL. It proves syntax and constraint shape, not planner, transaction or concurrency behaviour.

## 4. Data copy tool

`backend/scripts/pg/migrate-data.mjs`:

```
node backend/scripts/pg/migrate-data.mjs --source demo/secureflow-demo.db --dry-run
node backend/scripts/pg/migrate-data.mjs --source <db> --target "$DATABASE_URL"
node backend/scripts/pg/migrate-data.mjs --source <db> --target "$DATABASE_URL" --verify
```

- The source is opened read only.
- Tables are copied in dependency order, in batches of 500 rows.
- One transaction wraps the whole copy; a failure rolls it back.
- The target must be empty unless `--truncate --confirm-empty-target` is passed on a disposable database.
- Row values are never logged.
- `--verify` compares source and target counts per table and exits non-zero on a mismatch.
- Dry run requires no driver and no server. It reported 41 tables and 801 rows for the demo snapshot.

## 5. Tenant isolation design

The current application already derives `org_id` from the session and scopes every query. For PostgreSQL the plan is defence in depth:

1. Application scoping stays as it is: `req.user.orgId` from the session, never from the body.
2. Every tenant table keeps `org_id NOT NULL` and a composite unique key `(org_id, id)` where a child references a parent, so a cross tenant foreign key is impossible.
3. Row Level Security on tenant tables, enabled and forced:

```sql
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON incidents
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));
```

4. Each request runs inside a transaction that sets the context locally:

```sql
SET LOCAL app.org_id = 'org_meridian';
```

`SET LOCAL` is transaction scoped, so a pooled connection cannot carry one tenant's context into the next request. The application role must not have `BYPASSRLS`.
5. Tests must open two organizations and prove that a query without the setting returns zero rows and that a cross tenant id returns 404, not 403, matching current behaviour.

This design is written down, not applied. Applying RLS while the application still connects with a single unscoped connection would break every query, so it belongs with the runtime adapter.

## 6. Why runtime support is not implemented

`node:sqlite` is synchronous. PostgreSQL drivers are asynchronous. Supporting PostgreSQL therefore means changing every data access to `await`, propagating through route handlers, services, seeding, the scheduler, the demo generator and the website pipeline. That is a 667 call site refactor with transaction boundaries to redesign.

Doing that in the same change as the schema and the rest of the remediation would risk the working SQLite path, which the rules forbid. The correct sequence is:

1. Generate and review the schema (done).
2. Build the copy tool and rehearse it against a disposable PostgreSQL instance (tool done, rehearsal blocked).
3. Introduce a repository layer with an async interface behind a flag, migrate module by module with the existing tests running against both engines.
4. Enable RLS after the async layer is the only path.

## 7. Rollback procedure

The SQLite database is never modified by any of this work.

To abandon the PostgreSQL attempt:

1. Delete `backend/src/migrations/postgres/001_schema.sql`.
2. Delete `backend/scripts/pg/`.
3. Remove `pg` and `pg-mem` from `backend/package.json` development dependencies.
4. No application setting changes, because no runtime switch exists.

## 8. Remaining risks

- Generated `text` timestamps keep ordering as ISO strings, which is correct while every writer uses `toISOString()`. A future writer with a different format would break ordering.
- pg-mem does not exercise concurrency, so unique constraint races and deadlocks are unverified.
- RLS policies are not written as migrations yet, by design.
- A real migration rehearsal needs a disposable PostgreSQL 15+ instance and a maintenance window.
