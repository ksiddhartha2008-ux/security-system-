# Scalability plan

Status: plan only. No database migration and no shared rate limiter were implemented. This file covers review item 3.1.

## Current architecture

- SQLite in WAL mode through `node:sqlite`, one file per deployment.
- One Node process is the documented deployment. Several processes on the same database work for the website job lease, but session rate limiting is per process.
- Website ingestion and verification use durable counters in SQLite (`website_usage`, `website_verification_attempts`), so those limits survive restarts and are shared by processes on the same file.
- Session routes use the in-memory limiter in `backend/src/lib/ratelimit.js` (1200 requests per minute per identity, plus route specific limits).
- The website scheduler claims jobs with `BEGIN IMMEDIATE` and a 60 second lease.
- Indexes that matter for volume: `security_events(org_id, occurred_at)`, `security_events(org_id, src_ip, occurred_at)`, `security_events(org_id, dedupe_key)` unique, `website_sites(hostname)`, `site_api_keys(key_id)` unique, `incident_entities(org_id, entity_type, entity_value)`, `website_jobs(next_run_at, lease_until)`.

## Shared rate limiting

### Option A: SQLite token bucket (no new service)

A table keyed by `(scope, identity, window_start)` with an atomic upsert. Works for several processes on one database and survives restarts. It adds one write per limited request, which becomes the bottleneck before the API does.

- Pros: no new dependency, same transaction model, simple operations.
- Cons: writes on the hot path, does not work across hosts with separate databases, lock contention under flood.

### Option B: Redis token bucket (recommended when leaving one host)

A Lua script performs `INCR` and `EXPIRE` atomically. Keys: `rl:user:<id>`, `rl:org:<id>`, `rl:key:<key id>`, `rl:ip:<address>`, each with a window and a limit.

- Pros: constant time, shared across hosts, natural expiry, well understood.
- Cons: a new service to operate; a Redis outage becomes an availability problem.

**Failure policy.** Authentication, ingestion key validation and verification must fail closed when the limiter is unavailable (deny or return `503`). Read only endpoints may fail open with a warning, because their abuse impact is lower. This distinction must be explicit in code, not left to a default.

**Key design.**
- Per user: prevents one session from exhausting a workspace.
- Per organization: protects shared storage and detection capacity.
- Per website key: protects ingestion independently of the customer's user accounts.
- Per IP: protects login and public endpoints before authentication.

**Atomicity.** Increment and expiry in one script. Never read then write from the application.

**Migration.** Run both limiters in shadow mode for a week, compare decisions, then make Redis authoritative. Keep the in-memory limiter as a circuit breaker.

## PostgreSQL migration

### Inventory

41 tables, 4 migrations plus v5. SQLite specific points:

- `json_extract` in detection, incident and export queries. PostgreSQL uses `jsonb` operators or `->>`.
- Partial unique indexes (supported by both, syntax differs slightly).
- `INTEGER` booleans (`0`/`1`) and `CHECK` constraints. PostgreSQL would use `boolean` or keep integers for a smaller diff.
- `node:sqlite` synchronous API. `pg` is asynchronous, so every route and service call site changes.
- `AUTOINCREMENT` is not used; identifiers are application generated.
- WAL checkpoint and file backup semantics have no PostgreSQL equivalent.

### Sequence

1. Freeze schema changes and tag a release.
2. Create the target schema with a reviewed DDL translation. Keep column names and constraints identical.
3. Backfill in dependency order: organizations, users, assets, sites, verifications, keys, events, detections, incidents, timeline, notifications, jobs, audit.
4. Validate row counts per table, foreign key orphan counts, audit hash chain per organization, and a sample of event dedupe keys.
5. Run the application test suite against a disposable PostgreSQL instance. The suite currently assumes SQLite and must be parameterised first.
6. Switch reads, then writes, behind a maintenance window. Keep the SQLite file read only for rollback.
7. Rollback: stop the application, restore the pre migration SQLite file, redeploy the previous release. Any writes made after the switch are lost unless a dual write phase exists.

### Downtime

- Small database (under 5 GB, under one million events): 30 to 90 minutes including validation.
- Larger database: a logical replication or dual write design is required. That design is not proven here and must not be described as zero downtime.
- Backups: SQLite backup API or a checkpoint plus file copy, verified by restoring into a temporary database and running the audit chain check.

### Not done

No adapter layer, no PostgreSQL schema, no dual write, no load test. The current release remains single node SQLite.

## Event volume assumptions

- 100,000 events per site per day is the enforced ceiling.
- At the current schema, one million events per month per workspace is a reasonable ceiling for a single node. Beyond that, archive old events and add composite indexes for the dashboard queries.
- Detection runs over a bounded time window per rule and uses indexes on `(org_id, occurred_at)` and `(org_id, src_ip, occurred_at)`.
- The post commit pipeline runs once per batch, not once per event.

## Open decisions

1. Redis versus database counters for shared limits.
2. Fail closed or fail open per endpoint class.
3. PostgreSQL boolean versus integer columns.
4. Whether a dual write phase is required before the database switch.
5. Retention length under higher volume.
