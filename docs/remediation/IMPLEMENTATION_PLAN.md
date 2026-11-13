# Implementation plan

Follows `REPOSITORY_AUDIT.md`. Each task lists current behaviour, target behaviour, affected files, impact, dependencies, tests and the smallest safe step.

## Dependency order

```
themes (independent)
accessibility harness (independent, used to verify themes)
shared rate limiting (independent of database)
security headers (independent)
integrations (independent of database)
PostgreSQL schema + data tooling
backup/restore + deployment docs
regression, final report
```

PostgreSQL runtime support depends on an asynchronous data layer, which is a prerequisite for the application, not for the migration tooling. The tooling is therefore delivered first and the runtime change is left as a documented blocker rather than half applied.

## Task 1: PostgreSQL

- Current: SQLite only, synchronous API, 41 tables, schema version 5.
- Target: a PostgreSQL schema that matches the SQLite schema, a repeatable data copy with dry run and verification, and a documented path for the asynchronous runtime adapter and tenant isolation.
- Files: `backend/scripts/pg/schema.mjs`, `backend/scripts/pg/generate-schema.mjs`, `backend/scripts/pg/migrate-data.mjs`, `backend/src/migrations/postgres/001_schema.sql`, `backend/tests/postgres-schema.test.mjs`.
- Database impact: additive. The SQLite database is untouched.
- API impact: none.
- Security impact: the generated schema preserves foreign keys, unique constraints and check constraints. Tenant isolation remains application level until the runtime adapter exists.
- Dependencies: `pg` and `pg-mem` as backend development dependencies.
- Testing: schema applies in pg-mem, all 41 tables and 44 indexes present, parents ordered before children, row counts match the demo database.
- Rollback: delete the generated file and the scripts. No data changes.
- Acceptance: schema generation is reproducible, the copy tool is dry run safe, and the runtime limitation is documented. Full acceptance (application tests against PostgreSQL) is blocked by the missing server and the asynchronous refactor.

## Task 2: Redis rate limiting

- Current: per process map, no headers, no failure policy.
- Target: one store interface with an in-memory and a Redis implementation, atomic increment with expiry, per user and per IP keys, response headers, and explicit behaviour when Redis fails.
- Files: `backend/src/lib/ratelimit.js`, `backend/src/lib/ratelimitStore.js`, `backend/tests/ratelimit.test.mjs`, `backend/tests/ratelimit-redis.test.mjs`, `backend/src/index.js`, `backend/src/routes/auth.js`, `backend/src/lib/http.js`.
- Database impact: none.
- API impact: every response gains `RateLimit-*` headers. A 429 gains an accurate `Retry-After`.
- Security impact: authentication endpoints fail closed when the shared store is unavailable; other endpoints use a bounded local fallback so they do not become unlimited.
- Dependencies: `redis` 5.x backend dependency, a Redis server only for the shared test.
- Testing: eight unit tests for the limiter, two integration tests that run when `SF_REDIS_URL` is set and are exercised by a dedicated CI job with a real Redis service.
- Rollback: unset `SF_REDIS_URL`; the memory store is the default.
- Acceptance: cannot be bypassed by switching instances; tested in CI with two stores against one server.

## Task 3: Security

- Current: strong base controls, missing HSTS/CORP/cache headers and a readiness probe; duplicated provider code; audit not transactional with the business write.
- Target: header hardening, no-store API responses, readiness probe, an explicit post-login redirect check, shared provider client, and a findings register with reproduction and retest.
- Files: `backend/src/index.js`, `frontend/src/pages/Public.tsx`, `backend/src/services/reputation.js`, `backend/src/routes/intel.js`, `backend/src/services/phishing.js`, `docs/remediation/SECURITY_FINDINGS.md`.
- Security impact: reduces browser caching of tenant data, prevents protocol relative redirects after login, and removes duplicated provider handling.
- Testing: header assertions in the API sweep, provider unit tests with a stub server, accessibility suite for the login change.
- Acceptance: every verified finding fixed or documented as residual. Independent penetration testing remains NOT VERIFIED.

## Task 4: Deployment readiness

- Current: single container, SQLite volume, no Redis, health check on liveness only, no backup tooling.
- Target: compose with Redis and the shared limiter wired, readiness health check, backup and restore tooling with a tested restore, and staging instructions.
- Files: `Dockerfile`, `docker-compose.yml`, `backend/scripts/backup.mjs`, `backend/tests/backup.test.mjs`, deployment docs.
- Testing: five backup tests including a real restore and a tamper test.
- Acceptance: staging configuration is prepared and backup restoration is proven locally. A real staging deployment is NOT VERIFIED because this host has no Docker.

## Task 5: Integrations

- Current: inline provider calls, no cache, no retry, no health.
- Target: one provider module with timeout, bounded retry, response validation, cache, health record and honest status. SOAR actions stay simulated and labelled.
- Files: `backend/src/services/reputation.js`, `backend/src/routes/intel.js`, `backend/src/services/phishing.js`, `backend/src/routes/settings.js`, tests.
- Testing: eight provider tests against a local stub.
- Acceptance: no fake provider success; live provider calls BLOCKED without keys.

## Task 6: Accessibility

- Current: no automated test.
- Target: Playwright with axe on all 16 authenticated routes in both themes, plus skip link, dialog focus, theme persistence and system mode.
- Files: `frontend/playwright.config.ts`, `frontend/e2e/a11y.spec.ts`, `frontend/e2e/auth.setup.ts`, CI job.
- Testing: 37 tests. Failures are fixed in the UI, not suppressed.
- Acceptance: zero serious or critical violations; moderate and minor reviewed.

## Task 7: Themes

- Current: dark only, Astryx mode hardcoded, 161 hardcoded colours.
- Target: light, dark and system, stored per browser, applied before first paint, tokens for every surface, charts readable in both.
- Files: `frontend/src/styles.css`, `frontend/src/lib/theme/ThemeMode.tsx`, `frontend/src/components/layout.tsx`, `frontend/src/lib/theme/AstryxProviders.tsx`, `frontend/public/theme-init.js`, `frontend/index.html`, charts and pages.
- Testing: axe contrast in both themes, persistence and system mode tests, computed style checks.
- Acceptance: every route renders in both themes with no serious contrast failure.

## Rollback strategy

Every change is additive or reversible by configuration:
- Redis off: leave `SF_REDIS_URL` unset.
- Theme: the preference is client local storage; removing the control restores system behaviour.
- PostgreSQL tooling: files only, no runtime switch.
- Backup: no change to the live database until an operator runs a restore.

## Acceptance map

See `FINAL_REMEDIATION_REPORT.md` for the result of each criterion with evidence.
