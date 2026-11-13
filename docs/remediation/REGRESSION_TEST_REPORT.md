# Regression test report

Date: 13 November 2026
Environment: Windows, Node 24.20.0, npm 11.19.0, Chromium through Playwright.
Database: SQLite schema version 5, 41 tables.
Redis: not installed on this host; the shared limiter test is exercised by CI against a real service.
PostgreSQL: no server on this host; schema validation uses pg-mem.

## 1. Summary

| Area | Command | Result | Status |
| --- | --- | --- | --- |
| Backend | `npm test` | 121 tests, 119 passed, 2 skipped, 0 failed, 70 s | TESTED |
| SDK | `npm run test:sdk` | 13 passed, 0 failed | TESTED |
| Types | `npm run typecheck` | no diagnostics | TESTED |
| Build | `npm run build` | built in 8.2 s | TESTED |
| Astryx theme | `npm run check:theme` | outputs up to date | TESTED |
| Astryx wiring | `npm run check:astryx` | passed | TESTED |
| Secrets | `npm run scan:secrets` | clean | TESTED |
| Links | `node scripts/check-links.mjs` | 0 broken | TESTED |
| Frontend deps | `npm audit --prefix frontend` | 0 vulnerabilities | TESTED |
| Backend deps | `npm audit --prefix backend --omit=dev` | 0 vulnerabilities | TESTED |
| API sweep | `scripts/health-check.ps1` | 55 checks, 0 failed | TESTED |
| Accessibility | `npm run test:a11y --prefix frontend` | 37 passed, 0 failed | TESTED |
| CI | run 43404898224 on `4f2c11b` | test, redis and accessibility jobs all success | TESTED |

Two backend tests are skipped locally because `SF_REDIS_URL` is not set. They are not disabled: the CI `redis` job sets the URL and runs them against `redis:7.4-alpine`.

## 2. Backend suite composition

| File | Focus |
| --- | --- |
| `auth.test.mjs` | registration, login, session, validation envelope |
| `mfa.test.mjs` | TOTP enrolment, challenge, recovery |
| `isolation.test.mjs` | cross tenant access |
| `security.test.mjs` | SSRF, headers, hardening cases |
| `hardening.test.mjs` | CSRF, audit chain, upload rules |
| `detection.test.mjs` | deterministic rules, de-duplication |
| `workflow.test.mjs` | incident lifecycle, evidence, reports, approvals |
| `simulation.test.mjs` | engine, cancellation, pipeline |
| `demo.test.mjs` | demo generation, reset scope, admin only |
| `website-*.test.mjs` | normalisation, DNS, ingestion, keys, scheduler, detection, API |
| `ratelimit.test.mjs` | shared store semantics, headers, failure modes (8) |
| `ratelimit-redis.test.mjs` | two stores against one Redis (2, skipped locally) |
| `reputation.test.mjs` | provider validation, retry, cache, health (8) |
| `postgres-schema.test.mjs` | schema translation and migration plan (7) |
| `backup.test.mjs` | backup, restore, checksum, retention (5) |

## 3. Before and after

| Metric | Before this remediation | After |
| --- | --- | --- |
| Backend tests | 91 | 121 (30 added) |
| Skipped | 0 | 2 (Redis, run in CI) |
| SDK tests | 13 | 13 |
| Accessibility tests | 0 | 37 |
| Rate limit tests | 0 | 10 |
| Provider tests | 0 | 8 |
| Schema and backup tests | 0 | 12 |
| API checks | 55 | 55 |
| Serious axe violations | unknown, not measured | 0 |
| Theme support | dark only | dark, light, system |

## 4. API sweep detail

The script signs in as admin, analyst and viewer, then calls every read route with a small page size, plus detail routes for events, assets, incidents, detections, investigations, reports, simulations, evidence and websites.

Also checked:

- viewer write returns 403
- analyst user administration returns 403
- unknown incident returns 404
- readiness reports database and store
- responses carry `RateLimit-*` and `Cache-Control: no-store`
- no 5xx and no error lines in `backend/run.log`

## 5. Accessibility suite

32 route scans (16 routes x 2 themes) plus skip link, dialog focus, theme persistence, system mode and light theme scan. All pass. A separate full axe tally over the same 16 routes in dark and light reports 0 violations at any impact.

## 6. Database and recovery

- PostgreSQL schema: 41 tables, 44 indexes, applies in pg-mem, constraints preserved.
- Migration plan: parents before children, 801 rows in the demo snapshot, dry run writes nothing.
- Backup: 5 tests including a real restore and a tamper rejection.

## 7. Browser pass

Earlier in the same day, the built application was opened at 488 px and 1280 px: 22 authenticated routes, dialogs, tabs, filters, pagination, role switching and the 404 page. No console error, no failed request, no error banner. The theme pass added computed style checks for both themes.

## 8. Not run

- Real Redis locally (no server). CI covers it.
- Real PostgreSQL end to end (no server and no async runtime).
- Docker build and compose up (no Docker).
- Independent penetration test.
- Manual screen reader pass.
- Live external provider call (no keys).

## 9. Failures fixed during the run

| Failure | Cause | Fix |
| --- | --- | --- |
| 18 axe failures on first run | light theme faint text at 4.29:1, account button name mismatch | token darkened, visible text included in the accessible name |
| Playwright setup could not reuse the port | a manual server was left running | stopped it; CI never has this conflict |
| Skip link test failed | wrong selector, the shell uses `#astryx-app-shell-main` | corrected selector and waited for network idle |
| PostgreSQL test used a non existent table name | website events live in `security_events` | corrected the assertion |
| Migration script resolved paths from the wrong directory | cwd dependent paths | paths derived from the module location |
