# Repository audit

Date: 13 November 2026
Commit at audit start: `a8471fc`
Scope: the repository at `C:\Users\ksidd\OneDrive\Pictures\Desktop\hack`, remote `https://github.com/ksiddhartha2008-ux/security-system-`

This audit describes what exists, not what an older report claimed. Line numbers refer to the commit above unless a later phase changed the file.

## 1. Structure

```
backend/            Express API, SQLite schema, services, tests
  src/db.js         node:sqlite connection, migrations, helpers
  src/migrations/   five SQL migrations, schema version 5
  src/routes/       19 route modules
  src/services/     detection, correlation, simulations, website pipeline
  tests/            16 test files before this work
frontend/           React 19 client, Vite, Astryx
  src/pages/        24 page modules
  src/components/   shell, charts, shared primitives
  src/styles.css    dark-first application CSS
  src/lib/theme/    Astryx theme source and generated output
packages/sdk-node/  private Node SDK, 13 tests
docs/               product, website evidence pack, health report
scripts/            secret scan, link check, demo export, API health sweep
demo/               sanitized database snapshot and DNS fixture
third_party/        vendored notes for external services
```

## 2. Runtime and dependencies

| Component | Version | Evidence |
| --- | --- | --- |
| Node.js | 24.20.0 | `node --version` |
| Express | 4.21.2 | `backend/package.json` |
| Zod | 4.6.7 | `backend/package.json` |
| tldts | 7.4.21 | `backend/package.json` |
| React | 19 | `frontend/package.json` |
| Vite | 6 | `frontend/package.json` |
| TypeScript | 5.7 | `frontend/package.json` |
| Astryx | 0.7.13, pinned | `frontend/package.json` |
| StyleX | 0.19.1 | `frontend/package.json` |
| Tailwind CSS | 4 | `frontend/package.json` |

The backend has three runtime dependencies before this work. There is no ORM: `backend/src/db.js:15` opens a `DatabaseSync` handle and every route calls `all`, `get`, `run` or `transaction` directly. A count of those call sites in `backend/src` is 667.

## 3. Database

- Engine: SQLite through `node:sqlite`, WAL mode, foreign keys on, 5 second busy timeout (`backend/src/db.js:15-19`).
- Migrations: `001_init.sql` to `005_website_protection.sql`, tracked with `PRAGMA user_version` (`backend/src/db.js:22-61`).
- Schema version: 5.
- Tables: 41. Indexes: 44. Verified by reading `sqlite_master` from the sanitized demo database.
- Tenant model: an `organizations` table and `org_id` on tenant-owned tables. Requests resolve the organization from the session user in `backend/src/lib/auth.js`, never from the request body.
- Transactions: `backend/src/db.js:63` provides `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`.

There is no PostgreSQL driver, no connection pool and no asynchronous query layer in the application runtime.

## 4. Authentication and authorization

- Passwords: scrypt with a per-user salt, constant time compare (`backend/src/lib/auth.js:12-40`).
- Sessions: random 32 byte token, stored as a SHA-256 hash, HttpOnly, SameSite=Lax, seven day expiry (`backend/src/lib/auth.js:109`).
- CSRF: double submit cookie bound to the session hash plus an Origin/Host check (`backend/src/lib/auth.js:204-239`).
- MFA: TOTP with a five minute challenge cookie (`backend/src/lib/auth.js`, `backend/src/lib/totp.js`).
- Roles: viewer, analyst, admin. `requireRole` uses a rank comparison (`backend/src/lib/auth.js:175`). No route calls `requireRole('viewer')`, so the rank behaviour is not currently observable.
- Sensitive website actions also require a password step-up inside ten minutes.

## 5. Rate limiting

Before this work: a single in-memory `Map` in `backend/src/lib/ratelimit.js` with a fixed window, keyed by user id or IP, no response headers and no failure policy. Policies existed for register, login, step-up, MFA, threat intelligence lookup and phishing scan. The global API limit was 1200 requests per minute.

## 6. Frontend and design system

- Six public routes and 24 authenticated routes, all authenticated pages lazy loaded (`frontend/src/App.tsx`).
- Astryx provides the application shell, navigation, buttons, cards, headings, badges and text inputs. Import paths are subpaths of `@astryxdesign/core`.
- The Astryx theme source is `frontend/src/lib/theme/secureflowTheme.ts`; `secureflow.css` and `secureflow.js` beside it are generated and byte checked in CI.
- Application CSS is dark first: `frontend/src/styles.css` defined dark token values in `@theme` and `:root` with `color-scheme: dark`. Astryx was mounted with `mode="dark"` in `frontend/src/lib/theme/AstryxProviders.tsx`.
- Before this work the frontend had no linter, no unit test runner and no automated accessibility test. Playwright and axe were not installed.

## 7. Existing security controls

| Control | Location | State |
| --- | --- | --- |
| Security headers | `backend/src/index.js:89` | nosniff, frame deny, referrer policy, permissions policy, COOP |
| CSP for the SPA | `backend/src/index.js` static handler | script self, frame ancestors none |
| CSRF | `backend/src/lib/auth.js:225` | enforced on cookie authenticated mutations |
| Origin check | `backend/src/lib/auth.js:204` | enforced on mutations |
| Tenant scoping | every route | `org_id` from the session |
| Audit chain | `backend/src/lib/audit.js` | SHA-256 chain per organization, verify endpoint |
| Upload validation | `backend/src/routes/forensics.js:64` | MIME allowlist, magic byte signature check, size cap, ClamAV fail closed in production |
| SSRF protection | `backend/src/services/phishing.js` | DNS resolution and private range blocking on every redirect hop |
| API key storage | `backend/src/lib/apiKeys.js` | hashed secret, timing safe compare, revocation, recent auth |
| SOAR approval | `backend/src/routes/automation.js` | destructive actions require approval server side |
| Production config gate | `backend/src/lib/config.js` | refuses insecure production flags at startup |

Missing before this work: HSTS, cross-origin resource policy, cache prevention on API responses, a readiness probe.

## 8. Integrations and SOAR

- Threat intelligence lookups call VirusTotal and AbuseIPDB inline in `backend/src/routes/intel.js` when keys exist. The phishing scanner repeats similar code in `backend/src/services/phishing.js`.
- No timeout policy beyond `AbortSignal.timeout(8000)`, no retry, no cache, no persisted provider health.
- Wazuh, Sysmon, Suricata, Zeek, ClamAV, YARA and MiroFish are catalogued in `backend/src/routes/settings.js`. ClamAV is a real connection when `CLAMAV_HOST` is set. MiroFish is a real HTTP adapter when `MIROFISH_BASE_URL` is set. The rest have no connector code and are shown as unconfigured.
- Workflow actions are recorded as `simulated` because no firewall or endpoint integration exists. The code states this in the execution log (`backend/src/routes/automation.js:93`).

## 9. Deployment

- `Dockerfile`: multi stage, non-root user, health check against `/api/health`.
- `docker-compose.yml`: one service, named volume for `/data`, demo mode off by default.
- CI: `.github/workflows/ci.yml` runs backend tests, SDK tests, secret scan, Astryx theme check, Astryx wiring check, and the frontend build on Ubuntu with Node 24.
- No staging environment, no Redis service, no PostgreSQL service, no backup job, no restore test.

## 10. Tests before this work

| Suite | Count | Notes |
| --- | --- | --- |
| Backend | 91 | auth, MFA, isolation, hardening, website, workflow, simulation, demo |
| SDK | 13 | envelope validation, batching, retries |
| API sweep | 55 checks | `scripts/health-check.ps1`, three roles |
| Accessibility | none | no Playwright or axe |
| Themes | none | dark only |

## 11. Technical debt and missing dependencies

1. PostgreSQL requires an asynchronous data layer. 667 synchronous call sites make this the largest single piece of work in the remediation.
2. Redis was not a dependency; shared limits were impossible across instances.
3. Provider calls are duplicated in two modules with no shared health record.
4. The frontend has hardcoded colours (65 in `styles.css`, 96 in TSX before this work) which block light mode.
5. Audit writes are hash chained and fail loudly, but they are not in the same transaction as the business write in most routes.
6. No automated accessibility, contrast or keyboard test.
7. No staging deployment, no restore rehearsal, no external integration credentials on this host.

## 12. Conflicting documentation and unverified assumptions

- `README.md` described the project as demo only and did not mention the website protection module or the sanitized snapshot.
- `docs/APP_HEALTH_REPORT.md` correctly listed light mode and shared rate limiting as planned at the time of writing; those statements are superseded by this remediation.
- The 41 table count and 302 event demo figures were still accurate when re-measured.
- Assumption that could not be verified: behaviour against a real PostgreSQL server, a real Redis server and real provider credentials. None are available on this host.

## 13. Gate 0 result

The repository is accessible, the working tree is clean apart from this remediation work, the schema and routes are understood, and the dependencies for each phase are known. Proceeding to the implementation plan.
