# Implementation log

Chronological record of the build session. Times are local (UTC+5:30).

## 1. Audit

- The workspace contained only `.zwork/` attachments; there was no existing SecureFlow code to preserve. The application was built from scratch.
- Read the supplied master prompt, the launch hygiene prompt and the architecture PDFs for requirements.
- Extracted `MiroFish-main.zip` to `third_party/mirofish/` and `api-anything-main.zip` to `third_party/api-anything/`. Original archives were left untouched.

## 2. Repository inspection (before any integration)

**MiroFish** (`666ghj/MiroFish`):

- Flask backend with blueprints registered at `/api/graph`, `/api/simulation` and `/api/report`; Vite frontend; no database of its own beyond Zep Cloud.
- `requirements.txt`: flask, flask-cors, openai, zep-cloud 3.25.0, camel-oasis 0.2.5, camel-ai 0.2.78, PyMuPDF, pydantic.
- `pyproject.toml` pins Python `>=3.11,<3.13`; the available runtime is 3.13.15, so the service cannot be installed here.
- Requires `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL_NAME` and `ZEP_API_KEY`; none are available.
- License: AGPL-3.0. Network use of a modified version carries source distribution obligations; the adapter avoids copying code.
- Actual routes read from source: `/api/simulation/create` (project_id, graph_id), `/prepare`, `/start` (platform, max_rounds), `/api/simulation/<id>/run-status`, `/api/report/generate`, `/api/graph/project/list`.

**API Anything** (`goodnight000/api-anything`):

- Node 22.13+ TypeScript MCP server and CLI; MIT. Learns website operations from browser traffic and exposes them over HTTP or MCP.
- Requires a browser automation backend and stores learned operations locally; not a web framework and not a data store.
- Decision: document as an optional development tool, add a status surface only, never call it at runtime.

## 3. Backend

- Schema v1 (`server/src/migrations/001_init.sql`): 28 tables, foreign keys, organization led traffic indexes, JSON text columns, `PRAGMA user_version` migration tracking.
- Chose `node:sqlite` (built into Node 24) to avoid a native build dependency. Verified the module loads before writing the data layer.
- `db.js`: connection, WAL, foreign keys, transaction helper, id generation, JSON helpers.
- `lib/auth.js`: scrypt hashing, hashed session tokens, cookie helpers, `attachUser`, `requireRole`, origin check.
- `lib/http.js`: success and error envelopes, Zod validation, pagination, async wrapper.
- Services: deterministic detection (nine rules including a statistical hourly volume anomaly), native simulation engine (five scenarios, seeded PRNG, round driver), phishing scanner with SSRF validation, MiroFish HTTP adapter, report builder.
- Routers: auth, overview, events, assets, incidents, investigations, threat intel, detections, phishing, vulnerabilities, automation, forensics, network, reports, simulations, settings. SSE endpoint and `/api/docs` index in `index.js`.
- Seed: 14 assets, 276 events including live-window bursts, 150+ flows, 12 indicators, 12 vulnerabilities, 8 incidents with timelines, 4 investigations, 4 workflows, 4 sealed evidence files, 2 executed simulations, 3 reports, audit entries.
- Fixed a real SQL bug before running: SQLite `datetime('now')` does not compare to ISO-8601 strings with a `T` separator. Window filters now bind generated ISO timestamps.
- First boot succeeded and produced 276 events and 14 detections, including two from the credential stuffing burst.

## 4. Backend verification

- Smoke script against 27 read endpoints: all 200.
- Mutation script: asset, incident, investigation, note, ingest, detection run, feedback, promotion, simulation create and start (completed with 15 events and risk 36), report generate and download, workflow run and approval, evidence upload and verify, network ingest, indicator add, lookups, SSRF refusal, RBAC refusal.
- Fixed the report download false negative in PowerShell (`Invoke-WebRequest` quirk); the endpoint returned 200 and 4.6 kB of Markdown when checked with curl.

## 5. Frontend

- Vite 6, React 19, TypeScript 5.7, Tailwind v4 via `@tailwindcss/vite`, `lucide-react` icons. No chart or UI kit dependency.
- Design tokens and a component layer in `styles.css`, then: UI primitives, SVG charts, app shell with mobile drawer and focus management, error boundary.
- Pages: landing, login, signup, privacy, terms, 404, overview, monitoring, assets, incidents and detail, investigations and detail, threat intel, detections, phishing, vulnerabilities, network, forensics, automation, reports, simulations and detail, people, settings.
- Build succeeded (506 kB JS, 140 kB gzip).

## 6. Frontend verification and fixes

- The first browser pass exposed a blank page on every paginated module: the API client unwrapped `data` from `{ data, meta }`, leaving `meta` undefined. Changed the client to preserve the envelope when `meta` exists. This was a single root cause across twelve screens.
- Added a top level error boundary after diagnosing that defect, so a render failure shows a diagnostic instead of a blank screen.
- Mobile fixes: top bar wrapping, nav link wrapping, two column grids at narrow widths, table density, chart axis rounding, hidden persona column, 2 x 2 KPI grids.
- Verified in the browser: login, overview aggregates, monitoring, assets, incident creation and transition and note, detections queue, threat intel, simulation create and live run to completion, reports, settings, integration statuses.

## 7. Tests

- Six `node:test` files with a harness that boots an isolated server per file on a random port with a temporary database.
- 30 tests covering auth, RBAC, tenant isolation, origin rejection, detection rules and de-duplication, incident lifecycle, simulation execution and cancellation, SSRF refusals, evidence integrity and tamper detection, reports and workflow approval.
- Fixed two failures found by the suite: a test asserted 404 where RBAC correctly returned 403 first, and evidence storage ignored `SF_DATA_DIR` (a genuine bug, now fixed).

## 8. Documentation and packaging

- README, architecture, API reference, security, deployment, project status, this log, remaining work, and three integration documents.
- `.env.example`, `.gitignore`, multi stage `Dockerfile`, `docker-compose.yml`, GitHub Actions workflow.

## 9. Security hardening pass (after the first delivery)

A review of the finished build found one defect that mattered more than any missing feature: **a production deployment would have seeded a workspace with the public demo admin password**, and those passwords were compiled into the client bundle. Closed as follows.

- Demo seeding is now gated by `SF_DEMO_MODE`, defaulting to off when `NODE_ENV=production`. The first production admin comes from `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD`; without them the server refuses to start and prints instructions.
- The login page fetches demo accounts from `/api/auth/demo-accounts` at runtime, so a production build contains no demo password. Verified by searching the built bundle for `Admin#2026` (not present).
- TOTP multi-factor authentication (schema v2): enrolment with password confirmation, eight single use recovery codes, a five minute login challenge that issues no session until a valid code arrives, and self-service disable with password plus code. Recovery codes are stored as SHA-256 hashes and removed when used.
- Session cap of ten, rotation on password change (all sessions deleted, a fresh one issued), and a "sign out other sessions" action.
- SSRF address pinning: the URL scanner now resolves and validates once, then passes the chosen address to a custom DNS lookup inside `http`/`https.request`, closing the rebinding window between validation and connection at every redirect hop.
- Sealed evidence download now requires analyst or admin (viewers could previously download files).
- The test suite grew from 30 to 33, adding the full MFA lifecycle and demo-mode gating. All pass.

## Decisions worth remembering

| Decision | Alternative rejected | Why |
| --- | --- | --- |
| SQLite through `node:sqlite` | PostgreSQL with a container | No external service or credentials in this environment; keeps the app runnable with `npm start` |
| Deterministic detection with stored factors | Model based scoring | Auditable, testable, and defensible as a baseline |
| Native simulation engine | Calling MiroFish for the lab | MiroFish cannot run here; inventing MiroFish results would be dishonest |
| Session cookie plus origin check | Bearer token in local storage | Scripts cannot read the cookie; revocation is immediate |
| Hand written SVG charts | Chart library | Smaller bundle, consistent styling, no licence questions |

## Reproduce the verification

```powershell
npm run install:all
npm test
npm run typecheck
npm run build
npm start
# open http://localhost:4000 and sign in with analyst@secureflow.dev / Analyst#2026
```
