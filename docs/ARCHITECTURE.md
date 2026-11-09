# Architecture

## Context

SecureFlow AI is a single node web application with three runtime parts:

```
Browser (React 19 SPA)
   |  HTTPS, HttpOnly session cookie, JSON + SSE
   v
Node 24 API (Express 4)
   |  SQL prepared statements
   v
SQLite (WAL) + evidence files on disk

Optional, isolated:
   Node API  --HTTP-->  MiroFish service (Flask, AGPL-3.0, external credentials)
```

The browser never receives database credentials and never chooses its organization. Everything tenant scoped is resolved from the session on the server.

## Runtime components

| Component | Responsibility |
| --- | --- |
| `backend/src/index.js` | HTTP wiring, security headers, request id, static SPA hosting, SSE endpoint, graceful shutdown |
| `backend/src/db.js` | `node:sqlite` connection, migration runner, query helpers, id generation, transactions |
| `backend/src/lib/auth.js` | scrypt hashes, session cookies, `requireAuth` / `requireRole`, origin check |
| `backend/src/lib/http.js` | error envelope, async wrapper, pagination, validation formatting |
| `backend/src/services/detection.js` | nine deterministic rules, scoring model, explanation payload |
| `backend/src/services/simulation.js` | five scenario definitions, seeded RNG, round driver, outcome scoring, report |
| `backend/src/services/phishing.js` | SSRF-safe URL fetching, heuristics, reputation adapters |
| `backend/src/services/mirofish.js` | HTTP adapter for the separate MiroFish service |
| `backend/src/services/reports.js` | report assembly from live SQL aggregates |
| `frontend/src/lib/api.ts` | typed fetch client, error normalisation, pagination envelope handling |
| `frontend/src/lib/auth.tsx` | session bootstrap, login/logout, permission flags |
| `frontend/src/components/layout.tsx` | navigation, mobile drawer, account menu, skip link |
| `frontend/src/components/ui.tsx` | badges, cards, tables, modals, drawers, toasts, focus trap |

## Request flow

1. `attachUser` reads the `sf_session` cookie, hashes it with SHA-256 and joins the session to its user. Expired sessions are deleted. A disabled user resolves to no session.
2. `checkOrigin` compares `Origin` with `Host` for every non-GET request. Cross-origin writes are rejected even if a cookie leaks.
3. Route middleware applies `requireAuth` and, for writes, `requireRole`. Roles rank `viewer < analyst < admin`; a route may name explicit roles.
4. Handlers read `req.user.orgId` and pass it into every SQL statement. Client supplied `orgId` fields are ignored.
5. Writes that matter are appended to `audit_logs` with actor, resource, IP and metadata.
6. Errors are converted to `{ error: { code, message, details } }`. Stack traces are logged server side and never returned.

## Data model

30 tables in four groups.

**Identity** `organizations`, `users`, `sessions`, `login_attempts`, `audit_logs`.

**Telemetry and detection** `security_events`, `detection_rules`, `detections`, `network_events`, `assets`.

**Response** `incidents`, `incident_events`, `investigations`, `investigation_notes`, `iocs`, `intel_lookups`, `phishing_scans`, `vulnerabilities`, `response_workflows`, `workflow_executions`, `forensic_evidence`, `custody_records`.

**Simulation and reporting** `simulations`, `simulation_agents`, `simulation_events`, `simulation_reports`, `reports`, `integration_configs`.

Key relationships:

```
organizations 1--n users
organizations 1--n assets
assets        1--n security_events
security_events 1--n detections
detections    0..1--1 incidents (via incident_events metadata)
incidents     1--n incident_events
incidents     0..n investigations
investigations 1--n investigation_notes
simulations   1--n simulation_agents / simulation_events
simulations   1--1 simulation_reports
forensic_evidence 1--n custody_records
```

Every tenant table has `org_id` with an index that leads with it (`org_id, <time or score>`). Timestamps are ISO 8601 strings so lexicographic ordering matches chronological ordering. SQLite JSON1 functions are used for a few metadata lookups; the schema stores JSON as text.

## Detection pipeline

```
event ingest (API)
   -> validation
   -> insert security_event
   -> evaluateRules(orgId)
        -> per enabled rule: aggregate query over the rule window
        -> score = base severity + capped factor weights + asset criticality + confidence lift
        -> de-duplicate against detections from the last two hours by signature
        -> insert detection with explanation JSON
   -> refreshAssetRisk(orgId)
   -> broadcast SSE 'event.ingested'
```

The score is deterministic and every factor is stored. The interface shows the factors, the observed values and the score model. No model inference is part of the decision.

## Simulation lifecycle

```
POST /simulations            -> draft, agents materialised from the scenario roster
POST /simulations/:id/start  -> running, driver scheduled with setTimeout per round
   each tick: generate events -> insert events -> update agent activity -> progress
   final tick: computeOutcome -> insert report -> completed (risk score, findings)
POST /simulations/:id/cancel -> cancelled, timer cleared
server restart               -> any 'running' row becomes 'failed' with a reason
```

Runs use a seeded PRNG (`mulberry32`) so a seed and scenario reproduce the event stream. Events carry `metadata.synthetic = true`. Reports carry the same disclaimer in the API, the UI and the downloaded Markdown.

## MiroFish boundary

MiroFish is never imported into the API process. The adapter:

- reads `MIROFISH_BASE_URL` and an optional bearer token from the server environment,
- calls the documented Flask routes with a six second timeout,
- reports `unconfigured`, `reachable` and the latency in the settings and lab screens,
- can import a finished remote run as a read-only SecureFlow simulation record.

Nothing in the request path depends on MiroFish being available.

## Frontend architecture

- **Routing** - `react-router-dom` with public routes (`/`, `/login`, `/signup`, `/privacy`, `/terms`) and an authenticated shell for every module. Unknown paths render a custom 404. Each route sets a document title.
- **Data layer** - a small `useApi` hook with abort handling, plus explicit `api.post/patch/del` calls for mutations. Paginated responses keep their `{ data, meta }` envelope; single resources are unwrapped.
- **Design system** - CSS custom properties plus a small component layer (`.card`, `.btn`, `.badge`, `.table`, `.drawer`) styled with Tailwind v4 utilities where layout benefits. One accent colour, one radius token, severity always paired with a text label.
- **Charts** - hand written SVG components (trend, bars, donut, ranked bars, sparkline, risk gauge) with `<title>` equivalents via `aria-label`. No external chart dependency.
- **States** - every data view has loading skeletons, an error state with retry and an empty state. Mutations surface toasts. A top level error boundary keeps a render failure from blanking the screen.
- **Accessibility** - skip link, focus trap in dialogs and drawers, Escape to close, visible focus rings, `aria-expanded` on disclosure controls, tables with header cells, no colour-only severity.

## Design decisions

| Decision | Reason |
| --- | --- |
| SQLite via `node:sqlite` | Zero external services, no native build step, real relational constraints. |
| No ORM | Queries stay explicit and auditable; the schema is small and stable. |
| Cookie sessions instead of JWT in storage | HttpOnly cookie cannot be read by scripts; server side revocation on disable is immediate. |
| Deterministic detection | A security decision must be explainable and testable; the score model is stored with each detection. |
| Native simulation engine | MiroFish cannot run here (Python 3.11-3.12, LLM and Zep keys). A real engine avoids fake results. |
| SSE plus polling | Live updates without a websocket dependency, with polling as a fallback for long runs. |
| Hand written charts | Keeps the bundle small and the visual language consistent. |

## Scaling path

1. Replace SQLite with PostgreSQL and move `db.js` to a connection pool; the SQL is standard apart from JSON1 usage.
2. Move sessions to a shared store if more than one API instance runs.
3. Put simulation drivers on a queue (the current timers are in-process).
4. Serve the SPA from a CDN and keep the API behind the same origin, or enable a documented CORS origin for a split deployment.
