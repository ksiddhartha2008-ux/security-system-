# SecureFlow AI

An intelligent cybersecurity operations platform: one application for monitoring, detection, incident response, investigation, evidence handling and threat simulation on synthetic data.

The repository is a working full stack application, not a mockup. The React client talks to a Node API over HTTP; every list, detail page and action reads or writes the SQLite database through the server. A multi-agent simulation engine and an isolated MiroFish adapter power the Threat Simulation Lab.

---

## Problem and audience

Small and medium businesses and educational institutions usually run a handful of disconnected tools. A failed sign-in lives in one log, a suspicious request in a web server, an incident in a spreadsheet, and evidence in a shared folder. SecureFlow AI puts the operational path in one application: collect events, evaluate deterministic rules, score and correlate them, open an incident, record the investigation and the evidence hash, and produce a report.

The intended users are security analysts and IT administrators in organisations without a full security operations centre, and students or instructors who need a realistic, self-hosted lab. The application is honest about what is simulated: demo records, simulation runs and response automation actions are labelled, and there is no machine learning model in the decision path.

## Modules and status

Status labels: **IMPLEMENTED** (works, not directly covered by an automated test), **TESTED** (automated tests executed and passed), **SIMULATED** (demonstration behaviour, labelled in the UI), **PARTIALLY IMPLEMENTED** (core works, a named capability is absent), **PLANNED** (not built), **UNVERIFIED** (not run here).

| # | Module | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Authentication and access control | TESTED | `backend/tests/auth.test.mjs`, `mfa.test.mjs`, `isolation.test.mjs` |
| 2 | Security overview dashboard | IMPLEMENTED | SQL aggregates; manual browser walkthrough |
| 3 | Live security monitoring | TESTED | `backend/tests/detection.test.mjs`; streaming checked manually |
| 4 | Threat intelligence | PARTIALLY IMPLEMENTED | Local IOC store and lookup tested; external providers need keys and are unconfigured |
| 5 | Asset management | IMPLEMENTED | Asset API and inventory used by detection and website protection |
| 6 | Incident management | TESTED | `backend/tests/workflow.test.mjs` |
| 7 | Threat investigation | IMPLEMENTED | Investigation routes, notes and findings; manual check |
| 8 | Detection centre, deterministic | TESTED | `backend/tests/detection.test.mjs`, `website-detection.test.mjs`. AI-assisted scoring is PLANNED and not implemented |
| 9 | Phishing URL scanner | TESTED | `backend/tests/security.test.mjs`, SSRF and scheme cases |
| 10 | Vulnerability management | IMPLEMENTED | Register, CVSS, remediation status; demo data |
| 11 | Security automation (SOAR) | TESTED for the approval gate; actions SIMULATED | `backend/tests/workflow.test.mjs`; no EDR or firewall is connected |
| 12 | Digital forensics | TESTED | `backend/tests/workflow.test.mjs`, SHA-256 and tamper detection |
| 13 | Network monitoring | IMPLEMENTED | Flow list, summary and ingestion; manual check |
| 14 | Reports and analytics | TESTED | `backend/tests/workflow.test.mjs`, export formats |
| 15 | Settings and administration | TESTED | `backend/tests/auth.test.mjs`; audit chain verification |
| + | Website protection | TESTED, launch gate G1 blocked | `backend/tests/website-*.test.mjs`; [status](docs/website/STATUS.md) |
| + | Threat simulation lab | TESTED, all data SIMULATED | `backend/tests/simulation.test.mjs` |
| + | Demo data management | TESTED | `backend/tests/demo.test.mjs` |

No LLM, prompt template engine or agent framework exists in the repository. Detection is deterministic and explainable; the interface says so where scores appear. See [PROMPT_ENGINE_SECURITY_AUDIT.md](docs/PROMPT_ENGINE_SECURITY_AUDIT.md).

Five simulation scenarios: credential stuffing, API abuse, phishing, insider threat and ransomware.

---

## Quick start

Requirements: Node.js 22.5 or newer (Node 24 is used here) because the server uses the built-in `node:sqlite` module. No external database is required.

```powershell
# from the repository root
npm run install:all      # installs server and web dependencies

# development: API on :4000, Vite dev server on :5173
npm run dev:api          # terminal 1
npm run dev:web          # terminal 2, open http://localhost:5173

# or a production style run
npm run build            # builds frontend/dist
npm start                # serves the API and the built client on http://localhost:4000
```

The first start creates `backend/data/secureflow.db` and seeds a demo workspace with synthetic records. Demo mode is on by default outside production. Deleting the database and restarting re-seeds it. `npm run seed` reseeds explicitly (`--force`).

In production, demo mode is off. The first start requires `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD` (12 or more characters) to create the first admin, or it exits with instructions. It will never seed a public admin password into a production database.

### Demo accounts

| Role | Email | Password |
| --- | --- | --- |
| Admin | `admin@secureflow.dev` | `Admin#2026` |
| Security analyst | `analyst@secureflow.dev` | `Analyst#2026` |
| Viewer | `viewer@secureflow.dev` | `Viewer#2026` |

All seeded records are synthetic and labelled **Demo data** in the interface.

The sign-in screen offers a demo profile picker: choose Administrator, Security Analyst or Viewer, then continue with the seeded account. The button performs a real backend login; it is not a browser-only session. The same screen keeps an email and password form for a workspace account and for production. See [LOGIN_AND_DEMO_ACCESS.md](docs/LOGIN_AND_DEMO_ACCESS.md).

---

## Project layout

```
.
├── backend/                   Node 24 + Express API
│   ├── src/
│   │   ├── index.js           app wiring, security headers, SPA hosting, SSE
│   │   ├── db.js              node:sqlite connection, migrations, helpers
│   │   ├── migrations/        schema v1 to v5 (41 tables, foreign keys, indexes)
│   │   ├── seed.js            deterministic synthetic demo workspace
│   │   ├── lib/               http envelope, auth, audit, rate limit, events
│   │   ├── routes/            module routers, settings, demo data, streaming
│   │   └── services/          detection, correlation, demo, simulation, phishing, MiroFish, reports, website protection
│   └── tests/                 91 node:test integration and unit tests
├── frontend/                  React 19 + TypeScript + Vite + Tailwind CSS v4 + Astryx 0.7
│   └── src/
│       ├── pages/             one page per module, public pages, detail views
│       ├── components/        design system, charts, app shell, error boundary
│       ├── lib/theme/         SecureFlow Astryx theme source and generated CSS
│       └── lib/               API client, auth context, hooks, formatting
├── docs/                      audits, guides, API reference, security and simulation documentation
├── scripts/                   development verification and smoke scripts
├── packages/sdk-node/         server side Node SDK, private, zero runtime dependencies
├── third_party/               MiroFish and API Anything sources (inspected, not vendored into the app)
├── Dockerfile                 multi stage build, non-root runtime
├── docker-compose.yml
├── .env.example
└── package.json               root scripts for both applications
```

---

## How a signal becomes an incident

```
Event ingestion (session API or website SDK key)
  -> strict validation and normalization
  -> security_events (org scoped, origin labelled)
  -> deterministic rules (at ingest, post commit and on demand)
  -> risk score from severity, stored factors, asset criticality and confidence
  -> correlation by asset, website, source address and actor
  -> incident with a timeline and linked evidence
  -> investigation notes and findings
  -> approval gated response (actions recorded as simulated)
  -> audit hash chain and reports
```

Website events follow the same path after the API key resolves the organization and site. The decision path contains no model inference. A detection stores the factors, weights and observed values that produced its score, so an analyst can audit it.

## How the stack fits together

- **Database**: SQLite in WAL mode through the built-in Node driver. 41 tables with foreign keys and indexes. Every tenant owned table carries `org_id`; the server resolves the organization from the session, never from the request body.
- **Auth**: scrypt password hashes (async on request paths), optional TOTP multi-factor authentication with single use recovery codes, session-bound CSRF tokens, random 256 bit session tokens stored as SHA-256 digests, HttpOnly SameSite=Lax cookie with a seven day expiry, session cap and rotation on password change, origin check on state changing requests, per-route and per-account rate limits.
- **Audit**: append-only hash chain per organization with a verification endpoint, request correlation ids and fail-closed writes.
- **Detection**: eighteen deterministic rules. Nine cover the existing telemetry (brute force, credential stuffing, API abuse, port scan, bulk transfer, ransomware behaviour, phishing interaction, authorization probing, hourly volume anomaly) and nine cover website SDK events (credential stuffing, one account brute force, success after failures, MFA failures, scanning, sensitive paths, injection bursts, repeated denials, known bad address). Each detection stores the factors, weights and observed values that produced its score.
- **Simulation**: a seeded multi-agent engine advances rounds in the background, writes agent activity and events, then computes findings, recommendations and a deterministic risk score. A server restart marks in-flight runs failed rather than pretending they continued.
- **Design system**: Astryx 0.7.13 supplies the shell, navigation, badges, search input and layout primitives. The SecureFlow theme extends neutral with a dark SOC palette and semantic severity colours; it is compiled to CSS and checked in CI. Existing page components stay application owned and inherit the same tokens.
- **Streaming**: Server-Sent Events push new events and simulation rounds to the browser. The UI also polls running simulations, so a dropped stream does not hide progress.

---

## Security remediation status

Applied in the November 2026 hardening pass. Full evidence is in [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) and [SECURITY_PROGRESS.md](docs/SECURITY_PROGRESS.md).

| Control | Status |
| --- | --- |
| Demo credentials removed from production seeding and from the client bundle | Implemented, verified |
| TOTP MFA with single use recovery codes | Implemented, verified |
| Session-bound CSRF tokens, missing-Origin bypass closed | Implemented, verified |
| Account-based login throttling | Implemented, verified |
| Async scrypt on request paths | Implemented, tested |
| Session cap and rotation on password change | Implemented |
| Tamper-evident audit hash chain with verification endpoint | Implemented, verified |
| SOAR approval mandatory for destructive actions, expiry, idempotency, pause | Implemented, verified |
| Evidence magic-byte validation and optional ClamAV scanning | Implemented; live ClamAV unverified |
| CSV formula injection neutralisation | Implemented, verified |
| Production configuration validation (demo mode, HTTPS origins) | Implemented, verified |
| Dependency audit clean (zod 4.6.7) | Verified |
| Light, dark and system themes | Implemented, tested in both themes |
| Organization MFA policy enforcement | Not implemented |
| Password reset and email verification | Blocked on SMTP infrastructure |
| Shared/distributed rate limiting | Implemented with Redis; multi-instance test in CI |
| Audit atomicity with every business write, custody chaining | Partial |

## AI and Prompt Engine status

There is **no LLM, prompt template engine or agent framework** in this repository. Detection is deterministic and explainable; the UI says so. [PROMPT_ENGINE_SECURITY_AUDIT.md](docs/PROMPT_ENGINE_SECURITY_AUDIT.md) records the verification and [PROMPT_ENGINE_ARCHITECTURE.md](docs/PROMPT_ENGINE_ARCHITECTURE.md) defines the requirements for any future model feature. No AI capability is claimed.

## Demo data and the simulation pipeline

A new workspace starts empty, so its dashboard correctly shows zero. An administrator can open **Demo data** and generate a deterministic synthetic workspace: 45 assets, about 258 events, network telemetry, 14 vulnerabilities, then detections and correlated incidents through the real engine. Every record is tagged `DEMO` and a reset removes only that batch.

A sanitized SQLite snapshot of the Meridian demo workspace is published in [demo/README.md](demo/README.md). It contains only synthetic demo records; sessions, audit logs, API keys, evidence and the personal workspace in the local database were removed. Regenerate it with `npm run demo:snapshot`.

Simulation runs are no longer isolated. Each generated event is mirrored into `security_events` as `SIMULATED`, with a dedupe key, and a finished run evaluates the deterministic rules, correlates incidents and refreshes asset risk. See [DATA_FLOW_AUDIT.md](docs/DATA_FLOW_AUDIT.md), [DEMO_DATA_GUIDE.md](docs/DEMO_DATA_GUIDE.md), [SIMULATION_ENGINE.md](docs/SIMULATION_ENGINE.md) and [DASHBOARD_DATA_DICTIONARY.md](docs/DASHBOARD_DATA_DICTIONARY.md).

## Website protection

A business owner registers a website, proves ownership with a DNS TXT record, creates a scoped API key, installs the Node SDK and sees website events, detections and incidents in the same application.

1. `POST /api/v1/websites` normalizes the URL, rejects IP literals, public suffixes and reserved names, and returns the exact TXT record to publish.
2. `POST /api/v1/websites/:id/verify` performs one DNS check. A scheduler retries pending checks and re-checks verified websites daily. Resolver errors never count as failures.
3. A verified website becomes an asset of type `website`. A key is created only for a verified site, only by an admin, only after a password re-entry inside ten minutes, and the secret is shown once.
4. `POST /api/v1/ingest/website-events` accepts batches authenticated by the key alone. The organization and site come from the key. Duplicates are counted, not stored twice.
5. Nine deterministic website rules create detections. Correlation groups them by shared website, source address and account so one attack becomes one incident. Notifications are throttled and every suppression records a reason.

The workflow is documented in [docs/website/STATUS.md](docs/website/STATUS.md), with the reuse map, decisions, event mapping and evidence files beside it. Website protection is on by default outside production and off in production until the launch gates are accepted. Set `SF_WEBSITE_PROTECTION=true` to override.

Production readiness is **not** claimed. Gate G1 (verified email addresses) is blocked because the product has no email verification, and no independent penetration test has been performed. The gate matrix records this.

## Testing

```powershell
npm test                 # 121 backend tests, isolated database per test file
npm run test:sdk         # 13 SDK tests against a local HTTP server
npm run check:theme      # Astryx theme output matches the source
npm run typecheck        # TypeScript project check`nnpm run test:a11y --prefix frontend  # 37 Playwright and axe checks in both themes
npm run build            # production bundle
```

Verified on 13 November 2026: 121 backend tests, 119 passing, 2 skipped without Redis, 0 failing; 13 SDK tests passing; 37 accessibility checks passing. Production bundle: 862 kB initial JavaScript (278 kB gzip) and 324 kB CSS (55.7 kB gzip), with module routes lazy loaded.

Coverage includes registration and login, TOTP enrolment and login step-up, recovery code single use, session rotation, CSRF token enforcement, account-based login throttling, RBAC (viewer/analyst/admin), cross-tenant isolation, detection rules and de-duplication, incident lifecycle guards, simulation execution and cancellation, simulation-to-event pipeline, demo generation and safe reset, SSRF protection (including private ranges), evidence signature and tamper detection, audit hash chain, SOAR approval enforcement, CSV formula neutralisation, production config validation, report export and the workflow approval gate. Website protection adds URL normalization, DNS verification, key lifecycle, ingestion limits, idempotency, tenant isolation, incident correlation, notification throttling, scheduler leases, retention, export, deletion and the SDK reliability suite.

---

## Configuration

Copy `.env.example` to `.env` or export the variables in your shell. Nothing is required for local use. External providers are only called when their key exists, and the interface states when they are unconfigured.

| Variable | Purpose |
| --- | --- |
| `PORT`, `SF_DATA_DIR`, `SF_DB_PATH` | Server port and storage location |
| `SF_DEMO_MODE` | `true` seeds the synthetic demo workspace with known accounts. Defaults to on outside production, off in production |
| `SF_BOOTSTRAP_EMAIL`, `SF_BOOTSTRAP_PASSWORD`, `SF_BOOTSTRAP_ORG`, `SF_BOOTSTRAP_NAME` | First admin created on an empty production database |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Optional reputation enrichment |
| `WAZUH_API_URL`, `SYSMON_COLLECTOR_URL`, `SURICATA_EVE_PATH`, `ZEEK_LOG_PATH`, `CLAMAV_HOST`, `YARA_RULES_PATH` | Integration status and adapter hooks |
| `MIROFISH_BASE_URL`, `MIROFISH_API_KEY` | Optional separate MiroFish service |
| `API_ANYTHING_ENABLED` | Documents the optional development tool |
| `SF_WEBSITE_PROTECTION` | Website protection. Default on outside production and off in production |
| `SF_ALLOW_TEST_HOSTNAMES` | Allows `.test` hostnames for development and tests. Rejected in production |
| `SF_WEBSITE_VERIFICATION_GRACE_DAYS` | Days a failing re-verification may last before the website lapses. Default 14 |
| `SF_DNS_RESOLVERS` | Optional comma separated DNS servers for verification. Default the system resolver |
| `SF_PLATFORM_DOMAINS` | Comma separated platform domains that cannot be registered |
| `SF_SDK_HEARTBEAT_SECONDS`, `SF_NOTIFICATION_HOURLY_CAP` | Health threshold and notification cap |

External integrations currently report configuration state and expose ingestion endpoints; they do not ship working collectors for every product. This is stated again under limitations.

---

## Deployment

```powershell
npm run build            # builds frontend/dist
npm start                # API and built client on PORT, default 4000
```

- Migrations run automatically at startup and are tracked with `PRAGMA user_version`. The current schema is v5, 41 tables.
- The database and evidence files live in `SF_DATA_DIR` (default `backend/data`). Mount a persistent volume in a container.
- `Dockerfile` is a multi stage build with a non-root runtime user. `docker-compose.yml` maps port 4000 and a data volume.
- Put a TLS terminating reverse proxy in front, set `SF_TRUST_PROXY=true` only when that proxy overwrites `X-Forwarded-For`, and keep the session cookie `Secure` in production.
- `GET /api/health` is the liveness probe. `GET /api/health/ready` also checks the database and names the rate limit store. Neither contains tenant data.
- Single node SQLite is the supported runtime. Shared rate limiting is available with `SF_REDIS_URL`. PostgreSQL schema and data migration tooling exists, but application runtime support is not implemented; see [docs/remediation/DATABASE_MIGRATION_REPORT.md](docs/remediation/DATABASE_MIGRATION_REPORT.md).

No deployment was performed as part of this repository work. See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full procedure.

## Third party repositories

Both supplied archives were extracted to `third_party/` and read before any integration work:

- **MiroFish** (`666ghj/MiroFish`, AGPL-3.0) is a Flask service with `/api/graph`, `/api/simulation` and `/api/report` blueprints. It needs Python 3.11-3.12, an OpenAI compatible LLM key and a Zep Cloud key, so it cannot run in this environment and is not bundled. SecureFlow contains a real HTTP adapter that reports an honest unconfigured state and can import a finished remote run as a read-only record. See [docs/MIROFISH_INTEGRATION.md](docs/MIROFISH_INTEGRATION.md).
- **API Anything** (`goodnight000/api-anything`, MIT) is a local MCP server and CLI that learns website operations for agents. It is documented as an optional development tool only, never a runtime dependency, and no credentials are shared with it. See [docs/API_ANYTHING_INTEGRATION.md](docs/API_ANYTHING_INTEGRATION.md).

Neither repository is copied into the frontend or backend. The Threat Simulation Lab runs on the SecureFlow native engine.

---

## Limitations

- Detection rules are threshold based and deterministic. There is no machine learning model in the decision path; the interface says so where scores appear.
- Response automation records actions as **simulated** because no EDR, firewall or identity integration is configured. It does not isolate hosts or block addresses.
- External integration collectors (Wazuh, Sysmon, Suricata, Zeek, ClamAV, YARA) are configuration surfaces plus ingestion APIs, not finished connectors.
- Retention is a stored target value for existing module data; website events now have a retention job, but evidence and incident records have no automatic deletion.
- Website protection launch gate G1 is blocked: the product has no email verification, so an account with a verified address cannot be required before adding a website. The feature is off by default in production.
- DNS verification uses the system resolver by default. Two-resolver corroboration is not implemented.
- Website notifications are in-app only. There is no email or webhook delivery, and suppression is recorded rather than retried.
- There is no browser SDK and no request blocking. Events arrive only from explicit `track()` calls on the server.
- Account deletion and password reset email are not implemented. There is no SMTP configuration, so no email is sent.
- Multi-factor authentication is TOTP only. WebAuthn security keys and SSO are not implemented.
- The URL scanner fetches a single page and does not execute JavaScript. A low score is not proof that a site is safe.
- SQLite suits a single node deployment. Moving to PostgreSQL means replacing the driver layer and adapting SQL dialect details.
- MiroFish cannot be executed here (Python version and external LLM/Zep credentials), so only its adapter and unconfigured path are verified.

---

## Roadmap

Priority order, with the reason each item is not done today.

1. **Email verification and password reset.** Needs SMTP infrastructure. This is also website protection gate G1, so it blocks enabling that feature for customers.
2. **Shared rate limiting and a PostgreSQL path.** Plan written, not implemented. Single node SQLite is the current limit.
3. **Independent security assessment.** Local tests and a self-review do not replace a penetration test.
4. **Real collectors and integrations.** Wazuh, Sysmon, Suricata, Zeek, ClamAV, YARA and reputation providers are configuration surfaces plus ingestion APIs. No finished connectors ship.
5. **SSO and WebAuthn.** TOTP MFA exists; organisation-wide MFA policy and hardware authenticators do not.
6. **Browser SDK and automatic key rotation.** Website protection is server side by design. Rotation is manual with a two key overlap.
7. **AI-assisted scoring, only as advice.** No model exists. Any future model must not lower a rule severity and needs a timeout with a rule-only fallback.
8. **Accessibility audit at 360 px and with a screen reader.** The interface is keyboard operable and labelled, but no automated engine was run.

## Screenshots

No screenshots are committed. The interface was exercised in a real browser during the website protection walkthrough, and the steps and results are recorded in [docs/website/verification/W4.1.md](docs/website/verification/W4.1.md). Adding stock or mock screenshots would misrepresent the application, so none are included. Run the app locally to see the current UI.

## Documentation

- [docs/README.md](docs/README.md) - documentation index by category
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - components, data model, request flow
- [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) - endpoint reference
- [SECURITY.md](docs/SECURITY.md) - controls, threat model, reporting
- [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) - findings with severity and evidence
- [SECURITY_REMEDIATION_PLAN.md](docs/SECURITY_REMEDIATION_PLAN.md) and [SECURITY_PROGRESS.md](docs/SECURITY_PROGRESS.md)
- [SECURITY_TEST_MATRIX.md](docs/SECURITY_TEST_MATRIX.md) - control to test mapping
- [PROMPT_ENGINE_SECURITY_AUDIT.md](docs/PROMPT_ENGINE_SECURITY_AUDIT.md) - confirms no LLM exists
- [SECURITY_DEPENDENCY_REPORT.md](docs/SECURITY_DEPENDENCY_REPORT.md) and [PRODUCTION_SECURITY_CHECKLIST.md](docs/PRODUCTION_SECURITY_CHECKLIST.md)
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - local, Docker and reverse proxy notes
- [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) - module by module status and evidence
- [IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) - what was built and verified
- [REMAINING_WORK.md](docs/REMAINING_WORK.md) - honest backlog
- [docs/THREAT_SIMULATION_LAB.md](docs/THREAT_SIMULATION_LAB.md) - engine, scenarios, scoring
- [docs/MIROFISH_INTEGRATION.md](docs/MIROFISH_INTEGRATION.md) and [docs/API_ANYTHING_INTEGRATION.md](docs/API_ANYTHING_INTEGRATION.md)
