# SecureFlow AI

An intelligent cybersecurity operations platform: one application for monitoring, detection, incident response, investigation, evidence handling and threat simulation on synthetic data.

The repository is a working full stack application, not a mockup. The React client talks to a Node API over HTTP; every list, detail page and action reads or writes the SQLite database through the server. A multi-agent simulation engine and an isolated MiroFish adapter power the Threat Simulation Lab.

---

## What is inside

| Area | Modules |
| --- | --- |
| Operations | Security overview, live monitoring, threat intelligence, asset inventory |
| Response | Incidents with a lifecycle and timeline, investigations with notes and findings, deterministic detections, phishing URL scanner |
| Exposure | Vulnerability register, network flows, digital forensics with SHA-256 and chain of custody |
| Programme | Response automation with an approval gate, reports with Markdown/CSV/JSON export, Threat Simulation Lab |
| Workspace | Role based access (admin, analyst, viewer), TOTP multi-factor authentication, organization settings, integration status, audit log, system health |

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
npm run build            # builds web/dist
npm start                # serves the API and the built client on http://localhost:4000
```

The first start creates `server/data/secureflow.db` and seeds a demo workspace with synthetic records. Demo mode is on by default outside production. Deleting the database and restarting re-seeds it. `npm run seed` reseeds explicitly (`--force`).

In production, demo mode is off. The first start requires `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD` (12 or more characters) to create the first admin, or it exits with instructions. It will never seed a public admin password into a production database.

### Demo accounts

| Role | Email | Password |
| --- | --- | --- |
| Admin | `admin@secureflow.dev` | `Admin#2026` |
| Security analyst | `analyst@secureflow.dev` | `Analyst#2026` |
| Viewer | `viewer@secureflow.dev` | `Viewer#2026` |

All seeded records are synthetic and labelled **Demo data** in the interface.

---

## Project layout

```
.
├── server/                    Node 24 + Express API
│   ├── src/
│   │   ├── index.js           app wiring, security headers, SPA hosting, SSE
│   │   ├── db.js              node:sqlite connection, migrations, helpers
│   │   ├── migrations/        schema v1 and v2 (29 tables, foreign keys, indexes)
│   │   ├── seed.js            deterministic synthetic demo workspace
│   │   ├── lib/               http envelope, auth, audit, rate limit, events
│   │   ├── routes/            module routers, settings, streaming
│   │   └── services/          detection, simulation engine, phishing, MiroFish, reports
│   └── tests/                 30 node:test integration tests
├── web/                       React 19 + TypeScript + Vite + Tailwind CSS v4
│   └── src/
│       ├── pages/             one page per module, public pages, detail views
│       ├── components/        design system, charts, app shell, error boundary
│       └── lib/               API client, auth context, hooks, formatting
├── docs/                      integration and simulation documentation
├── third_party/               MiroFish and API Anything sources (inspected, not vendored into the app)
├── Dockerfile                 two stage build, non-root runtime
└── docker-compose.yml
```

---

## How the stack fits together

- **Database**: SQLite in WAL mode through the built-in Node driver. 29 tables with foreign keys and indexes. Every tenant owned table carries `org_id`; the server resolves the organization from the session, never from the request body.
- **Auth**: scrypt password hashes, optional TOTP multi-factor authentication with single use recovery codes, random 256 bit session tokens stored as SHA-256 digests, HttpOnly SameSite=Lax cookie with a seven day expiry, session cap and rotation on password change, origin check on state changing requests, per-route rate limits.
- **Detection**: nine deterministic rules (brute force, credential stuffing, API abuse, port scan, bulk transfer, ransomware behaviour, phishing interaction, authorization probing, hourly volume anomaly). Each detection stores the factors, weights and observed values that produced its score.
- **Simulation**: a seeded multi-agent engine advances rounds in the background, writes agent activity and events, then computes findings, recommendations and a deterministic risk score. A server restart marks in-flight runs failed rather than pretending they continued.
- **Streaming**: Server-Sent Events push new events and simulation rounds to the browser. The UI also polls running simulations, so a dropped stream does not hide progress.

---

## Testing

```powershell
npm test                 # 30 integration tests, isolated database per test file
npm run typecheck        # TypeScript project check
npm run build            # production bundle
```

Verified on 8 November 2026: 33 passing, 0 failing. Production bundle: 503 kB JavaScript (139 kB gzip) and 25 kB CSS.

Coverage includes registration and login, TOTP enrolment and login step-up, recovery code single use, session rotation, RBAC (viewer/analyst/admin), cross-tenant isolation, CSRF origin rejection, detection rules and de-duplication, incident lifecycle guards, simulation execution and cancellation, SSRF protection (including private ranges), evidence hashing and tamper detection, report export and the workflow approval gate.

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

External integrations currently report configuration state and expose ingestion endpoints; they do not ship working collectors for every product. This is stated again under limitations.

---

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
- Retention is a stored target value; no automatic deletion job runs.
- Account deletion and password reset email are not implemented. There is no SMTP configuration, so no email is sent.
- Multi-factor authentication is TOTP only. WebAuthn security keys and SSO are not implemented.
- The URL scanner fetches a single page and does not execute JavaScript. A low score is not proof that a site is safe.
- SQLite suits a single node deployment. Moving to PostgreSQL means replacing the driver layer and adapting SQL dialect details.
- MiroFish cannot be executed here (Python version and external LLM/Zep credentials), so only its adapter and unconfigured path are verified.

---

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - components, data model, request flow
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - endpoint reference
- [SECURITY.md](SECURITY.md) - controls, threat model, reporting
- [DEPLOYMENT.md](DEPLOYMENT.md) - local, Docker and reverse proxy notes
- [PROJECT_STATUS.md](PROJECT_STATUS.md) - module by module status and evidence
- [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md) - what was built and verified
- [REMAINING_WORK.md](REMAINING_WORK.md) - honest backlog
- [docs/THREAT_SIMULATION_LAB.md](docs/THREAT_SIMULATION_LAB.md) - engine, scenarios, scoring
- [docs/MIROFISH_INTEGRATION.md](docs/MIROFISH_INTEGRATION.md) and [docs/API_ANYTHING_INTEGRATION.md](docs/API_ANYTHING_INTEGRATION.md)
