# Demo data guide

## What it is

A per-workspace synthetic dataset built through the real ingestion, detection and correlation path. Dashboard numbers are computed from the database; no widget is fed hardcoded values.

A generated batch contains:

| Record | Count |
| --- | ---: |
| Assets | 45 (workstations, Linux servers, web, database, application, network, cloud) |
| Security events | about 258 across identity, endpoint, email, application and network |
| Network flows | about 97, including a port sweep and a large outbound transfer |
| Vulnerabilities | 14 (well known CVE identifiers plus two clearly illustrative findings) |
| Detections | produced by the deterministic rules, not inserted manually |
| Incidents | correlated from high risk detections with event and detection links |

## Data classification

`data_origin` exists on assets, security events, detections, incidents, vulnerabilities and network events:

| Value | Meaning | Removed by reset |
| --- | --- | --- |
| `DEMO` | Synthetic workspace data generated here or by the seeder | Yes |
| `SIMULATED` | Events emitted by the Threat Simulation Lab | No |
| `REAL` | Telemetry ingested by the customer | No |
| `TEST` | Reserved for future test fixtures | No |

`demo_batch_id` groups one generation so a batch can be identified in the UI and audit trail. The UI shows `demo` and `simulated` badges on records that are not real.

## Using the feature

1. Sign in as an administrator of the workspace.
2. Open **Demo data** in the sidebar.
3. Select **Generate demo data**. It refuses if the workspace already has a demo batch; reset first.
4. Open **Overview**, **Monitoring**, **Incidents**, **Detections**, **Assets**, **Vulnerabilities** or **Network** to explore.
5. Run one of the five scenarios or **Run all five** to exercise the simulation pipeline.
6. To remove the synthetic workspace, select **Reset demo data**, type `RESET` and confirm.

## API

All endpoints require a session; mutations require the `x-csrf-token` header like every other write.

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/api/demo/status` | any authenticated | Counts by origin, batch id, recent runs |
| GET | `/api/demo/runs` | admin | Seed execution history |
| POST | `/api/demo/generate` | admin | Create a demo batch |
| POST | `/api/demo/reset` | admin | Delete DEMO rows; body `{ "confirm": "RESET" }` |
| POST | `/api/demo/scenarios/:key/run` | admin | Create and start one scenario |
| POST | `/api/demo/scenarios/run-all` | admin | Start the five demo scenarios |

Simulation runs are also available through the normal `/api/simulations` endpoints.

## Safety guarantees

- Generation and reset are scoped to `req.user.orgId`; the organization is never taken from the request body.
- Reset deletes only rows with `data_origin = 'DEMO'` in that organization. Real events, incidents, evidence, audits and simulations are preserved.
- Every generate, reset and scenario action writes an audit row.
- Generation is transactional. Detection and correlation run after the inserts commit; a failure is reported rather than leaving a partially counted batch.
- A second generation without a reset returns `409 Conflict`.
- Simulation events use a dedupe key per run, round and index, so a repeated tick cannot double count.

## Role rules

- Viewer: read-only; cannot generate, reset or start scenarios.
- Analyst: can read status; cannot manage demo data.
- Admin: full control.

## Reset behaviour in detail

Deletion order inside one transaction:

1. `incident_events` for DEMO incidents
2. `incidents` with `data_origin = 'DEMO'`
3. `detections` with `data_origin = 'DEMO'`
4. `security_events` with `data_origin = 'DEMO'`
5. `network_events`, `vulnerabilities`, `assets` with `data_origin = 'DEMO'`

Simulated runs, real telemetry and forensic evidence are not touched. A reset with no demo batch returns `{ nothingToDo: true }`.

## Tests

`backend/tests/demo.test.mjs` covers generation, counts, dashboard consistency, duplicate prevention, tenant isolation, role enforcement, reset confirmation, preservation of real records, simulation pipeline output and simulated-event preservation.

Commands:

```powershell
npm test
npm run typecheck --prefix frontend
npm run build --prefix frontend
```

## Limitations

- The dataset is representative, not a copy of any real environment.
- Existing simulation runs created before migration v4 are not backfilled into the event pipeline.
- Demo generation is manual. A new workspace stays empty until an admin generates data or ingests telemetry.
- Reset does not remove simulation runs; delete those from the simulation lab if needed.
