# Data flow audit

Date: 9 November 2026. This audit explains why a workspace showed zero events, incidents, detections and assets while simulations reported completed runs, and what was changed.

## Observed state

Queried directly from `backend/data/secureflow.db` before the fix:

| Organization | Assets | Security events | Simulations |
| --- | ---: | ---: | ---: |
| `org_meridian` (seeded demo workspace) | 14 | 276 | 3 |
| `org_g24xbs0jp4r9` ("microsoft", created through signup) | 0 | 0 | 3 |

The dashboard was not broken. It reads through the same tenant filter as every other API:

```sql
SELECT COUNT(*) FROM security_events WHERE org_id = ?
```

The signed-in workspace was a **new, empty organization**, so every aggregate correctly returned zero. The seeded demo data belonged to a different organization and was invisible by design.

Separately, the three completed simulations in that workspace produced no dashboard records because the engine wrote to a different table.

## Root cause 1: empty workspace onboarding

Registration creates an organization with no assets, events, incidents or vulnerabilities. Nothing seeds a new tenant, so a fresh account sees an empty product. This is correct multi-tenant behaviour but poor onboarding, and it makes a finished dashboard look broken.

## Root cause 2: simulation output bypassed the event pipeline

The engine wrote only to `simulation_events`:

```sql
INSERT INTO simulation_events (...)
```

It never wrote to `security_events`, never invoked `evaluateRules`, never correlated incidents and never refreshed asset risk. `simulation_events` feeds the simulation timeline and report, not the dashboard. That is why "simulations completed = 2/3" and "mean simulated risk = 63" could both be true while events, detections and incidents stayed at zero.

## Root cause 3: no data origin classification

There was no way to distinguish seeded demo records, simulation output and real telemetry. A reset therefore could not safely target only synthetic rows, and the UI could not label origins per record.

## Fixes implemented

| Problem | Fix |
| --- | --- |
| New workspace has no data | Per-workspace demo generator: 45 assets, ~258 events, network telemetry, 14 vulnerabilities, detections and correlated incidents |
| Simulation isolated from dashboard | Every generated simulation event is mirrored into `security_events` with `data_origin = SIMULATED`, a deterministic dedupe key and the simulation id |
| Detections not produced by simulation | The engine runs `evaluateRules`, `correlateDetections` and `refreshAssetRisk` when a run finishes |
| Detections lost origin | Rule evaluation accepts an origin hint; detections inherit the source event or asset origin, then the hint |
| Asset risk stayed flat | `refreshAssetRisk` now counts `open` and `confirmed` detections, not only `open` |
| Cannot separate demo from real | `data_origin` on assets, events, detections, incidents, vulnerabilities and network events; `demo_batch_id` for batches |
| Unsafe reset | Reset deletes only `data_origin = 'DEMO'` rows for the caller's organization; real and simulated records are untouched |
| Duplicate runs | Simulation event dedupe key `sim:<simulationId>:<round>:<index>` with a unique index; demo generation refuses to stack batches |

## Database changes (migration v4)

- `data_origin` and `demo_batch_id` on `assets`, `security_events`, `detections`, `incidents`, `vulnerabilities`, `network_events`.
- `security_events.dedupe_key` (partial unique index per organization) and `simulation_id`.
- `demo_runs` table for generate/reset history.
- Existing `org_meridian` rows are labeled `DEMO` with batch `seed-v1`; other organizations default to `REAL`.

## Verification

Automated tests (`backend/tests/demo.test.mjs`):

1. Generation creates 45 assets, ≥250 events, ≥5 detections, ≥3 incidents, 14 vulnerabilities and ≥80 flows.
2. Dashboard summary equals the generated event count.
3. Every listed event and incident is labeled `DEMO`.
4. A second generation returns 409.
5. A second organization sees zero records (tenant isolation).
6. Reset removes only DEMO rows; a real asset and a real incident survive.
7. Reset without `confirm: "RESET"` returns 400.
8. A brute-force simulation writes `SIMULATED` events, creates detections and updates dashboard totals.
9. A reset with no demo batch returns `nothingToDo` and leaves simulated events in place.
10. Viewer and analyst roles cannot manage demo data.

Full suite: 47 tests passing.

## What is still not automatic

- Existing simulation runs created before this change are not backfilled into `security_events`. Only new runs feed the pipeline.
- Demo generation is manual per workspace (the Demo data page). It is not triggered at signup, to avoid silently creating synthetic data for a real tenant.
- PostgreSQL row level security remains a future migration; tenant filtering is application level and tested.
