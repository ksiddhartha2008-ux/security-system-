# Simulation engine

The Threat Simulation Lab runs a native, seeded multi-agent engine. It is not an external attack tool and it never contacts a real host, account or network.

## Scenarios

| Key | Name | Category | Rounds | Primary events |
| --- | --- | --- | ---: | --- |
| `brute-force` | Brute-force attack | identity | 7 | `auth.failure`, `auth.success`, `auth.rate_limited` |
| `phishing` | Phishing campaign | email | 7 | `email.sent`, `email.click`, `email.credential_submit` |
| `malware` | Malware infection | endpoint | 8 | `process.exec`, `malware.detected`, `file.encrypt` |
| `sql-injection` | SQL injection attempt | application | 7 | `web.sql_injection`, `web.request`, `waf.block` |
| `suspicious-admin` | Suspicious administrator login | identity | 8 | `auth.privileged_login`, `authz.grant`, `data.export` |
| `credential-stuffing` | Credential stuffing | identity | 8 | `auth.failure` across many accounts |
| `api-abuse` | API abuse | application | 8 | `api.request`, `api.rate_limit` |
| `insider-threat` | Insider threat | identity | 9 | `data.export`, `device.usb_write` |
| `ransomware` | Ransomware | endpoint | 9 | `process.shadow_copy_delete`, `file.encrypt` |

The five scenarios requested for the demo are brute-force, phishing, malware, SQL injection and suspicious administrator login. The other four remain available for broader rehearsal.

## Execution path

```
POST /api/simulations (draft, agents materialised)
        |
POST /api/simulations/:id/start
        |
  round 1..N (seeded PRNG)
        |
        +--> simulation_events        timeline and report
        |
        +--> security_events          data_origin = SIMULATED, dedupe key
                    |
                    v
          evaluateRules(orgId, { dataOrigin: 'SIMULATED' })
                    |
                    v
          correlateDetections(orgId)   incidents for risk >= 70
                    |
                    v
          refreshAssetRisk(orgId)
                    |
                    v
          dashboard aggregates update
```

Each simulation event is mirrored into `security_events` with:

- `source = 'simulation'`
- `data_origin = 'SIMULATED'`
- `simulation_id = <run id>`
- `dedupe_key = sim:<simulationId>:<round>:<index>`
- a synthetic source address derived from the run id, so grouping rules (brute force) work

A partial unique index on `(org_id, dedupe_key)` plus `INSERT OR IGNORE` makes reruns idempotent.

When the last round finishes, the engine evaluates the deterministic rules, correlates detections with risk ≥ 70 into incidents, and refreshes asset risk. Detection never runs on the model of a scenario; it runs on the generated events, exactly like real telemetry.

## Detection mapping

| Scenario event | Rule that can fire |
| --- | --- |
| `auth.failure` burst from one address | brute-force-auth, credential-stuffing |
| `email.click` / `email.credential_submit` | phishing-interaction |
| `malware.detected` / `malware.quarantined` | malware-detection |
| `file.encrypt` | ransomware-behaviour |
| `web.sql_injection` / `web.xss` | web-attack |
| `auth.privileged_login` | privileged-login-anomaly |
| network port sweep | port-scan |
| large outbound flow | data-exfiltration |

Detections store the rule, severity, risk score, confidence and the factor list used to compute the score.

## Determinism

- A run uses `mulberry32` seeded from `config.seed`, so the same scenario and seed reproduce the same event stream.
- Demo scenario runs use seed `424242`.
- The database stores the config and seed with the run.

## Reports

Each completed run stores findings, recommendations, metrics and a narrative in `simulation_reports`. The report is downloadable as Markdown and is labeled synthetic. Metrics come from the generated events (for example files encrypted, clicks, injections), not from fixed text.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/simulations/scenarios` | All scenario definitions |
| POST | `/api/simulations` | Create a draft |
| POST | `/api/simulations/:id/start` | Start |
| GET | `/api/simulations/:id` | Agents, events, report |
| POST | `/api/simulations/:id/cancel` | Stop |
| GET | `/api/simulations/:id/report/download` | Markdown report |
| POST | `/api/demo/scenarios/:key/run` | Demo shortcut: create and start |
| POST | `/api/demo/scenarios/run-all` | Start the five demo scenarios |

## Data classification

Every mirrored event is `SIMULATED`. Detections and incidents created from those events inherit `SIMULATED`. The UI shows a `simulated` badge on those records. Demo-generated incidents are `DEMO` and are removed only by a demo reset.

## Tests

`backend/tests/simulation.test.mjs` verifies the scenario catalogue, validation, execution, cancellation, reports and MiroFish honesty. `backend/tests/demo.test.mjs` verifies that a brute-force run writes `SIMULATED` events and creates detections that appear in the dashboard.

Full suite: 47 tests passing.

## Limitations

- Agents follow scripted probabilistic behaviour, not free-form reasoning.
- Telemetry shapes are representative, not vendor exact.
- Detection de-duplicates by signature for two hours, so repeated identical runs may not create a second detection. This is intentional anti-noise behaviour.
- Runs created before migration v4 are not backfilled into `security_events`.
