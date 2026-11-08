# Threat Simulation Lab

## Purpose

The lab lets an analyst rehearse an attack pattern against **synthetic data** and read how the defensive agents responded. It is a training and design tool. It is not an attack tool, not a prediction engine for your network, and not a substitute for a detection test in a real environment.

Every record carries `synthetic: true`, every simulation event stores `metadata.synthetic = true`, and every report repeats the disclaimer. The interface shows a **Synthetic** badge on each scenario and each run.

## Architecture

```
POST /api/simulations              draft + agent roster materialised
POST /api/simulations/:id/start    status=running, driver scheduled
        |
        |  every 220-900 ms (default 650)
        v
   round 1..N
     generate events for the round (seeded PRNG)
     insert simulation_events, update agent activity and risk
     update progress, broadcast SSE 'simulation.round'
        |
        v
   final round: computeOutcome()
     findings, recommendations, metrics, risk score, narrative
     insert simulation_reports, status=completed, SSE 'simulation.finished'
```

Properties:

- **Deterministic.** `seed` and scenario reproduce the same event stream. The seed is stored in `simulations.config`.
- **Bounded.** 3 to 30 rounds; per scenario numeric inputs are clamped and validated server side.
- **Isolated.** Agents act only on generated identifiers (documentation IP ranges, `meridian.demo` mailboxes, `ws-fin-114` style hosts). No network call is made during a run.
- **Honest on failure.** A server restart marks in-flight runs `failed` with a reason. A cancelled run stays `cancelled` and cannot be silently completed.
- **Readable after the fact.** Agents, every event, the summary metrics and the report are stored in the database and rendered on the run page.

## Agents

Each scenario defines three to four agents with a role and a persona. Roles drive what the agent can emit:

| Role | Emits |
| --- | --- |
| attacker | failures, requests, sends, loader execution |
| insider | exports, removable media writes |
| target | authentication outcomes, file encryption, warehouse queries |
| defender | rate limiting, quarantine, detection matches, isolation, restore |
| legitimate / context | baseline traffic, HR context that should have triggered a review |

Agent risk rises with the severity of the events it causes. The run page shows actions, risk and last action per agent.

## Scenarios

| Scenario | Synthetic inputs | What the rounds produce | Outcome metrics |
| --- | --- | --- | --- |
| Credential stuffing | Bot accounts, victim accounts, attempts per round, MFA coverage, rate limiting on/off | `auth.failure`, occasional `auth.success`, `auth.mfa_challenge`, `auth.rate_limited`, `detection.rule_match`, `response.credential_reset` | Attempts, successful logins, blocked challenges |
| API abuse | Clients, requests per round, quota, auth required, pagination | `api.request`, `api.rate_limit`, `api.enumeration`, baseline partner traffic, quota reduction | Estimated requests, rate limit events, enumeration events |
| Phishing | Recipients, domain age, click rate, submission rate, report rate | `email.sent`, `email.delivered`, `email.click`, `email.credential_submit`, `email.reported`, quarantine, credential reset | Recipients, clicks, submissions, reports |
| Insider threat | Records accessed, off hours, USB enabled, DLP enabled, notice period | `data.export`, `audit.off_hours`, `dlp.alert`, `device.usb_write`, detection match, access review | Rows exported, USB writes, DLP alerts |
| Ransomware | Patient zero, lateral targets, encryption rate, immutable backups, EDR | `process.exec`, `process.shadow_copy_delete`, `file.encrypt`, `edr.detection`, `response.isolate_host`, restore | Files encrypted, shadow copy deletions, host isolated, backup state |

## Risk score

The score is deterministic and derived from the outcome, not from a model.

- **Credential stuffing:** base 45, plus 14 per successful login, plus attempts / 6, minus 1.5 per blocked challenge, capped at 98.
- **API abuse:** base 38, plus 2.5 per rate limit event, plus 6 per enumeration event, minus 8 when authentication was required, capped at 96.
- **Phishing:** base 40, plus 7 per click, plus 16 per credential submission, minus 3 per report, capped at 97.
- **Insider threat:** base 35, plus exported rows / 25, plus 9 per USB write, minus 2 per DLP alert, capped at 95.
- **Ransomware:** base 55, plus encrypted files / 40, plus 6 per shadow copy deletion, minus 14 when the host was isolated, minus 8 when backups were not immutable, capped at 99.

Every report states the score, the findings that produced it and the recommendations. The UI labels it **Simulated risk** and says higher means more impact before containment.

## UI flow

1. **Lab page** - five scenario cards with summary, round count, agent roster, and a **Configure run** action.
2. **Configure modal** - name, seed, rounds and the scenario parameters. Inputs are validated again on the server.
3. **Run page** - start or cancel, progress bar with round counter, live polling while running, risk gauge, outcome metrics, findings, recommendations, agents, event log and report download.
4. **History** - every run with engine, status, progress and risk.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/simulations/scenarios` | Five definitions with agents and defaults |
| POST | `/api/simulations` | Create a draft |
| GET | `/api/simulations` | History |
| GET | `/api/simulations/:id` | Detail with agents, events, report |
| POST | `/api/simulations/:id/start` | Start |
| POST | `/api/simulations/:id/cancel` | Cancel |
| DELETE | `/api/simulations/:id` | Delete a non running run (admin) |
| GET | `/api/simulations/:id/report/download` | Markdown report |
| GET | `/api/simulations/mirofish/status` | Optional adapter state |
| POST | `/api/simulations/mirofish/import` | Import a remote MiroFish run |

## Testing

`server/tests/simulation.test.mjs` verifies:

- all five scenarios exist with at least three agents and three config fields;
- an unknown scenario returns 400;
- a ransomware run completes, reaches 100 percent, records events and agent activity, stores findings and recommendations, and marks every event synthetic;
- a run can be cancelled and keeps the cancelled status;
- a completed run cannot be started again;
- MiroFish reports unconfigured and refuses an import.

Manual browser verification: created a phishing run, started it, observed live progress from round 1 to 7 of 7 with 15 events, and read the generated findings and recommendations.

## Limitations

- Agents follow scenario scripts with probabilistic branching, not free-form language reasoning. There is no LLM in the loop.
- Telemetry shapes are representative, not vendor exact. They are useful for process rehearsal, not for tuning a specific SIEM parser.
- The engine does not model real network topology or identity provider behaviour beyond the parameters exposed.
- A run lives in the API process. If the process stops mid run, the run is marked failed rather than resumed.
- Results must not be presented as real detections or as predictions of future incidents.
