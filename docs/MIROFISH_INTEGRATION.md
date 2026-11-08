# MiroFish integration

## What MiroFish actually is

Source inspected: `third_party/mirofish/MiroFish-main` (extracted from `MiroFish-main.zip`, original repository `https://github.com/666ghj/MiroFish`).

| Fact | Finding |
| --- | --- |
| Backend | Flask 3 with three blueprints registered in `backend/app/__init__.py` |
| Route prefixes | `/api/graph`, `/api/simulation`, `/api/report` |
| Frontend | Vite application in `frontend/` (not used by SecureFlow) |
| Runtime | `requires-python = ">=3.11,<3.13"`; this machine has Python 3.13.15 |
| Required services | OpenAI compatible LLM (`LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL_NAME`) and Zep Cloud (`ZEP_API_KEY`) |
| Key libraries | `camel-oasis==0.2.5`, `camel-ai==0.2.78`, `zep-cloud==3.25.0`, PyMuPDF, pydantic |
| Persistence | Zep Cloud knowledge graph plus local project and simulation state files; no local SQL database |
| Execution model | A preparation task generates agent profiles and a simulation config; a runner process executes OASIS social platforms for a number of rounds |
| License | GNU AGPL-3.0 (`LICENSE`) |

### Routes read from source

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/graph/project/list` | Projects available to the service (used as the health probe) |
| POST | `/api/graph/build` | Build a knowledge graph from seed material |
| POST | `/api/simulation/create` | Create a simulation for a `project_id` and `graph_id` |
| POST | `/api/simulation/prepare` | Generate agent profiles and configuration (asynchronous task) |
| POST | `/api/simulation/start` | Start the OASIS run (`platform`, `max_rounds`) |
| GET | `/api/simulation/<id>` | Simulation record |
| GET | `/api/simulation/<id>/run-status` | Runner status, round progress |
| GET | `/api/simulation/<id>/actions` | Agent actions |
| POST | `/api/simulation/stop` | Stop a run |
| POST | `/api/report/generate` | Generate a prediction report |
| GET | `/api/report/by-simulation/<id>` | Report for a simulation |

No endpoint was invented. The adapter only calls routes that exist in `backend/app/api/*.py`.

## Why it is not executed here

Three independent blockers:

1. **Python version.** `pyproject.toml` requires `<3.13`. The available interpreter is 3.13.15, so `pip install -e .` cannot resolve.
2. **Model credentials.** Preparation and reporting call an LLM through the OpenAI SDK. No key is available, and the lab must not fabricate an LLM response.
3. **Memory service.** Zep Cloud requires an account key. The graph, entity extraction and agent memory all depend on it.

The service is therefore not started, not vendored and not simulated. The interface states this in plain language.

## Integration shape

```
SecureFlow API (Node)
  services/mirofish.js
    GET  {base}/api/graph/project/list        health and capability probe
    GET  {base}/api/simulation/{id}           import metadata
    GET  {base}/api/simulation/{id}/run-status progress and round
    (create/prepare/start/report routes are documented but only used
     when an operator explicitly enables a remote run)

Browser
  Settings > Integrations (MiroFish row)
  Threat Simulation Lab > MiroFish adapter panel
```

Properties of the adapter:

- Base URL and optional bearer token come from the server environment only. They are never sent to the browser.
- Every request has a six second timeout (`AbortSignal.timeout`).
- Errors are classified as `not_configured`, `unreachable` or `upstream_error` and returned as a message, not a stack trace.
- Health is a real call. A dead service shows `error` with the reason; it never shows a fake connected state.
- Imported runs are stored with `engine = 'mirofish'`, `summary.source = 'mirofish'` and the remote id. The summary explicitly says SecureFlow did not execute the run and cannot verify its inputs.
- Importing validates the id against `^[A-Za-z0-9_-]{3,64}$`.

## Scenario mapping, honestly

The five required cybersecurity scenarios are implemented by the **SecureFlow native engine**. They are not MiroFish runs.

MiroFish consumes seed documents and builds a social world of agents that post, comment and interact. It has no native model of authentication logs, network flows, endpoints or DLP events. Mapping a credential stuffing scenario onto it would simulate how a narrative about an attack spreads through a population, not how authentication telemetry looks. Presenting that as a security simulation would misrepresent the tool.

What MiroFish could genuinely add, if credentials existed:

| SecureFlow scenario | Possible MiroFish use | Not claimed |
| --- | --- | --- |
| Phishing campaign | Simulate how a warning spreads through a workforce after a report, using a seed document describing the campaign | It would not model mailbox delivery or credential submission |
| Insider threat | Simulate how a rumour about a departing employee moves through teams | It would not detect exfiltration |
| Ransomware | Simulate public and internal reaction to an outage announcement | It would not model encryption |
| Credential stuffing | Simulate discussion after a breach notification | It would not replay credentials |
| API abuse | Simulate developer community reaction to a quota change | It would not model request rates |

This mapping is documented rather than wired, because a remote run needs the credentials above and a graph built from real seed documents. The lab does not offer a button that pretends to do it.

## Configuration

| Variable | Required | Effect |
| --- | --- | --- |
| `MIROFISH_BASE_URL` | for any MiroFish use | Enables the adapter; without it the status is `unconfigured` |
| `MIROFISH_API_KEY` | optional | Sent as `Authorization: Bearer` if the deployment puts an authenticating proxy in front of MiroFish |

Deployment guidance: run MiroFish on its own host or container, bind it to loopback or a private network, and never expose its UI publicly. SecureFlow should reach it over the private network only.

## Test results

| Check | Result |
| --- | --- |
| Adapter status without configuration | `configured: false`, `reachable: false`, reason names `MIROFISH_BASE_URL` |
| Import without configuration | HTTP 400 with `MiroFish is not configured. Set MIROFISH_BASE_URL first.` |
| Network call attempted without configuration | None |
| License surfaced in the API and UI | `AGPL-3.0` |
| Real service reachability | Not verified; the service cannot start here |
| Real create/prepare/start/report cycle | Not verified; blocked by credentials and Python version |

Automated evidence: `server/tests/simulation.test.mjs`, test "MiroFish reports an honest unconfigured state".

## Licensing findings

- MiroFish is AGPL-3.0. SecureFlow does not copy its source into the application and does not link against it, so the application's own code is not derived from it.
- Running a modified MiroFish as a network service triggers AGPL section 13: users interacting with it over a network must be offered the corresponding source. If you modify and host MiroFish, publish your modifications.
- Distributing MiroFish binaries or source alongside SecureFlow requires preserving the AGPL license and notices, and offering source for the whole combined work as AGPL defines it.
- The adapter is an independent HTTP client; keep it that way. Do not paste MiroFish modules into `server/src`.
- No MiroFish assets, prompts or model files are redistributed here.

This is a summary for engineers, not legal advice. Have counsel review distribution plans.
