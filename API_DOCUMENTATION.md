# API documentation

Base URL: `/api`. A machine readable index is served at `GET /api/docs` for any signed in user.

## Conventions

**Authentication** - session cookie `sf_session` (HttpOnly, SameSite=Lax, seven day expiry). Send `credentials: 'same-origin'` from the browser. Unauthenticated requests receive `401`.

**Roles** - `viewer` reads, `analyst` writes operational data, `admin` also manages users, settings, integrations, rule enablement and deletion. A `403` means the role is insufficient; a `404` is returned when a record does not exist in the caller's organization, so cross-tenant access is indistinguishable from a missing record.

**Success envelope**

```json
{ "data": { } }
```

Paginated endpoints add `meta`:

```json
{
  "data": [],
  "meta": { "page": 1, "limit": 25, "total": 210, "totalPages": 9, "hasNext": true }
}
```

**Error envelope**

```json
{ "error": { "code": "validation_failed", "message": "Request validation failed",
  "details": [{ "path": "email", "message": "Enter a valid email address" }] } }
```

**Pagination and filters** - `?page=1&limit=25`. Most list endpoints accept `q`, `severity`, `status`, `from`, `to` and resource specific filters.

**Rate limits** - in memory, per process: 12 login attempts per 15 minutes per IP, 6 registrations per hour, 600 event ingests per minute, 40 URL scans per hour, 1200 API requests per minute.

---

## Auth

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/register` | public | Create an organization and its first admin |
| POST | `/auth/login` | public | Start a session, or return an MFA challenge |
| POST | `/auth/mfa/verify` | public with challenge cookie | Complete an MFA login |
| POST | `/auth/logout` | any | Destroy the current session |
| GET | `/auth/me` | any | User, organization and permission flags |
| PATCH | `/auth/me` | any | Update display name or password (requires current password; revokes all sessions) |
| GET | `/auth/demo-accounts` | public | Demo accounts, only when demo mode is on |
| GET | `/auth/sessions` | any | Active sessions for the current user |
| POST | `/auth/sessions/revoke-others` | any | Sign out every other session |
| POST | `/auth/mfa/setup` | any | Start TOTP enrol (requires password, returns secret and recovery codes) |
| POST | `/auth/mfa/enable` | any | Confirm a code and enable MFA |
| POST | `/auth/mfa/disable` | any | Disable MFA (password and live code) |
| POST | `/auth/mfa/recovery-codes` | any | Regenerate single use recovery codes |

Register body: `{ name, email, password, organizationName }` with a minimum password length of 10.

## Overview

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/overview/summary` | KPI object, severity mix, incident and detection status counts, top assets, recent events, open incidents, MTTR |
| GET | `/overview/trends?days=14` | Daily events, high severity events, incidents, detections, average detection risk, outbound bytes |

## Monitoring (security events)

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/events` | any | Paginated events |
| GET | `/events/facets` | any | Severity, source and category counts |
| GET | `/events/:id` | any | Event with raw payload, detections and related telemetry |
| POST | `/events` | analyst | Ingest an event and evaluate rules |
| PATCH | `/events/:id` | analyst | Set `new`, `triaged` or `closed` |
| GET | `/stream` | any | Server-Sent Events |

Ingest body:

```json
{
  "eventType": "auth.failure",
  "source": "identity-provider",
  "severity": "medium",
  "category": "identity",
  "title": "Failed sign-in for j.reyes",
  "description": "Password rejected",
  "srcIp": "203.0.113.44",
  "destIp": "10.20.1.11",
  "userEmail": "j.reyes@example.com",
  "assetId": "ast_...",
  "raw": { "provider": "okta" }
}
```

Response: `{ "data": { "event": {...}, "detections": [{ "id", "title", "severity", "riskScore", "ruleKey" }] } }`.

SSE events: `connected`, `event.ingested`, `simulation.round`, `simulation.finished`, `simulation.failed`, `phishing.scan_completed`.

## Assets

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/assets` | any | Inventory with event and open detection counts |
| GET | `/assets/summary` | any | Counts and mean risk by criticality and type |
| GET | `/assets/:id` | any | Asset with events, detections, vulnerabilities and flows |
| POST | `/assets` | analyst | Register an asset |
| PATCH | `/assets/:id` | analyst | Update fields |
| DELETE | `/assets/:id` | admin | Delete an asset (related events keep a null asset) |

## Incidents

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/incidents` | any | Queue with per status counts in `meta.counts` |
| POST | `/incidents` | analyst | Open an incident, optionally from a detection |
| GET | `/incidents/:id` | any | Timeline, linked detections, investigations, allowed transitions |
| PATCH | `/incidents/:id` | analyst | Status, severity, priority, assignee, title, description |
| POST | `/incidents/:id/notes` | analyst | Append a timeline note |

Lifecycle: `open -> investigating -> contained -> resolved -> closed`, with reopening allowed from `resolved` and `closed` back to `investigating`. Invalid transitions return `400` with the allowed list.

## Investigations

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/investigations` | any | Case files with note counts |
| POST | `/investigations` | analyst | Open a case, optionally linked to an incident |
| GET | `/investigations/:id` | any | Notes, indicators, assets, correlated timeline |
| PATCH | `/investigations/:id` | analyst | Status, findings, hypothesis, severity |
| POST | `/investigations/:id/notes` | analyst | Add an analyst note |

## Threat intelligence

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/threat-intel` | any | Indicator inventory |
| POST | `/threat-intel` | analyst | Add an indicator (validated per type) |
| PATCH | `/threat-intel/:id` | analyst | Status, confidence, description |
| DELETE | `/threat-intel/:id` | admin | Remove an indicator |
| POST | `/threat-intel/lookup` | analyst | Local match plus configured providers |
| GET | `/threat-intel/lookups/recent` | any | Recent lookups |

Lookup response includes `localMatch`, `external[]`, `providersConfigured` and a `note` when no provider is configured. No reputation provider is called without a key.

## Detections

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/detections` | any | Queue, ordered by risk |
| GET | `/detections/summary` | any | Status, severity, per rule counts and the score model |
| GET | `/detections/:id` | any | Detection with explanation, event and related telemetry |
| GET | `/detections/rules` | any | Rule catalogue |
| PATCH | `/detections/rules/:id` | admin | Enable or disable, adjust threshold and window |
| POST | `/detections/run` | analyst | Evaluate rules now |
| POST | `/detections/:id/feedback` | analyst | `confirmed`, `false_positive`, `closed` |
| POST | `/detections/:id/promote` | analyst | Create an incident and link it |

## Phishing scanner

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/phishing/scan` | analyst | Fetch and analyse one URL |
| GET | `/phishing` | any | Scan history |

`POST /phishing/scan` body: `{ "url": "https://example.com/login" }`.

Refused with `400`: non HTTP(S) schemes, embedded credentials, localhost and internal hostnames, loopback, private, link local, multicast, reserved and documentation ranges, DNS failures, and redirects that resolve to those ranges. Redirects are capped at three, the response at 256 kB and each request at six seconds. Remote HTML is pattern matched only.

## Vulnerabilities

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/vulnerabilities` | any | Register ordered by CVSS |
| POST | `/vulnerabilities` | analyst | Record a finding |
| PATCH | `/vulnerabilities/:id` | analyst | Status, severity, remediation, due date |

## Automation

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/automation/workflows` | any | Workflow definitions |
| POST | `/automation/workflows` | admin | Create a workflow |
| PATCH | `/automation/workflows/:id` | admin | Enable, approval requirement, description |
| POST | `/automation/workflows/:id/run` | analyst | Run, or queue for approval |
| POST | `/automation/executions/:id/approve` | analyst | Approve a pending execution |
| POST | `/automation/executions/:id/cancel` | analyst | Cancel a pending execution |
| GET | `/automation/executions` | any | Execution history with step logs |

Every action is recorded with status `simulated` when no external integration is configured. The API never claims a host was isolated or an address blocked.

## Forensics

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/forensics` | any | Evidence register |
| GET | `/forensics/stats` | any | Totals by status and case |
| POST | `/forensics` | analyst | Seal evidence (base64, 5 MB limit, MIME allowlist) |
| GET | `/forensics/:id` | any | Metadata and chain of custody |
| GET | `/forensics/:id/download` | any | Download with `X-Evidence-SHA256` header |
| POST | `/forensics/:id/verify` | analyst | Recompute SHA-256 and record the result |
| POST | `/forensics/:id/custody` | analyst | Record `in_review`, `note` or `released` |

Upload body: `{ caseRef, filename, description, mimeType, contentBase64, collectedFrom }`. Filenames are reduced to a safe basename and stored under a generated name inside the data directory.

## Network

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/network` | any | Flow records |
| GET | `/network/summary` | any | Totals, protocols, top sources, destinations and ports |
| POST | `/network` | analyst | Ingest a flow record |

## Reports

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/reports/types` | any | Six report types |
| POST | `/reports/generate` | analyst | Build from current records, optional `from` and `to` |
| GET | `/reports` | any | Generated reports |
| GET | `/reports/:id` | any | KPIs, tables, notes and Markdown body |
| GET | `/reports/:id/download?format=md|csv|json` | any | Export |
| DELETE | `/reports/:id` | admin | Delete a report |

## Threat simulation lab

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/simulations/scenarios` | any | Five scenarios with agents and default config |
| GET | `/simulations` | any | Run history |
| POST | `/simulations` | analyst | Create a draft run |
| GET | `/simulations/:id` | any | Agents, events, summary and report |
| POST | `/simulations/:id/start` | analyst | Start the engine |
| POST | `/simulations/:id/cancel` | analyst | Stop a running simulation |
| DELETE | `/simulations/:id` | admin | Delete a non running run |
| GET | `/simulations/:id/report` | any | Report JSON |
| GET | `/simulations/:id/report/download` | any | Markdown report |
| GET | `/simulations/mirofish/status` | any | Adapter configuration and reachability |
| POST | `/simulations/mirofish/import` | analyst | Import a remote MiroFish run |

Create body:

```json
{ "scenario": "ransomware", "name": "Finance rehearsal", "totalRounds": 8, "seed": 424242,
  "config": { "edrEnabled": true, "backupsImmutable": true } }
```

## Settings

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/settings/organization` | any | Organization and counts |
| PATCH | `/settings/organization` | admin | Name and settings |
| GET | `/settings/users` | any | Members |
| POST | `/settings/users` | admin | Add a member |
| PATCH | `/settings/users/:id` | admin | Role, status, name |
| GET | `/settings/integrations` | any | Integration status, env var names and details |
| POST | `/settings/integrations/:key/test` | admin | Configuration test |
| PATCH | `/settings/integrations/:key` | admin | Enable or disable |
| GET | `/settings/audit-logs` | admin | Audit trail with filter |
| GET | `/settings/health` | any | Service checks and record counts |

Secrets are never accepted by the settings API. Provider keys come from the environment only.

## Health

`GET /health` returns `{ "status": "ok", "service": "secureflow-api", "time", "version" }` without authentication and without tenant data. Suitable for a container health check.
