# Project status

Last updated: 11 November 2026. This file reflects what was actually built, run and verified. Nothing below is marked complete on the strength of a plan. The website protection evidence pack is in [website/STATUS.md](website/STATUS.md).

## Summary

| | |
| --- | --- |
| Application | SecureFlow AI, single page client plus REST API |
| Backend tests | 91 passing, 0 failing (`npm test`) |
| SDK tests | 13 passing, 0 failing (`npm run test:sdk`) |
| Type check | clean (`npm run typecheck`) |
| Production build | success (`npm run build`), 857 kB initial JavaScript and 318 kB CSS after the Astryx integration |
| Dependency audit | 0 vulnerabilities (server and web) |
| Manual browser verification | signing in, overview, monitoring, assets, incidents (create, transition, note), detections, threat intel, simulations (create, run to completion, history), reports, settings, website onboarding, DNS verification, key creation, ingestion, detections and incidents, 404 |
| Deployment | not performed, by instruction |

## Module status

Statuses: **Complete and verified** means the UI, API, persistence and a test or recorded manual check exist. **Complete with limitation** means the feature works but a named external capability is unavailable.

| # | Module | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 1 | Authentication and RBAC | Complete and verified | `tests/auth.test.mjs`, `tests/mfa.test.mjs`, `tests/isolation.test.mjs` | Register, login, logout, sessions, roles, disabled accounts, TOTP MFA with recovery codes, session cap and rotation, origin check |
| 2 | Security overview dashboard | Complete and verified | Manual browser run, `tests/detection.test.mjs` | All KPIs from SQL aggregates; trends over 14 days |
| 3 | Live monitoring | Complete and verified | Manual run; ingest covered by `tests/detection.test.mjs` | Filters, search, pagination, SSE stream, triage, detail drawer |
| 4 | Threat intelligence | Complete and verified | `tests/security.test.mjs`, manual run | IOC CRUD, typed validation, local lookup, provider status honesty |
| 5 | Asset management | Complete and verified | `tests/isolation.test.mjs`, manual run | Criticality, risk, owner, tags, detail with correlated records |
| 6 | Incident management | Complete and verified | `tests/workflow.test.mjs` | Forward-only lifecycle guard, timeline, notes, assignment, promotion from a detection |
| 7 | Threat investigation | Complete and verified | Manual run | Hypothesis, correlated timeline, notes, findings, linked incident, assets, indicators |
| 8 | Detection centre, deterministic | Complete and verified | `tests/detection.test.mjs`, `tests/website-detection.test.mjs` | 18 deterministic rules, 9 platform and 9 website. No AI or model inference exists; AI-assisted scoring is not implemented. Stored explanation, feedback, rule enablement, asset risk refresh |
| 9 | Phishing URL scanner | Complete and verified | `tests/security.test.mjs` | SSRF protections verified against eight blocked ranges and four schemes; heuristics, redirect chain, optional reputation |
| 10 | Vulnerability management | Complete and verified | Manual run | Register with CVE, CVSS, asset, remediation, status flow |
| 11 | Security automation (SOAR) | Complete with limitation | `tests/workflow.test.mjs` | Approval gate and execution log work; actions are recorded as simulated because no EDR/firewall/identity integration is configured |
| 12 | Digital forensics | Complete and verified | `tests/workflow.test.mjs` | SHA-256 on intake, tamper detection, custody trail, safe download, path guard |
| 13 | Network monitoring | Complete and verified | Manual run | Flows, summary, protocol mix, top talkers, ingestion |
| 14 | Reports and analytics | Complete and verified | `tests/workflow.test.mjs`, manual run | Six report types from live data, Markdown/CSV/JSON export |
| 15 | Settings and administration | Complete and verified | Manual run, `tests/auth.test.mjs` | Organization, members, roles, integrations, audit log, health, account |
| + | Website protection | Complete with a blocked launch gate | `tests/website-*.test.mjs`, [website/STATUS.md](website/STATUS.md) | Registration, DNS TXT verification, scoped keys, SDK ingestion, detection, incidents, dashboard, scheduler, retention, export and deletion. Gate G1 (verified email) is blocked, so the feature stays off by default in production |
| + | Threat Simulation Lab | Complete and verified | `tests/simulation.test.mjs`, manual run | Five scenarios, seeded engine, live progress, agents, events, findings, recommendations, report download |
| + | Demo data management | Complete and verified | `tests/demo.test.mjs` | Per-workspace deterministic 45 asset / ~258 event batch, detection and incident correlation, safe reset, origin labels, admin only |
| + | Simulation to event pipeline | Complete and verified | `tests/demo.test.mjs`, `tests/simulation.test.mjs` | Simulation events mirrored to `security_events` with dedupe keys, then detection, correlation and asset risk refresh |
| + | MiroFish adapter | Complete with limitation | `tests/simulation.test.mjs` | Honest unconfigured state, real route definitions, import path; the service cannot run here (Python 3.11-3.12 plus LLM and Zep keys) |
| + | API Anything evaluation | Documented | `docs/API_ANYTHING_INTEGRATION.md` | MIT tool, Node 22.13+, local MCP; deliberately not a runtime dependency |

## Verification log

The commands below are the 8 November 2026 baseline. The current counts after the website protection work are 91 backend tests and 13 SDK tests, with a 568 kB production bundle before Astryx; the current bundle is 857 kB initial JavaScript and 318 kB CSS with lazy routes; the full run is recorded in [website/verification](website/verification/).

```
$ npm test --prefix backend
tests 47 | pass 47 | fail 0 | duration_ms 51799

$ npm run typecheck --prefix frontend
(no output; exit 0)

$ npm run build --prefix frontend
dist/index.html                 0.75 kB
dist/assets/index-*.css        25 kB
dist/assets/index-*.js        513 kB (142 kB gzip)
```

Manual browser checks performed in a real browser against the production build served by the API on port 4000:

- Signed in with a demo account through the login form; the session survived navigation and reload.
- Overview loaded real aggregates (108 events in 24 hours, 8 open incidents, 8 open detections, 2 of 15 assets at risk).
- Monitoring rendered 277 events with severity facets, filters and a live streaming indicator.
- Created incident INC-2026-1011 from the UI, moved it from `open` to `investigating`, and added a timeline note; the timeline showed three entries.
- Detections showed eight open items with risk scores and the stored rule factors.
- Created a phishing simulation, started it, watched progress reach 7 of 7 rounds and 15 events, and read the generated findings.
- Settings showed the organization, all ten integrations with honest statuses (nine unconfigured, API Anything disabled), and admin-only controls disabled for an analyst.
- Settings Security enrolled TOTP MFA for the demo admin (secret and eight recovery codes shown once), the badge switched to Enabled, and the login page then returned the six digit challenge instead of a session. The demo admin was reset to MFA disabled afterwards so the documented demo login keeps working.

## Defects found and fixed during verification

| Defect | Cause | Fix |
| --- | --- | --- |
| Blank page on every paginated module | API client unwrapped `data` from `{ data, meta }`, so `meta` was undefined | Client now returns the envelope when `meta` is present |
| Chart axis wasted half its height | Axis maximum rounded to the next power of ten | Round up to a readable 5 x 10^n step |
| Mobile top bar wrapped to two lines | Account label and secondary action did not collapse | Hide the crumb, account label and secondary action below 620 px |
| Mobile nav links wrapped mid-label | No `white-space: nowrap`, brand subtitle took width | Responsive nav rules at 900 px and below |
| Two column pages squeezed at narrow widths | Inline grid templates ignored media queries | Force inline multi-column grids to one column below 900 px |
| Agents table crowded on mobile | Persona column competed for width | Hide the persona column below 620 px and give tables a minimum width |
| Evidence files escaped the configured data directory | Evidence path ignored `SF_DATA_DIR` | Path now derives from the exported data directory |
| **A production deployment would have seeded a public admin password** | Demo seeding ran on any empty database, and the demo credentials were compiled into the client bundle | Demo mode now defaults off in production; the first admin comes from `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD`; the login page fetches demo accounts at runtime only when demo mode is on. Verified the production bundle contains no demo password |
| SSRF validation had a DNS rebinding window | The hostname was validated, then `fetch` resolved it again and could connect elsewhere | The scanner now pins the validated address with a custom DNS lookup in `http`/`https.request`, including every redirect hop |
| Viewers could download sealed evidence | The download route only required a session | Download now requires analyst or admin and writes a custody record |
| Password change left other sessions valid | Sessions were not revoked on credential change | Every session is deleted and a fresh one issued; a "Sign out other sessions" action exists in Settings |
| **CSRF protection could be bypassed by omitting Origin** | No token existed and the only check returned early when Origin was absent | Session-bound CSRF token on every authenticated mutation; missing Origin no longer bypasses it. Verified in `tests/hardening.test.mjs` |
| **Destructive SOAR actions could run without approval** | Approval depended on a workflow flag an admin could turn off | Approval is mandatory for isolate_host, block_ip, disable_user and force_password_reset. Added 30 minute expiry, idempotency keys and a workspace pause |
| **Audit log was mutable with no integrity check** | Best-effort insert and no hash | Per-organization SHA-256 hash chain, verification endpoint, failures propagate; tamper test passes |
| **Evidence type was trusted from the client** | Only a MIME allowlist was checked | Magic-byte validation for PNG/JPEG/PDF/ZIP; ClamAV adapter with production fail-closed behaviour |
| **Login throttling was per IP only** | Distributed attempts against one account were unlimited | 10 failures per account per 15 minutes, in addition to the IP limit |
| **scrypt blocked the event loop** | Synchronous scrypt on login and registration | Async scrypt on all request paths; full suite passes |
| **CSV export allowed formula injection** | Cells were quoted but not neutralised | Leading `= + - @` are prefixed before quoting |
| **zod advisory** | zod 3.23.8 affected by GHSA-mrhx-c7xc-m3w5 | Upgraded to 4.6.7, schemas adjusted, 42 tests pass, audit clean |
| **Dashboard showed zero in a new workspace** | New organizations were never seeded and simulation output went only to `simulation_events` | Per-workspace demo generator, simulation events mirrored into `security_events`, detection and correlation run on completion, `data_origin` labels and safe reset |
| **Aggregate detections lost their origin** | Rules without an event or asset defaulted to REAL | `evaluateRules` accepts an origin hint; demo and simulation paths pass DEMO or SIMULATED |
| **Asset risk stayed flat after correlation** | Risk refresh only counted `open` detections | Refresh now includes `open` and `confirmed` |

## Known limitations

See README and SECURITY for the full list. The ones that affect a production claim:

1. No MFA, password reset email or account deletion.
2. Integration collectors for Wazuh, Sysmon, Suricata, Zeek, ClamAV and YARA are not implemented; the API accepts their events.
3. Automation actions are recorded, not executed against external systems.
4. Retention is a stored target, not an enforced job.
5. Single node SQLite deployment.
6. MiroFish could not be executed or verified live.
