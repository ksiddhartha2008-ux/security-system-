# SecureFlow AI application health report

Report date: 13 November 2026
Repository: `C:\Users\ksidd\OneDrive\Pictures\Desktop\hack`
Remote: `https://github.com/ksiddhartha2008-ux/security-system-`
Branch: `main`
Commit under test: `d698e17` plus the fixes listed in section 7 (committed after this run as `fix: repair filters, report generation and role gating`)

## 1. Verdict

The application is healthy.

- All automated suites pass: 91 backend tests, 13 SDK tests.
- Type checking, production build, Astryx theme check and Astryx wiring check pass.
- 55 authenticated API checks across every read route and detail route pass with no 5xx response.
- 22 frontend routes render without a console error, a React error or an error banner.
- Three defects that broke real user flows were found and fixed: the website event type filter returned no rows, the report generator could submit an empty type and fail validation, and resolving or closing an incident applied with a single click and no confirmation.
- Four role and accessibility mismatches were fixed: write actions that the API refuses are no longer shown to roles that cannot use them, and field validation errors are now linked to their inputs.

No outstanding critical or high severity defect is known after this pass.

## 2. Environment

| Item | Value |
| --- | --- |
| Operating system | Windows, PowerShell 5.1 |
| Node.js | v24.20.0 |
| npm | 11.19.0 |
| API | `http://localhost:4000`, `NODE_ENV=development` |
| Database | SQLite through `node:sqlite`, schema v5, 41 tables |
| Website protection | enabled for this run, test hostnames allowed, DNS fixture file |
| Browser | Chromium pane, 488 x 752 CSS pixels (mobile width) |

The API process used the current working tree. The health checks read and wrote through the API only, apart from two read only database inspections.

## 3. Stack and shape

- Frontend: React 19, TypeScript 5.7, Vite 6, Tailwind CSS v4, Astryx 0.7.13, StyleX 0.19.1.
- Backend: Express 4 on Node 24, Zod validation, `node:sqlite`, session cookies with CSRF tokens.
- SDK: private `packages/sdk-node`, 13 tests, used by the website ingestion path.
- Documentation: `docs/`, including 22 website protection evidence documents.
- Frontend routes: 6 public routes and 24 authenticated routes, all authenticated pages lazily loaded.
- Astryx components are confined to `frontend/src`. The API client, session handling and routes remain the source of truth for data and permissions.

## 4. Automated test matrix

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Backend and SDK adjacent tests | `npm test` | 91 passed, 0 failed, 0 skipped | TESTED |
| Node SDK tests | `npm run test:sdk` | 13 passed, 0 failed | TESTED |
| TypeScript project build | `npm run typecheck` | no diagnostics | TESTED |
| Production bundle | `npm run build` | built in 9.4 s | TESTED |
| Astryx theme freshness | `npm run check:theme` | outputs match `secureflowTheme.ts` | TESTED |
| Astryx wiring | `npm run check:astryx` | pinned packages, compiled theme, shell and lazy routes verified | TESTED |
| Secret scan | `npm run scan:secrets` | clean | TESTED |
| Documentation links | `node scripts/check-links.mjs` | 0 broken | TESTED |
| Frontend production audit | `npm audit --prefix frontend` | 0 vulnerabilities | TESTED |
| Backend production audit | `npm audit --prefix backend --omit=dev` | 0 vulnerabilities | TESTED |

Build output: `dist/assets/index-*.js` 857.97 kB (277.08 kB gzip) and `dist/assets/index-*.css` 320.77 kB (54.90 kB gzip). Astryx dominates the initial JavaScript weight. Route level code splitting keeps the initial bundle at 858 kB instead of the 1.09 MB measured before splitting.

## 5. API coverage

Script: `scripts/health-check.ps1`. It signs in as the three seeded roles, keeps each session cookie and CSRF token, then calls every read route with `limit` set.

Result: 55 checks, 55 passed, 0 failures, no 5xx response, no entry in `backend/run.log`.

| Area | Routes verified |
| --- | --- |
| Session | `/auth/me`, `/auth/sessions`, `/auth/demo-accounts` |
| Overview | `/overview/summary`, `/overview/trends?days=14` |
| Events | `/events`, `/events/facets`, `/events/:id` |
| Assets | `/assets`, `/assets/summary`, `/assets/:id` |
| Incidents | `/incidents`, `/incidents/:id`, unknown id returns 404 |
| Detections | `/detections`, `/detections/summary`, `/detections/rules`, `/detections/:id` |
| Investigations | `/investigations`, `/investigations/:id` |
| Threat intelligence | `/threat-intel`, `/threat-intel/summary`, `/threat-intel/lookups/recent` |
| Vulnerabilities | `/vulnerabilities` |
| Network | `/network`, `/network/summary` |
| Phishing | `/phishing` |
| Automation | `/automation/workflows`, `/automation/executions` |
| Forensics | `/forensics`, `/forensics/stats`, `/forensics/:id` |
| Reports | `/reports/types`, `/reports`, `/reports/:id` |
| Simulations | `/simulations`, `/simulations/scenarios`, `/simulations/mirofish/status`, `/simulations/:id` |
| Settings | `/settings/organization`, `/settings/users`, `/settings/integrations`, `/settings/audit-logs`, `/settings/audit-logs/verify`, `/settings/health` |
| Demo tool | `/demo/status`, `/demo/runs` |
| Website protection | `/v1/websites`, `/v1/websites/:id`, `/events`, `/detections`, `/incidents`, `/keys` |

Authorisation boundaries checked with live requests:

| Check | Expected | Observed |
| --- | --- | --- |
| Viewer `POST /assets` | 403 | 403 |
| Analyst `POST /settings/users` | 403 | 403 |
| Analyst `POST /settings/integrations/:key/test` | 403 | 403 |
| Viewer `GET /settings/audit-logs` | 403 | 403 |
| Unknown incident | 404 with a JSON error envelope | 404 |

Every error response carries a request id, which the frontend shows in its error state.

## 6. Browser and interface coverage

All checks ran against the built application served by the API on port 4000.

Routes opened, each with a recorded network log and console listener:

Public: `/`, `/login`, `/signup`, `/privacy`, `/terms`, and an unknown path that renders the 404 page.

Authenticated: `/overview`, `/monitoring`, `/assets`, `/websites`, `/websites/new`, `/websites/:id`, `/incidents`, `/incidents/:id`, `/investigations`, `/investigations/:id`, `/threat-intel`, `/detections`, `/phishing`, `/vulnerabilities`, `/network`, `/forensics`, `/automation`, `/reports`, `/simulations`, `/simulations/:id`, `/users`, `/settings`, `/demo-data`.

Result: 22 authenticated routes rendered, 0 console errors, 0 unhandled promise rejections, 0 failed network responses, 0 error banners. `/events/:id` correctly renders the 404 page because event detail is a drawer on `/monitoring`, not a route.

Interactions exercised:

| Interaction | Result |
| --- | --- |
| Incident status tabs (All, Open, Investigating, Contained, Resolved, Closed) | Counts match the API and the table filters correctly |
| Incident text search | Narrows to the matching incident and reports one result |
| Incident status change to contained | Applied, toast shown, timeline entry written |
| Incident status change to resolved or closed | Confirmation dialog appears, cancel leaves the status unchanged |
| Open incident dialog, empty submit | Field error shown, input marked invalid, dialog stays open |
| Website detail tabs: Overview, Events, Detections, Incidents, Keys, Verification, Settings | All render, counts match the API |
| Website event type filter | Returns the matching SDK event rows after the fix |
| Website pagination | Page 1 of 2, next and previous states correct |
| All dialogs: report, asset, evidence, indicator, workflow, demo reset | Open with focus inside, labelled by their title, close by cancel or Escape |
| Settings tabs: Organization, Integrations, Audit log, System health, Security, Your account | All render for an administrator; audit log shows the admin only notice for other roles |
| Account menu and sign out | Menu opens, sign out clears the session and returns to `/login?next=...` |
| Mobile navigation at 488 px | Opens, lists every module, closes with the shell control |
| 404 route | Plain explanation and a link back to the overview |
| Role switch on the login screen | Administrator, Security Analyst and Viewer resolve to the matching seeded account and server role |
| Viewer session | No write buttons in incidents, detections, assets, forensics, automation, websites or reports; the demo tool disables its run controls and explains why |
| Analyst session | Write actions available where the API allows them; administrator only actions remain hidden or disabled |

The role selector changes which seeded account signs in, and `/auth/me` confirms the server side role and permissions afterwards. A client side role label never grants access.

## 7. Defects found and fixed

| # | Severity | Defect | Cause | Fix | Verified by |
| --- | --- | --- | --- | --- | --- |
| 1 | High | Website Events tab returned no rows when filtering by an SDK event name such as `auth.login_succeeded` | The query only compared `event_type`, which stores the normalised class (`auth.success`), while the filter list and the table show the raw SDK name | Filter matches either the raw payload type or the normalised type in `backend/src/routes/websites.js` | New regression assertions in `backend/tests/website-api.test.mjs`; live request returns 1 row; browser filter shows the row |
| 2 | High | Generating a report from the dialog failed with `Request validation failed` | The dialog could submit an empty `type` when the select had no matching option at the moment it was opened | The dialog now derives the selected type from the loaded option list, falls back to the preset or first type, blocks submit while the list is empty, and sends the resolved value | Live request now returns 201 and the report detail opens with CSV, Markdown and JSON export |
| 3 | Medium | Moving an incident to resolved or closed applied immediately on one click | Transition buttons called the API directly | Confirmation dialog for the two terminal transitions, with the status left unchanged on cancel | Browser check: dialog appears, cancel keeps `investigating` |
| 4 | Medium | Viewer sessions saw a working Generate report button that the API rejects | The page header action was not gated | Gated with `permissions.canWrite` | Role pass shows no button for viewer, button present for analyst and admin |
| 5 | Low | Analyst saw an enabled Test configuration button on Integrations that the API rejects | The test action was not gated | Disabled unless `canAdmin`, matching the API role | Role pass, API returns 403 for analyst |
| 6 | Low | Viewer saw an evidence Download button that the API rejects | The download action was not gated | Hidden unless `canWrite` | Role pass; analyst still sees Download and Verify hash |
| 7 | Low | Form field errors were visible but not associated with the input for assistive technology | `Field` rendered the message without `aria-invalid` or `aria-describedby` | `Field` now links the message to the control and marks it invalid | Browser check: `aria-invalid=true`, `aria-describedby` matches the message id |
| 8 | Low | Website 24 hour empty state said no event had ever arrived | Copy did not mention the 24 hour window | Copy now says no event in the last 24 hours | Text check on the website detail page |
| 9 | Low | Seeded incident timelines said the incident came from a detection while no detection was linked | Seed wrote a detection style message without a detection reference | Seed message now describes analyst intake, which matches the stored link state | Read of the seed and the demo database |

No business rule, database schema, authentication rule or tenant boundary was changed.

## 8. Security review

| Control | Evidence |
| --- | --- |
| Session and CSRF | Login issues an HttpOnly session cookie; every state changing check in the script sends the CSRF header; missing or wrong tokens are rejected |
| Role enforcement | Viewer write returns 403; analyst administrator write returns 403; the UI mirrors those roles |
| Tenant isolation | Existing tests cover cross organisation reads; website routes return 404 for another workspace |
| Input validation | Zod schemas on every write route; malformed bodies return a field level error envelope with a request id |
| Output safety | Event fields render as text; no `dangerouslySetInnerHTML` in the frontend |
| Secret handling | Secret scan clean; the frontend holds no API key; website keys are shown once and stored hashed |
| Dependency risk | 0 known vulnerabilities in frontend and backend production trees |
| Data handling | The live database is not committed; a sanitized snapshot with no sessions, audit rows, keys or evidence is published instead |

## 9. Data state

| Item | Value |
| --- | --- |
| Live database | `backend/data/secureflow.db`, not tracked by Git |
| Sanitized snapshot | `demo/secureflow-demo.db`, 1 organisation, 3 users, 302 events, 19 detections, 9 incidents, 15 assets, 0 sessions, 0 audit rows, 0 API keys, 0 evidence |
| Demo accounts | Administrator, Security Analyst, Viewer, all scoped to `org_meridian` |
| Test residue | Two reports and one incident status change created during the pass were removed or reverted; the incident timeline keeps an honest record of the transition |

## 10. Capability status

| Capability | Status | Note |
| --- | --- | --- |
| Authentication, MFA, sessions | IMPLEMENTED, TESTED | Covered by backend tests and the browser login pass |
| Role based access control | IMPLEMENTED, TESTED | Enforced in the API; the UI now matches it |
| Dashboard and overview metrics | IMPLEMENTED, TESTED | Values are SQL aggregates over stored rows |
| Events, detections, incidents | IMPLEMENTED, TESTED | Deterministic rules with stored scoring factors |
| Investigations, forensic evidence | IMPLEMENTED, TESTED | Evidence hashing and custody covered by tests |
| Threat intelligence | IMPLEMENTED, TESTED | Lookup writes a record with no role gate, by design |
| Vulnerabilities, network, phishing | IMPLEMENTED, TESTED | Read and write routes covered |
| Automation and approvals | IMPLEMENTED, TESTED | Actions are recorded as simulated where no integration exists |
| Reports and export | IMPLEMENTED, TESTED | Generate, view, delete, CSV, Markdown and JSON after this pass |
| Simulations | IMPLEMENTED, TESTED | Scores are labelled synthetic everywhere |
| Website protection | IMPLEMENTED, TESTED | Event filter fixed in this pass; verification gate and scheduler covered by tests |
| Node SDK | IMPLEMENTED, TESTED | 13 tests |
| Demo data tool | IMPLEMENTED, TESTED | Administrator only, disabled controls explained for other roles |
| Astryx design system | IMPLEMENTED, TESTED | Theme compiled from source, wiring check passes |
| Light mode | PLANNED | Legacy CSS is dark first; no switch is exposed |
| PostgreSQL migration | PLANNED | SQLite only in this build |
| Shared rate limiting | PARTIALLY IMPLEMENTED | Per process limits exist; shared store is not built |
| Independent penetration test | NOT VERIFIED | No third party review has been performed |
| Production deployment | NOT VERIFIED | Local and CI only |

## 11. Remaining risks

1. The published demo snapshot still contains the older seeded timeline wording. The running application and new seeds use the corrected text. Regenerating the snapshot would remove the difference.
2. Astryx 0.7.13 is a pinned beta. A version change needs the theme build and the wiring check rerun.
3. The frontend has no linter and no unit test runner. Behaviour is covered by the browser pass, not by component tests.
4. Accessibility was checked for labels, names, focus, dialog semantics and error association, but no automated axe run or screen reader session has been recorded.
5. Website protection still depends on the verified email gate in production and is off by default there.
6. SQLite and per process rate limits suit a single node deployment; horizontal scaling needs the planned PostgreSQL and shared limiter work.
7. The evidence records in the demo snapshot point at files that are not shipped, so verification reports the missing file rather than a hash match. The interface states this plainly instead of showing a false success.

## 12. Reproduce

```powershell
npm test
npm run test:sdk
npm run typecheck
npm run build
npm run check:theme
npm run check:astryx
npm run scan:secrets
node scripts/check-links.mjs

# with the API running on port 4000
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/health-check.ps1
```

`scripts/health-check.ps1` exits non zero if any route returns an unexpected status, if a role boundary is crossed, or if an unknown record does not return 404.

## 13. Conclusion

The backend, the frontend and the connection between them are healthy on this commit. Every automated check passes, every read route answers, every page renders, and the flows that were broken during this audit now work. The remaining items are planned work or documented limits, not defects in the current build.
