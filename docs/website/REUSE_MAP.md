# Reuse map

The rule was to extend the application, not to build a second one. This table records what existed, where, and how the website feature uses it.

| Existing capability | Where it lives | How website protection uses it |
| --- | --- | --- |
| SQLite connection, migrations, `transaction()`, `newId()` | `backend/src/db.js` | Schema v5 and every website write. Composite foreign keys and `BEGIN IMMEDIATE` give the conflict rules their guarantees. |
| Session authentication, roles, CSRF, origin check | `backend/src/lib/auth.js` (`attachUser`, `requireRole`, `requireCsrf`, `checkOrigin`) | Every dashboard and key route. `requireRecentAuth` and `RECENT_AUTH_MS` were added beside them. |
| TOTP verification and recovery codes | `backend/src/lib/totp.js`, `backend/src/routes/auth.js` | The step-up endpoint accepts a TOTP code when MFA is enabled, reusing `verifyTotp` and the recovery code hash. |
| Audit hash chain | `backend/src/lib/audit.js` (`audit`, `verifyAuditChain`) | Every website action writes through `audit()`, inside the same transaction as the business change. No new audit format. |
| API envelope, `ApiError`, Zod validation, pagination | `backend/src/lib/http.js` | All website routes. `request_id` was added to the error envelope for the whole API. |
| Rate limiter | `backend/src/lib/ratelimit.js` | Session routes keep the existing limiter. Ingestion and verification add durable SQLite counters because they must survive restarts. |
| Asset inventory | `assets` table, `backend/src/routes/assets.js`, `frontend/src/pages/Assets.tsx` | A verified website becomes `assets.asset_type = 'website'`. Risk score, criticality and the asset detail page work unchanged. |
| Event store | `security_events` table, `backend/src/routes/events.js`, `frontend/src/pages/Monitoring.tsx` | Website events are stored in the same table with `source = 'secureflow-sdk'`, `trust_level = 'server_sdk'`, `website_site_id` and an existing category. |
| Detection engine and rule table | `backend/src/services/detection.js`, `detection_rules`, `backend/src/routes/detections.js` | `WEBSITE_RULES` is merged into the existing rule list. The same `scoreDetection`, `ensureRules`, storage and UI are used. |
| Incident model and timeline | `incidents`, `incident_events`, `backend/src/routes/incidents.js`, `frontend/src/pages/Incidents.tsx` | Website correlation creates and updates existing incidents with `incident_events` timeline rows. The incident detail page shows them without change. |
| Threat intelligence indicators | `iocs` table, `backend/src/routes/intel.js` | Rule W-INTEL-001 joins active IP indicators instead of adding a second intelligence store. |
| Server sent events | `backend/src/lib/events.js` | Ingestion emits `website.events` after commit so an open page can refresh. |
| Data origin classification | `data_origin`, `demo_batch_id` columns and `OriginBadge` | Website events are `REAL` SDK telemetry. The interface labels `.test` demo sites as `test domain` rather than pretending they are customer data. |
| UI system | `frontend/src/components/ui.tsx`, `layout.tsx`, `lib/hooks.ts`, `lib/api.ts`, `lib/format.ts` | Cards, badges, tabs, modals, toasts, pagination, `useApi`, error handling, navigation and typography. No second design system. |
| Navigation and routing | `frontend/src/components/layout.tsx`, `frontend/src/App.tsx` | A single **Websites** item under Operations, hidden when the feature flag is off. |
| Settings and audit screens | `backend/src/routes/settings.js`, `frontend/src/pages/Settings.tsx` | Audit verification for website actions uses the existing endpoint. |
| Scheduler pattern | None existed. `website_jobs` is new. | The lease query is new code; it follows the existing synchronous SQLite style and is driven from `backend/src/index.js`. |
| Notification delivery | None existed. `notifications` is new. | In-app records only. No email or webhook was invented. |
| Public suffix handling | None existed. | `tldts` 7.4.21 was added after checking the registry, licence and dependency count. |

## Not reused, and why

- **Phishing scanner fetcher.** `backend/src/services/phishing.js` contains an SSRF safe HTTP client, but website verification never fetches the customer site (D16), so it was not used.
- **Simulation mirroring.** Simulation events enter `security_events` with `SIMULATED`; website SDK events use the same table but keep `REAL` and their own dedupe prefix. A demo batch reset never touches them.
- **Correlation service.** `backend/src/services/correlation.js` creates one incident per detection. Website correlation needs entity intersection across site, address and actor, so `websiteIncidents.js` implements that rule and writes the same tables. The existing function is untouched.

## New tables in schema v5

`website_sites`, `domain_verifications`, `site_api_keys`, `website_event_ids`, `website_verification_attempts`, `website_usage`, `website_jobs`, `notifications`, `incident_entities`, `incident_detections`, `website_deletion_requests`.

New columns: `sessions.reauthenticated_at`, `security_events.trust_level`, `security_events.website_site_id`.

All tenant tables carry `org_id`. `website_jobs`, `notifications` and `incident_*` are scoped in every query; `website_event_ids` is keyed by `site_id`, which is resolved from the key before use.
