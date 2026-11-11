# Decisions

The binding decisions D1 to D16 in the supplied prompt are adopted unless a deviation is listed. This file records what was implemented, what was not, and the defaults applied where the owner did not answer.

## Adopted as specified

| ID | Decision | Implementation |
| --- | --- | --- |
| D1 | Host scope or domain scope | `website_sites.scope`. Domain scope publishes the TXT record at the registrable domain. |
| D2 | DNS TXT only in v1 | `backend/src/lib/dnsTxt.js`, `backend/src/services/websiteSites.js`. The file and meta tag methods do not exist. |
| D3 | Challenge record and token | `_secureflow-challenge.<name>`, `secureflow-site-verification=<token>`, 32 random bytes base64url, 7 day expiry, previous challenge superseded. |
| D4 | At most one verified site per hostname | Partial unique index `idx_website_sites_verified_host` on `hostname WHERE status = 'verified'`. |
| D5 | Continuous re-verification | `reverifySite` and the `reverify` job. Failures set `verification_failing_since`; the grace period lapses the site. Resolver errors change nothing. |
| D6 | Credential format and storage | `sfk_` + 12 base32 characters + `_` + 43 base64url characters. SHA-256 of the secret, last four characters, scopes, timestamps. Two active keys per site. |
| D7 | No browser or publishable keys | No browser SDK, no publishable key, no origin control surface. |
| D8 | Keys only for verified sites, admin, recent auth, audited | `POST /v1/websites/:id/keys` with `requireRole('admin')` and `requireRecentAuth`, plus `website.key_created`. |
| D9 | Trust comes from the key | `verifyApiKey` returns key and site; ingestion never reads organization or site from the body. |
| D10 | `(site, event_id)` unique | `website_event_ids` primary key plus `security_events.dedupe_key`. |
| D11 | Privacy defaults | Query strings and fragments stripped, bodies and headers never captured, sensitive attribute keys dropped, actor hashed by default. |
| D12 | Node SDK, explicit calls, heartbeat | `packages/sdk-node`, no automatic request capture. |
| D13 | Website is an asset of type `website` | `ensureAsset` in `websiteSites.js`. |
| D14 | Reuse the detection engine, data driven rules | `WEBSITE_RULES` merged into `detection.js`, rows in `detection_rules`, no AI in the decision path. |
| D15 | Notification throttling | 15 minute cooldown per incident, priority increase bypasses it, hourly organization cap, suppression reason stored. |
| D16 | No outbound requests to customer sites | Normalization is pure and tested with `fetch` replaced by a throwing stub. Verification only resolves DNS. |

## Deviations and interpretations

### 1. Layers L17 to L24 were not supplied

The provided prompt ends at L16 (548 lines). The task library, gate matrix and owner decision register referenced by L18, L20 and L24 are absent. Task cards W1 to W10 were derived from the L5.1 workflow and are recorded in STATUS.md. This is the largest deviation in the work.

### 2. Feature flag defaults

The prompt says `WEBSITE_PROTECTION_ENABLED` defaults to `false`. Implemented as: explicit `SF_WEBSITE_PROTECTION` or `WEBSITE_PROTECTION_ENABLED` wins; otherwise the feature is on outside production and off in production. Local development therefore works without configuration, and a production deployment is closed by default. This follows the L2.1 sentence that development proceeds regardless of gates. It is a deviation from the literal word "default false" and is recorded here.

### 3. Overlapping parent and host claims

The prompt requires deterministic conflict handling but the unique index only covers exact hostnames. Implemented policy, inside a `BEGIN IMMEDIATE` transaction:

- A verified host claim blocks a later domain scope claim for its registrable domain.
- A verified domain scope claim blocks a later host claim under that domain.
- Two simultaneous claims: the first transaction commits, the second sees it and returns `409 site_conflict`.
- The partial unique index remains the final guard for exact hostnames.

Consequence: the first verified owner wins. A host claim can block the domain owner from registering the parent domain, which is intentional and documented as first writer wins. Revocation or soft deletion releases the claim.

### 4. `expired` site state

L5.2 lists `expired` only as a verification state. The interface and schema also use `website_sites.status = 'expired'` when the challenge expires without success. This keeps the wizard resumable and is visible in the UI. The alternative, leaving the site pending with an expired challenge, was rejected because the list would show a misleading status.

### 5. Notification channel

No SMTP, webhook or notification service exists in the repository. Notifications are stored in `notifications` with `channel = 'in_app'`. Suppression is a first class state with a reason. No delivery mechanism was invented.

### 6. Incident priority formula

Severity strings map to the numeric scale used by L12.3: `info` 1, `low` 2, `medium` 2, `high` 3, `critical` 4. `raw = 2 x severity + criticality`, `P1 >= 13`, `P2 10 to 12`, `P3 7 to 9`, otherwise `P4`. A critical detection on a criticality 3 website therefore produces P2, matching the acceptance scenario.

### 7. Incident title on escalation

The title follows the highest severity rule that joined the incident. It is updated when the severity increases, otherwise the first title is kept. The fix is commit `60e02c8`.

### 8. Authorization header

The prompt text in L9 is partly redacted in the supplied file. The implementation accepts `Authorization: Bearer <key>` only, as described elsewhere in the same prompt. Keys in a query string or cookie are refused.

### 9. Public suffix library

`tldts` 7.4.21 was added. Registry check: MIT, one dependency (`tldts-core`), no install scripts. Private suffixes are enabled for the "is this a public suffix" check, so a shared platform suffix such as a hosting provider's cannot be claimed.

### 10. Test and demo DNS seam

`SF_DNS_FAKE_FILE` points the resolver at a JSON map. It exists so tests and the local walkthrough never perform a real DNS query. `checkProductionConfig` refuses to start when the variable is set in production. The dashboard labels `.test` names as `test domain`.

### 11. Step-up instead of a full re-authentication factor

Gate G2 is implemented as password re-entry plus TOTP when enabled, valid for ten minutes per session. WebAuthn and SSO are absent from the product, so no stronger factor could be reused. G2 remains OPEN-RISK.

### 12. Scheduler

No job runner existed. `website_jobs` uses an atomic claim with a 60 second lease. It is safe for several processes on one database and is not a distributed queue. Jobs cover pending verification, daily re-verification, the post commit pipeline, hourly health and daily retention.

### 13. Retention

Website events follow the existing organization `retentionDays` default of 90 days. The job deletes only rows with `website_site_id` set, plus idempotency markers, usage counters, verification attempts and old notifications. Incidents, detections and audit records are kept. A legal hold in organization settings stops all deletion.

### 14. Export and deletion

Export is a synchronous JSON response, scoped by organization, with `Cache-Control: no-store`. No file is written to disk, so there is no download link to expire. Deletion is a recorded request (`website_deletion_requests`) with counts and a completion timestamp.

## Owner decisions with defaults

| ID | Question | Default applied | Change requires |
| --- | --- | --- | --- |
| Q1 | Verification method | DNS TXT | Code and docs |
| Q2 | Grace period | 14 days | Environment variable |
| Q3 | Actor identifier mode | Hashed in the SDK example, raw accepted | Customer configuration |
| Q4 | Event retention | 90 days | Organization setting |
| Q5 | Deletion scope | Events and markers, keep incidents | Code |
| Q6 | Package name | `secureflow-sdk-node`, private | Package metadata |
| Q7 | File verification method | Off, not implemented | Code and gate G6 |
| Q8 | Notification channel | In-app only | New delivery integration |
| Q9 | Public suffix library | `tldts` | Dependency change |
| Q10 | Suggested TTL | 300 | UI text |
| Q11 | Resolver hardening | System resolver, optional list | Code |

## Things deliberately not built

- Browser SDK, publishable keys, origin allowlists.
- WAF integration, request blocking, automated action on a customer website.
- Active scanning, crawling or fetching the customer website.
- Billing, plans, quotas beyond the documented limits.
- WebSocket streaming. The existing Server-Sent Events stream is reused.
- Email verification or password reset. They are blocked on mail infrastructure and are the reason G1 fails.
- AI scoring. No model exists in the repository and none was added.
