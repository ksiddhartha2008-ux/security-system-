# Website protection status

Feature: website onboarding, domain ownership verification, scoped API credentials, SDK, event ingestion, detection, incidents and dashboard.

Code commit: `7d58cd1` (feature), `60e02c8` (incident title fix). Documentation commit: this file's commit.
Date: 11 November 2026 (UTC).
Environment: Node 24.20.0, Windows, SQLite through `node:sqlite`, local development only. No production access.

## How to read this folder

| File | Purpose |
| --- | --- |
| [STATUS.md](STATUS.md) | Task status, launch gates, owner decisions, verdict |
| [REUSE_MAP.md](REUSE_MAP.md) | What existing code the feature reuses, with paths |
| [DECISIONS.md](DECISIONS.md) | Binding decisions, deviations and defaults applied |
| [EVENT_MAPPING.md](EVENT_MAPPING.md) | SDK types to stored events |
| [HTTP_API.md](HTTP_API.md) | Raw ingestion API for non Node clients |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Abuse cases and the tests that cover them |
| [SECRET_SCANNING.md](SECRET_SCANNING.md) | Key pattern, scanning commands, response steps |
| [verification/](verification/) | Evidence files, one per card group |

## Scope note

The supplied prompt defines layers L0 to L16 and states that L17 to L24 (task library, gates matrix, owner decisions) follow. They were not present in the file that was provided (548 lines, ending at L16). The cards below were therefore derived from the owner workflow in L5.1 and the abuse cases in L14. This is a deviation from the prompt, recorded here and in DECISIONS.md.

## Task cards

Status values follow L3: `NOT_STARTED`, `IN_PROGRESS`, `IMPLEMENTED`, `VERIFIED`, `FAILED`, `BLOCKED`, `N/A`, `DEFERRED`.

| ID | Card | Status | Evidence |
| --- | --- | --- | --- |
| W1 | Website onboarding and input normalization | VERIFIED | [W1.1](verification/W1.1.md) |
| W2 | DNS TXT ownership verification, conflicts, re-verification | VERIFIED | [W1.2](verification/W1.2.md) |
| W3 | Scoped API credentials, one time display, revocation, rotation | VERIFIED | [W2.1](verification/W2.1.md) |
| W4 | Event ingestion, limits, idempotency, trust boundary | VERIFIED | [W2.2](verification/W2.2.md) |
| W5 | Detection rules and measured quality on a labelled corpus | VERIFIED | [W3.1](verification/W3.1.md) |
| W6 | Incident correlation and notification throttling | VERIFIED | [W3.2](verification/W3.2.md) |
| W7 | Website dashboard, wizard, detail tabs, key management | VERIFIED | [W4.1](verification/W4.1.md) |
| W8 | Scheduler, leases, retention, export, deletion | VERIFIED | [W5.1](verification/W5.1.md) |
| W9 | Tenant isolation, CSRF, audit atomicity, negative security tests | VERIFIED | [W6.1](verification/W6.1.md) |
| W10 | Node SDK reliability and packaging | VERIFIED | [W7.1](verification/W7.1.md) |

`VERIFIED` means the check in the evidence file ran and passed. Nothing in this folder is based on reading code alone.

## Launch gates

| Gate | Requirement | Status | Evidence and reason |
| --- | --- | --- | --- |
| G1 | Verified email required before adding a website | **BLOCKED** | `users` has no email verification column (`backend/src/migrations/001_init.sql`), and no mail infrastructure exists. `createSite` does not require it. The feature flag is therefore off by default in production. |
| G2 | Recent authentication or MFA step-up for sensitive actions | **OPEN-RISK, interim implemented** | `POST /api/auth/step-up` checks the password and, when enabled, a TOTP code, then records `sessions.reauthenticated_at` for ten minutes. Key creation, key revocation, website deletion and data deletion require it. This is not a hardware-backed step-up. |
| G3 | Tenant isolation tests pass for every new table and endpoint | **PASS** | `backend/tests/website-api.test.mjs`, test `another organization cannot read, change or verify the website`. |
| G4 | Transactional audit helper | **PASS** | `backend/tests/website-scheduler.test.mjs`, test `a failed business change rolls back its audit entry`. |
| G5 | Rate limiting works across all backend instances | **PARTIAL** | Session routes use the existing in-process limiter. Website ingestion and verification also use durable SQLite counters (`website_usage`, `website_verification_attempts`), which survive a restart and work with several processes on one database. Several databases or hosts would need a shared store. |
| G6 | SSRF safe fetcher for the optional file method | **N/A** | The file and meta tag methods are not implemented. v1 performs DNS lookups only and never requests the customer website. |

A failed or blocked critical gate means the feature is not production ready. See the verdict below.

## Owner decisions applied

The owner did not answer the decision register, so the documented defaults in DECISIONS.md were applied. Each one can be changed without a schema migration unless stated.

| ID | Decision | Default applied |
| --- | --- | --- |
| Q1 | Verification method | DNS TXT only |
| Q2 | Grace period before lapse | 14 days (`SF_WEBSITE_VERIFICATION_GRACE_DAYS`) |
| Q3 | Actor identifier handling | Hashed by default in the SDK, raw accepted if the customer chooses |
| Q4 | Website event retention | 90 days, from the existing organization `retentionDays` setting |
| Q5 | Deletion scope | Website events and idempotency markers; detections and incidents retained as audit records |
| Q6 | SDK package name | `secureflow-sdk-node`, `private: true`, not published |
| Q7 | Optional file verification | Off, not implemented |
| Q8 | Notification channel | In-app record only, because no SMTP or webhook exists |
| Q9 | Public suffix library | `tldts` 7.4.21, MIT, verified in the registry |
| Q10 | Suggested DNS TTL | 300 seconds, shown as a suggestion only |
| Q11 | Resolver hardening | System resolver by default, optional `SF_DNS_RESOLVERS`, no two resolver corroboration |

## Verified results

| Check | Command | Result |
| --- | --- | --- |
| Backend suite | `npm test` | 91 tests, 91 pass, 0 fail |
| SDK suite | `npm run test:sdk` | 13 tests, 13 pass, 0 fail |
| Type check | `npm run typecheck` | exit 0 |
| Production build | `npm run build` | 568 kB JavaScript, 26.6 kB CSS |
| Migration on a copy of the live database | `node scripts/_migrate-test.mjs` (temporary) | schema v5, 41 tables, 711 existing events preserved |
| Browser walkthrough | manual, 424 px viewport | website created, verified, key created once, events ingested, two detections, one P2 incident |
| Detection corpus | `backend/tests/website-detection.test.mjs` | precision 1.000, recall 1.000, F1 1.000 on 93 benign and 77 attack events |

The corpus is synthetic and small. It measures the rules against the cases it contains, not field accuracy. No claim is made about real traffic.

## Residual risk

1. **G1 is blocked.** Anyone who can create an account can register a website if the feature is enabled in production. Keep the flag off until email verification or an equivalent control exists.
2. **DNS is trusted.** Verification trusts the configured resolver. A spoofed answer could satisfy the challenge. Two resolver corroboration is optional and not implemented. Re-verification limits the window but does not remove the risk.
3. **Notification delivery is in-app only.** A suppressed notification is recorded with a reason and the incident is preserved, but no email or webhook is sent.
4. **Detection thresholds are starting values.** They were exercised by fixtures, not tuned against production traffic. The measured corpus has no false negatives by construction.
5. **Single node only.** SQLite, the in-process session limiter and the scheduler become a bottleneck or a coordination problem with several application hosts. The job table uses a lease, so several processes on one database are safe.
6. **Key cache window.** A validated key may be used for up to 10 seconds after a status change that is not a revocation. Revocation purges the cache immediately.
7. **No independent assessment.** Local tests do not replace a penetration test.
8. **No browser SDK and no request blocking.** Events exist only where the customer calls `track()`.
9. **The local demo uses a DNS test seam.** `SF_DNS_FAKE_FILE` was set while walking through the workflow so a `.test` name could be verified without owning a domain. Production refuses this setting at startup, and the site is labelled `test domain` in the interface.

## Verdict

**NOT PRODUCTION-READY. DEVELOPMENT-READY.**

The workflow is implemented end to end, tenant isolated, audited and covered by automated tests. It cannot be called production ready while G1 is blocked, G5 is single node only and no independent security assessment exists. Enabling it for real customers requires the owner to accept or close those gates.

## Reproduce the checks

```powershell
npm run install:all
npm test
npm run test:sdk
npm run typecheck
npm run build
```

The browser walkthrough needs a development server. To repeat it with a `.test` hostname:

```powershell
$env:SF_WEBSITE_PROTECTION='true'
$env:SF_ALLOW_TEST_HOSTNAMES='true'
$env:SF_DNS_FAKE_FILE='backend/data/demo-dns.json'
npm start
```

Publish the returned value in `backend/data/demo-dns.json` under the record name, then press **Verify now**. This seam is refused when `NODE_ENV=production`.
