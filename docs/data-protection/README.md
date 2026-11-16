# Customer credential and database protection

SecureFlow monitors **security metadata** from protected websites. It does not
receive, store or process customer passwords, session cookies, bearer tokens,
payment data or request bodies. That boundary is enforced at ingestion, not by
policy alone.

## What is implemented and tested

| Control | Status | Evidence |
| --- | --- | --- |
| Strict event allowlist at ingestion | COMPLETED AND TESTED | `backend/src/services/websiteIngest.js`: unknown fields reject the event; unknown attributes are dropped |
| Secret stripping in metadata | COMPLETED AND TESTED | `password`, `passwd`, `secret`, `token`, `authorization`, `cookie`, `api_key`, `session`, `card`, `cvv`, `ssn` are removed before storage; `backend/tests/data-protection.test.mjs` asserts `dropped_fields` |
| Tenant identity from the API key | COMPLETED AND TESTED | `verifyApiKey` resolves the site and organisation; payload org fields are rejected as unknown |
| Credential attack detection | COMPLETED AND TESTED | Existing `w-auth-001`, `w-auth-002`, `w-acc-001`, `w-intel-001`; new `w-api-001` denial burst |
| Database attack detection | COMPLETED AND TESTED | New `w-db-001` repeated auth failures, `w-db-002` bulk export, `w-db-003` schema change, `w-db-004` privileged operation burst |
| Incident correlation and evidence | COMPLETED AND TESTED | Existing website pipeline turns detections into incidents with entities and timeline |
| Protection summary API | COMPLETED AND TESTED | `GET /api/data-protection/overview`, tenant scoped; four API tests |
| Data protection page | COMPLETED AND TESTED | `/data-protection`, accessible in both themes, no console errors |
| Audit chain status | COMPLETED AND TESTED | The page reports the result of `verifyAuditChain`, including a broken row reference |
| MFA, sessions, RBAC, rate limits | COMPLETED AND TESTED | Existing suites, unchanged |
| Cross-tenant isolation | COMPLETED AND TESTED | New workspace sees zeros while the demo workspace sees its own evidence |

## Event contract

Allowed types, all metadata only:

```
auth.login_failed              auth.login_succeeded
auth.password_reset_requested  auth.mfa_failed
auth.signup                    access.denied
request.suspicious             request.rate_limited
app.error                      sdk.connectivity_test / sdk.heartbeat
user.account_locked            user.password_changed
api.authorization_denied       api.rate_limit_triggered
database.auth_failed           database.privileged_operation
database.schema_changed        database.bulk_export
```

Example, with no sensitive values:

```json
{
  "event_id": "6c1c4a4e-6f5e-4b7e-9f7a-0d6f4f7f9a11",
  "type": "database.bulk_export",
  "occurred_at": "2026-11-16T09:12:00Z",
  "client": { "ip": "203.0.113.10" },
  "attributes": { "records": 1200, "table": "customers" }
}
```

If the SDK sends `attributes.password`, the field is counted in `dropped_fields`
and never written to the database. If it sends an unknown field, the event is
rejected with a code, so a broken integration is visible instead of silent.

## Detection rules

| Rule | Condition | Severity |
| --- | --- | --- |
| `w-db-001` | 5 failed database authentications from one source in 10 minutes | high |
| `w-db-002` | 500 or more exported records, or three exports, in 30 minutes | high, critical at 5000 records |
| `w-db-003` | Any schema change; three or more in 30 minutes | medium, high at three |
| `w-db-004` | 10 privileged operations from one source in 10 minutes | high |
| `w-api-001` | 25 authorisation denials from one source in 5 minutes | medium |

Thresholds are starting values with fixtures, not a claim of optimal tuning.
Every detection stores the factors behind its risk score and is correlated into
an incident by the existing pipeline.

## Not implemented, and why

| Item | Status | Reason |
| --- | --- | --- |
| Argon2id in the protected website | CUSTOMER RESPONSIBILITY | SecureFlow never stores customer password hashes. The integration documentation recommends Argon2id in the shop's own stack. SecureFlow's own users use scrypt with per-user salts. |
| Database audit log collector | BLOCKED | Needs a database audit export or a log shipper. No database audit source exists here. The SDK carries application-emitted database metadata only. |
| Encryption at rest verification | NOT VERIFIED | Depends on the deployment volume, not the application. No production host exists to inspect. |
| Backup encryption assessment | NOT IMPLEMENTED | The backup tool exists; an automated encryption assessment does not. Documented in `docs/remediation/BACKUP_RECOVERY_GUIDE.md`. |
| AI analysis of these events | NOT IMPLEMENTED | There is no model provider in this build. The prompt engine document states the same. Nothing here is labelled AI analysis. |
| Automatic response (revoke key, lock account, block IP) | PARTIALLY IMPLEMENTED | API key revocation exists and is audited. Firewall blocks go through TriShield approval. Account lock and password reset in the customer application are not implemented. |
| CVV or card data | NOT ACCEPTED | No field for it. The SDK allowlist has no payment attributes, and `card`/`cvv` keys are stripped. |

## Privacy boundary

- Passwords, hashes, cookies, tokens, authorization headers and request bodies are
  not accepted by the ingestion schema.
- The SDK sends a pseudonymous actor identifier when the shop wants correlation;
  `id_mode` supports `hash`, `raw` or `omit`.
- Source addresses are masked in the protection page and in TriShield lists.
- Events are retained under the existing website retention policy; deleting a
  website removes its event data with an audit record.
- No customer production database is copied into the demo snapshot; the exporter
  purges TriShield tables and sessions.

## What this page does not claim

It does not claim that a shop cannot be breached. It reports configured metadata
sources, deterministic pattern matches and the evidence trail. Database coverage
is application-level metadata: ordinary database connections do not reveal every
query executed inside the engine, and the page says so.

## Testing

- `backend/tests/data-protection.test.mjs`: secret dropping, five new rules, the
  summary shape, MFA and audit fields, masking, and cross-workspace zeros.
- `backend/tests/website-*.test.mjs`: existing ingestion, detection and incident
  behaviour, unchanged.
- `frontend/e2e/a11y.spec.ts` and `health.spec.ts`: `/data-protection` in both
  themes, no console errors.
- Full suite result at the time of writing: 169 backend tests (167 pass, 2
  skipped) and 81 Playwright checks.
