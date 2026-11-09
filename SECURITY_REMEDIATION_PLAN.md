# Security remediation plan

Status values follow the task contract: NOT STARTED, INVESTIGATING, IMPLEMENTED, TESTS ADDED, TESTS PASSED, SECURITY VERIFIED, BLOCKED.

## Phase 1: authentication, CSRF, sessions

| Item | Change | Status | Evidence |
| --- | --- | --- | --- |
| CSRF token | Session-bound double-submit token, `sf_csrf` cookie plus `x-csrf-token` header, hashed on the session row | SECURITY VERIFIED | `tests/hardening.test.mjs` |
| Missing-Origin bypass | Authenticated mutations now require the token regardless of Origin; Origin mismatch still rejected | SECURITY VERIFIED | same test |
| MFA cookie | `sf_mfa` is `HttpOnly; SameSite=Strict; Secure` in production, cleared explicitly | IMPLEMENTED | code review; cookie attributes not asserted by a test |
| Account throttling | Ten failures per account per 15 minutes, in addition to per-IP limits | SECURITY VERIFIED | `tests/hardening.test.mjs` |
| Password hashing | Async scrypt for register, login, password change, MFA verification and admin-created users | TESTS PASSED | full suite, 42 tests |
| Session rotation | Password change deletes all sessions and issues a new one; session cap of ten | IMPLEMENTED | code review |
| Admin MFA policy | `mfaPolicy` setting accepted but not enforced at login | NOT STARTED | documented in SECURITY_PROGRESS |
| Password reset / email verification | Requires an email transport; none configured | BLOCKED | see blocker register |

## Phase 2: RBAC, IDOR, tenant isolation

| Item | Status | Evidence |
| --- | --- | --- |
| Cross-tenant read/write/delete on assets, incidents, simulations | SECURITY VERIFIED | `tests/isolation.test.mjs` |
| Client-supplied organization id ignored | SECURITY VERIFIED | `tests/isolation.test.mjs` |
| Nested resource authorization (assets, detections, evidence, reports) | SECURITY VERIFIED | route review; tenant scoping test covers representative paths |
| Admin-only routes (users, settings, audit, deletion) | SECURITY VERIFIED | `tests/auth.test.mjs` |
| PostgreSQL RLS | NOT STARTED | SQLite deployment; mapping documented in SECURITY_AUDIT |

## Phase 3: audit integrity and forensics

| Item | Change | Status |
| --- | --- | --- |
| Audit hash chain | `prev_hash`/`hash` per organization, verification endpoint, tamper detection test | SECURITY VERIFIED |
| Audit failure handling | Insert failures propagate instead of being swallowed | IMPLEMENTED |
| Transactional audit | Not applied to every critical route | PARTIAL |
| Evidence signature check | PNG/JPEG/PDF/ZIP magic bytes validated | SECURITY VERIFIED |
| Malware scanner | ClamAV INSTREAM adapter, timeout, fail closed in production when configured | IMPLEMENTED, not verified against a live daemon |
| Custody chaining | Not implemented | NOT STARTED |

## Phase 4: SOAR approval security

| Item | Status | Evidence |
| --- | --- | --- |
| Destructive actions always require approval | SECURITY VERIFIED | `tests/hardening.test.mjs` |
| Config cannot disable approval | SECURITY VERIFIED | same |
| Approval expiry (30 minutes) | SECURITY VERIFIED | same |
| Idempotency keys | SECURITY VERIFIED | same |
| Workspace emergency pause | SECURITY VERIFIED | same |
| Approver identity and audit | IMPLEMENTED | execution row + audit entry |
| Real action execution | NOT STARTED (no EDR/firewall integration) | simulated by design |

## Phase 5: rate limiting and API hardening

| Item | Status |
| --- | --- |
| Per-IP endpoint rate limits | IMPLEMENTED |
| Per-account login throttle | SECURITY VERIFIED |
| Shared/distributed counter (Redis) | NOT STARTED; single-node limitation documented |
| Body size limits, validation, error envelope, security headers | IMPLEMENTED |
| Request correlation id in audit | IMPLEMENTED |

## Phase 6: Prompt Engine and AI security

| Item | Status |
| --- | --- |
| Prompt Engine audit | COMPLETE: no Prompt Engine or LLM exists |
| Prompt injection defenses | NOT APPLICABLE (no prompts) |
| AI tool authorization gateway | NOT APPLICABLE (no AI tool calls) |
| Future architecture and requirements | DOCUMENTED in PROMPT_ENGINE_ARCHITECTURE.md |

## Phase 7: database and infrastructure

| Item | Status |
| --- | --- |
| SQLite security review (parameterized queries, tenant filters) | COMPLETE |
| PostgreSQL migration plan | NOT STARTED; mapping checklist documented |
| Production configuration validation | SECURITY VERIFIED (unit test + startup path) |
| Secrets in source | None; `.env` excluded, example file only placeholders |

## Phase 8: frontend and integration security

| Item | Status |
| --- | --- |
| CSRF header in the client | IMPLEMENTED |
| No sensitive storage; no tokens in localStorage | VERIFIED by review |
| CSV formula injection | SECURITY VERIFIED |
| Unsafe HTML rendering | None found |
| Integration status honesty | COMPLETE |

## Phase 9: regression and security testing

| Command | Result |
| --- | --- |
| `npm test` | 42 passing, 0 failing |
| `npm run typecheck --prefix web` | clean |
| `npm run build --prefix web` | success |
| `npm audit --prefix server` | 0 vulnerabilities (after zod upgrade) |
| `npm audit --prefix web` | 0 vulnerabilities |

## Dependency order and blockers

1. Shared rate limiting depends on a Redis (or equivalent) deployment; not available here. Documented, not faked.
2. Password reset and email verification depend on SMTP. Implemented nowhere rather than half-built.
3. Live ClamAV verification needs a daemon. Adapter implemented; production fails closed.
4. Audit atomicity requires refactoring every critical route into a transaction; the chain is in place and the highest risk paths are next.
5. PostgreSQL RLS requires a PostgreSQL instance and a full data migration; not attempted to avoid destructive change.

## Verification rules used

- A fix is only marked SECURITY VERIFIED when a test exercises the security behaviour and passes.
- Dependency changes require the full suite and the production build to pass.
- No test result in these documents was invented; commands and outcomes are recorded in SECURITY_PROGRESS.md.
