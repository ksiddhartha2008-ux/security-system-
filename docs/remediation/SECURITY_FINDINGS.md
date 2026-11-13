# Security findings

Scope: code review and automated checks on 13 November 2026, plus the changes in this remediation. An independent penetration test has not been performed; see `PENETRATION_TEST_PLAN.md`.

Severity follows CVSS qualitative bands. Every fixed finding has a regression test or a reproducible check.

## Summary

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SEC-01 | High | Rate limits were per process, so a second instance doubled the allowance | Fixed, tested |
| SEC-02 | Medium | API responses could be cached by browsers and shared proxies | Fixed, tested |
| SEC-03 | Low | Missing HSTS and cross origin resource policy | Fixed, tested |
| SEC-04 | Low | Login timing distinguished unknown emails from wrong passwords | Fixed, reviewed |
| SEC-05 | Low | Post-login destination accepted arbitrary input | Fixed |
| SEC-06 | Low | Provider responses were used without validation and without retry or cache | Fixed, tested |
| SEC-07 | Medium | Audit write is not in the same transaction as the business write | Residual, documented |
| SEC-08 | Informational | Session cookie has no `__Host-` prefix | Residual |
| SEC-09 | Informational | No independent penetration test | NOT VERIFIED |

## SEC-01 High: rate limits could be bypassed by switching instances

- Component: `backend/src/lib/ratelimit.js`.
- Evidence: counters lived in a process `Map`; two instances each enforced the full allowance.
- Root cause: no shared store; no response headers so the bypass was invisible.
- Remediation: store abstraction with a Redis implementation using one atomic Lua script, response headers, accurate `Retry-After`, fail closed for login, MFA, step-up and registration, bounded local fallback elsewhere.
- Regression test: `backend/tests/ratelimit.test.mjs` (8 tests) and `backend/tests/ratelimit-redis.test.mjs` (2 tests, real Redis in CI).
- Retest: two limiter instances sharing one store refuse the fourth request. CI job `redis` runs it against `redis:7.4-alpine`.
- Residual risk: during a Redis outage the local fallback multiplies the limit by the number of instances; sensitive policies refuse instead.

## SEC-02 Medium: tenant responses were cacheable

- Component: `backend/src/index.js`.
- Evidence: no `Cache-Control` header on `/api` responses.
- Root cause: headers were added per route only for the SPA shell.
- Remediation: `Cache-Control: no-store` on every `/api` response.
- Regression test: header assertion in the API sweep; readiness response inspected.
- Residual risk: none identified.

## SEC-03 Low: missing transport and cross origin headers

- Component: `backend/src/index.js`.
- Evidence: no HSTS, no `Cross-Origin-Resource-Policy`, no `X-Permitted-Cross-Domain-Policies`.
- Remediation: HSTS in production only (the local run is HTTP), CORP `same-origin`, cross domain policies `none`.
- Retest: response headers inspected with `curl -D -`.
- Residual risk: HSTS is only effective when the deployment actually terminates TLS; that is a staging check.

## SEC-04 Low: login timing could reveal whether an email exists

- Component: `backend/src/routes/auth.js`.
- Evidence: an unknown email returned before the scrypt comparison, a wrong password ran scrypt. The difference is measurable.
- Root cause: short circuit on `!user`.
- Remediation: an unknown email now verifies against a real dummy scrypt hash, so both paths spend the same work. The message and status were already identical.
- Retest: code review plus the existing authentication tests. A timing test would be flaky in CI and is not claimed.
- Residual risk: scrypt cost varies with hardware noise; the response text is identical.

## SEC-05 Low: post-login redirect accepted any value

- Component: `frontend/src/pages/Public.tsx`.
- Evidence: `next` from the query string was passed to the router unchanged.
- Remediation: only a single slash absolute path is accepted; protocol relative and absolute URLs fall back to `/overview`.
- Residual risk: the value is still a client side route, which is correct for this SPA.

## SEC-06 Low: provider responses were trusted and repeated

- Component: `backend/src/routes/intel.js`, `backend/src/services/phishing.js`.
- Evidence: `response.json()` was used without a schema, with no retry, no cache and no health record. The same code existed twice.
- Remediation: `backend/src/services/reputation.js` with Zod validation, an 8 second timeout, one bounded retry for transient failures, a 10 minute cache, per provider health and no key material in errors.
- Regression test: `backend/tests/reputation.test.mjs` (8 tests) against a local stub.
- Residual risk: a provider can change its response shape; that now surfaces as an explicit error rather than a silent zero.

## SEC-07 Medium residual: audit is not transactional with the business write

- Component: `backend/src/lib/audit.js` and the routes that call it after a write.
- Evidence: `audit()` throws on failure, which fails the request, but the business row was already committed. A crash between the two leaves an action without its audit row.
- Why not fixed here: wrapping every route in a transaction changes locking and error behaviour across 19 modules and needs its own test pass. Doing it silently in a remediation commit would be riskier than documenting it.
- Compensating controls: the audit chain detects tampering and missing hashes; `verifyAuditChain` is admin only; critical actions already write audit synchronously in the request path.
- Recommended fix: a `withAudit(fn)` helper that opens a transaction, performs the write and the audit insert, then commits. Apply to evidence sealing, user management, key creation and deletion, data deletion, and workflow approval first.
- Status: PARTIALLY IMPLEMENTED, documented.

## SEC-08 Informational: cookie prefix

The session cookie is `sf_session`, HttpOnly, SameSite=Lax, Secure in production. A `__Host-` prefix would add origin binding but requires renaming and invalidating every existing session. Documented for a maintenance window, not changed here.

## SEC-09 Informational: independent testing

Automated scans, code review and the test suite are not a penetration test. Status remains NOT VERIFIED.

## Controls verified as sound

| Control | Evidence |
| --- | --- |
| Password storage | scrypt, per user salt, timing safe compare |
| Session tokens | 32 random bytes, stored hashed, HttpOnly, same site |
| CSRF | double submit bound to session hash plus origin check |
| MFA | TOTP, short lived challenge cookie, replay window |
| Tenant isolation | organization from session, 404 for other tenants, isolation tests |
| SSRF | every redirect hop resolved and checked against private ranges |
| Uploads | MIME allowlist, magic bytes, size cap, ClamAV fail closed in production |
| API keys | hashed secret, constant time compare, revocation, step-up for creation |
| SOAR | destructive actions require server side approval and are labelled simulated |
| SQL injection | parameterised statements throughout; a hostile path is stored as text in tests |
| XSS | event fields rendered as text; no `dangerouslySetInnerHTML` in the client |
| Secrets | secret scan clean; no key in the frontend bundle |
| Dependency risk | 0 known vulnerabilities in frontend and backend production trees |

## Retest commands

```powershell
npm test
npm run scan:secrets
node scripts/health-check.ps1
npm run test:a11y --prefix frontend
```

`SF_REDIS_URL` set plus the CI Redis job covers the shared limiter.
