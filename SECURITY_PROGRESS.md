# Security progress

Date: 9 November 2026. This file records only what was actually changed and run.

## Summary

| Metric | Value |
| --- | --- |
| Findings confirmed | 20 |
| Fixed and verified | 9 |
| Fixed, not fully verified | 2 (MFA cookie attributes, ClamAV adapter) |
| Partially fixed | 2 (audit atomicity, session revocation) |
| Open | 6 |
| Blocked on infrastructure | 1 (password reset / email verification) |
| Tests before | 33 |
| Tests after | 42 |
| Failures | 0 |
| Dependency audit | 0 vulnerabilities (server and web) |

## Finding status

| ID | Finding | Status | Evidence |
| --- | --- | --- | --- |
| SEC-001 | Public demo admin seeded in any environment; credentials in bundle | SECURITY VERIFIED | Production start without bootstrap exits; with bootstrap creates that admin; bundle contains no demo password |
| SEC-002 | CSRF missing token / missing-Origin bypass | SECURITY VERIFIED | `tests/hardening.test.mjs` first test |
| SEC-003 | SOAR approval could be disabled; no expiry/idempotency/pause | SECURITY VERIFIED | `tests/hardening.test.mjs` tests 3 and 4 |
| SEC-004 | Audit best effort, mutable, no tamper evidence | SECURITY VERIFIED (chain) | `tests/hardening.test.mjs` audit test |
| SEC-005 | Evidence MIME trusted; no scanner | SECURITY VERIFIED (signature) / IMPLEMENTED (scanner) | `tests/hardening.test.mjs`; no live ClamAV |
| SEC-006 | No account-based login throttle | SECURITY VERIFIED | `tests/hardening.test.mjs` last test |
| SEC-007 | Sync scrypt blocks event loop | TESTS PASSED | Full suite after async hashing; no timing benchmark |
| SEC-008 | MFA cookie flags | IMPLEMENTED | Code review; not asserted by test |
| SEC-009 | CSV formula injection | SECURITY VERIFIED | `tests/hardening.test.mjs` |
| SEC-010 | No production config validation | SECURITY VERIFIED (unit) | `checkProductionConfig` test |
| SEC-020 | zod advisory | SECURITY VERIFIED | `npm audit --prefix server` reports 0; full suite passes on 4.6.7 |
| SEC-011 | MFA not enforced by organization policy | OPEN | Setting stored; login does not enforce |
| SEC-012 | No password reset / email verification | BLOCKED | Requires SMTP provider and domain |
| SEC-013 | In-process rate limits | OPEN | Single-node limitation |
| SEC-014 | Audit not transactional with business change | PARTIAL | Hash chain exists; not every route wraps both |
| SEC-015 | Custody chain not tamper evident | OPEN | Hash at action only |
| SEC-016 | Individual session revocation | OPEN | Revoke-others exists |
| SEC-017 | No WebAuthn/SSO | OPEN | Limitation |
| SEC-018 | CSP inline styles; no HSTS | ACCEPTED | Proxy responsibility, documented |
| SEC-019 | Collectors absent | OPEN | Honest status surfaces |

## Changes made in this pass

| File | Change |
| --- | --- |
| `server/src/migrations/003_security.sql` | New columns for CSRF binding, audit chain, evidence scan status, approval expiry, idempotency |
| `server/src/db.js` | Migration v3 runner |
| `server/src/lib/auth.js` | CSRF cookie and session hash, `requireCsrf`, MFA cookie helpers, async password helpers |
| `server/src/routes/auth.js` | Account throttle, MFA cookie flags, async hashing, CSRF-compatible login |
| `server/src/index.js` | CSRF middleware, request id, production config validation, async bootstrap |
| `server/src/lib/audit.js` | Hash chained audit entries, verification, failures throw |
| `server/src/routes/settings.js` | Audit verify endpoint, automation pause and MFA policy settings, async user creation |
| `server/src/routes/automation.js` | Mandatory approval for destructive actions, expiry, idempotency, paused workspace |
| `server/src/routes/forensics.js` | Magic-byte validation, ClamAV adapter wiring, scan metadata |
| `server/src/lib/clamav.js` | New INSTREAM adapter |
| `server/src/routes/reports.js` | CSV formula neutralisation |
| `server/src/lib/config.js` | New production configuration checks |
| `server/src/lib/bootstrap.js` | Async password hashing |
| `server/package.json` | zod 3.23.8 → 4.6.7 |
| `web/src/lib/api.ts` | Send `x-csrf-token` on mutations |
| `server/tests/hardening.test.mjs` | New suite, 9 tests |
| `server/tests/helpers.mjs` | CSRF aware test client |

## Commands and results

```
npm test
tests 42 | pass 42 | fail 0 | duration_ms 45345

npm run typecheck --prefix web
(no output; exit 0)

npm run build --prefix web
dist/assets/index-*.js  ~504 kB (140 kB gzip)

npm audit --prefix server
0 vulnerabilities

npm audit --prefix web
0 vulnerabilities
```

## Live verification of the hardened build

An isolated instance was booted on port 4011 with a temporary database (`tools/verify-hardening.mjs`):

```
registerStatus 201
sessionCookie true
csrfCookie true
postWithoutToken 403
postWithToken 201
auditChain true
```

This confirms schema v3, CSRF enforcement and the audit chain on a clean database. The developer instance on port 4000 was started before this pass and still runs the previous process; it must be restarted to apply schema v3, which also invalidates existing sessions by design.

## Not verified

- Cookie flags on a real TLS deployment (no host).
- ClamAV scanning against a live daemon (adapter only).
- Behaviour under horizontal scale with a shared rate-limit store (not implemented).
- PostgreSQL RLS (not migrated).
- MFA policy enforcement (not implemented).
- Email based recovery and verification (blocked).

## Next actions, in order

1. Enforce `mfaPolicy` at login for admins, with an enrolment-only session state.
2. Wrap the highest risk mutations (workflow approval, evidence upload, role change, incident closure) in one transaction with the audit insert.
3. Hash chain custody records.
4. Add individual session revocation.
5. Add a shared rate-limit adapter (Redis) with fail-closed production behaviour.
6. Add SMTP and implement reset/verification tokens.
