# Security audit

Date: 9 November 2026
Scope: the SecureFlow AI repository at `C:\Users\ksidd\OneDrive\Pictures\Desktop\hack`
Method: source review of every server route, middleware, service and migration; the React client; database schema; dependency audit (`npm audit`); and execution of the full test suite (42 tests). Nothing below is marked confirmed without a reproduction or a test.

## Architecture as built

- Node 24 + Express 4 API, SQLite (WAL, built-in `node:sqlite`), 30 tables across 4 migrations.
- React 19 + TypeScript client, session cookie authentication, role based access, per-organization scoping.
- Deterministic detection engine, native multi-agent simulation engine, optional MiroFish HTTP adapter.
- **No LLM, no prompt templates, no agent framework, no model provider.** It is documented as a detection platform whose scoring is deterministic.
- Optional integrations (Wazuh, Sysmon, Suricata, Zeek, ClamAV, YARA, VirusTotal, AbuseIPDB) report honest configured/unconfigured state; collectors are not implemented.

## Confirmed findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SEC-001 | Critical | Any empty database was seeded with a public demo admin (`admin@secureflow.dev`), and the passwords were compiled into the client bundle. A production deployment would have shipped an internet-facing admin password. | Fixed, verified |
| SEC-002 | High | CSRF: state-changing requests with no `Origin` header bypassed the only check, and there was no CSRF token. | Fixed, verified |
| SEC-003 | High | SOAR: destructive actions could lose their approval requirement by editing workflow config or the stored flag. No approval expiry, idempotency or emergency pause. | Fixed, verified |
| SEC-004 | High | Audit logging swallowed write failures and rows were mutable with no tamper evidence. | Fixed (hash chain, verify endpoint, failures throw), atomicity partial |
| SEC-005 | High | Forensics trusted the declared MIME type; no file signature check and no malware scanning. | Fixed signature check + ClamAV adapter; live scan not verified |
| SEC-006 | Medium | Login throttling was per IP only, so distributed attempts against one account were not limited. | Fixed, verified |
| SEC-007 | Medium | `scryptSync` on the login/registration path blocked the event loop; a burst of logins could stall every request. | Fixed for request paths, verified by suite |
| SEC-008 | Medium | The MFA challenge cookie lacked `Secure` in production and used `SameSite=Lax`. | Fixed |
| SEC-009 | Medium | Report CSV export allowed spreadsheet formula injection (cells starting with `= + - @`). | Fixed, verified |
| SEC-010 | Medium | Production configuration was not validated; demo mode could be enabled silently and insecure origins accepted. | Fixed |
| SEC-020 | High (dependency) | `zod < 4.6.6` has a memory exhaustion advisory (GHSA-mrhx-c7xc-m3w5). | Fixed by upgrading to 4.6.7, tests pass |
| SEC-011 | Medium | MFA is available but not enforced per organization policy. `mfaPolicy` is stored but not applied at login. | Open |
| SEC-012 | High (operational) | No password reset and no email verification. Without SMTP the product cannot support self-service recovery. | Open, blocked on infrastructure |
| SEC-013 | Medium | Rate limits are in-process; horizontal scaling has no shared counter and restarts reset limits. | Open |
| SEC-014 | Medium | Audit records are chained but not written in the same transaction as every critical business change. | Partial |
| SEC-015 | Medium | Evidence custody records are hashed at action time but not chained; deletion/reordering of custody rows is not detectable. | Open |
| SEC-016 | Low | Only "revoke all other sessions" exists; individual session revocation is not exposed. | Open |
| SEC-017 | Low | TOTP only; no WebAuthn or SSO. | Accepted limitation |
| SEC-018 | Low | CSP allows inline styles; HSTS is not set by the app (reverse proxy responsibility). | Accepted, deployment |
| SEC-019 | Medium | External integration collectors are not implemented. Status is honest but no telemetry is ingested automatically. | Known limitation |

## Evidence for the critical findings

**SEC-001.** The server seeded demo users with fixed passwords whenever the organization table was empty; the same credentials existed in the web bundle. Reproduction before the fix: fresh database, start, login as admin with the documented password. Fix: `SF_DEMO_MODE` gating, production bootstrap admin from environment, runtime demo-account endpoint. Verification: production start without bootstrap exits with an instruction; with bootstrap creates that admin; `npm run build` output contains no demo password.

**SEC-002.** `checkOrigin` returned `next()` when `Origin` was absent. A browser form POST from another site could omit it in some legacy paths, and any non-browser client could mutate state with only a stolen cookie. Reproduction: authenticated `POST /api/assets` with cookie and no token returned 201. Fix: session-bound double-submit token (`sf_csrf` cookie + `x-csrf-token` header, hashed token stored on the session row), plus the origin check. Verification: `tests/hardening.test.mjs`, first test (missing token 403, wrong token 403, valid token without Origin 201, cross-origin with token 403).

**SEC-003.** `needsApproval` was `workflow.requires_approval === 1 && destructive`. Setting the flag to 0 removed approval. Reproduction: create a workflow with `isolate_host` and `requiresApproval:false`, run it, observe immediate execution. Fix: destructive actions always require approval, config cannot disable it, approvals expire after 30 minutes, idempotency keys return the original execution, workspace pause blocks runs. Verification: `tests/hardening.test.mjs`, third and fourth tests.

**SEC-004.** `audit()` caught insert errors and continued; no integrity fields. Reproduction: inspecting `audit_logs` (no hash, no chain). Fix: per-organization SHA-256 chain over immutable fields, `prev_hash`/`hash` columns, verification endpoint, insert failures propagate. Tamper test updates an action through a second SQLite connection and the verify endpoint reports `brokenAt`. Verification: `tests/hardening.test.mjs`, second test.

**SEC-005.** Uploads only checked a MIME allowlist supplied by the client. Reproduction: a text buffer declared as `image/png` was accepted. Fix: magic-byte signatures for PNG/JPEG/PDF/ZIP, reject mismatch; optional ClamAV INSTREAM scanner with timeout; fail closed in production when configured but unavailable; `scan_status` persists `not_scanned` honestly. Verification: signature test passes; scanner path is unit-implemented but **not verified against a live ClamAV daemon** in this environment.

## Systematic review results (no confirmed issue found)

| Area | Result |
| --- | --- |
| SQL injection | Every query uses bound parameters; dynamic WHERE fragments are built only from fixed strings. |
| XSS | React escapes by default; no `dangerouslySetInnerHTML`; report Markdown is rendered as text. |
| IDOR / tenant isolation | Every resource query includes `org_id` from the session; cross-tenant tests cover assets, incidents and simulations. |
| Path traversal | Upload filenames are reduced to a basename; storage and download paths are resolved and checked against the evidence directory. |
| SSRF | Private/loopback/link-local ranges blocked before connect; address pinned at connection time; redirects revalidated. |
| Command injection | No shell execution anywhere in the server. |
| Insecure deserialization | JSON only; no `eval`, no `Function`, no object revival. |
| Session fixation | Session identifiers are generated server side; a client cannot propose one. |
| Open redirect | None implemented. |
| Secret leakage | Provider keys read from environment only; settings API rejects secret-like fields; database and evidence excluded from Git. |

## Architectural weaknesses

1. **Single-node assumptions.** SQLite, in-memory rate limits, in-memory simulation timers and per-process SSE. Documented; not a vulnerability by itself.
2. **Audit atomicity.** Hash chaining detects tampering, but a crash between a business write and its audit insert can leave an action without a record. The highest risk operations should be moved into a single transaction with the audit write.
3. **AI claims vs implementation.** No model exists. Any future AI feature must not reuse the current "deterministic score" language for probabilistic output, and must add the tool gateway described in `PROMPT_ENGINE_ARCHITECTURE.md`.

## Out of scope / not testable here

- Live MiroFish execution (Python 3.11-3.12, LLM and Zep credentials).
- Real ClamAV scanning (no daemon).
- TLS/HSTS behaviour (no deployed host).
- External provider reputation calls (no keys).
- Horizontal scaling and shared rate limiting (no Redis).
