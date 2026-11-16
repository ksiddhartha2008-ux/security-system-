# SecureFlow AI: baseline security audit

Audit date: 16 November 2026
Repository: `C:\Users\ksidd\OneDrive\Pictures\Desktop\hack`
Commit audited: `b0aeb52` (`main`, equal to `origin/main`)
Mode: read-only audit. No application code was changed to produce this report.

Status vocabulary: **IMPLEMENTED**, **PARTIALLY IMPLEMENTED**, **SIMULATED**,
**MISSING**, **UNVERIFIED**, **BLOCKED**.

## 1. Architecture summary

| Layer | Reality |
| --- | --- |
| Frontend | React 19, TypeScript, Vite 6, Tailwind v4, Astryx 0.7.13. Session cookie auth, CSRF header, no tokens in storage. |
| Backend | Node 24, Express 4, Zod validation, `node:sqlite` (SQLite 3, WAL), schema v7 with 50 tables. |
| Auth | Server sessions hashed at rest, scrypt password hashes, TOTP MFA with hashed single-use recovery codes, step-up auth. |
| Tenancy | Every query is scoped by `org_id` from the session; API keys resolve the organisation server-side. |
| Monitoring | Deterministic detection rules, risk scoring with stored factors, incident correlation, hash-chained audit log. |
| Integrations | Real nftables and Cloudflare connectors, Suricata/Wazuh/WAF collectors, ClamAV and Wazuh health checks. Live provider verification is blocked in this environment. |

## 2. Findings

### Critical

None found. No unauthenticated remote code execution, no plaintext password
storage, no cross-tenant read found in reviewed code and tests.

### High

#### SF-AUTH-01: MFA is optional for administrators

- Category: authentication / privileged access
- Severity: High
- Affected: `backend/src/routes/auth.js` (MFA enrollment routes), `frontend` settings, `GET /api/trishield/overview` MFA counters
- Evidence: MFA is enrolled per user and never required by role. The live overview reports `0 of 3 active users have MFA` in the demo workspace. No route or policy requires MFA before admin actions; step-up accepts password alone when MFA is not enrolled (`/auth/step-up`).
- Attack scenario: an administrator password is phished or reused. The attacker signs in without a second factor, then approves a firewall action or creates API keys.
- Impact: full workspace compromise from one credential.
- Recommended correction: require MFA for `admin` (and optionally `analyst`) before privileged routes; block role assignment until enrollment; surface an enforcement banner and an enrollment path.
- Required regression tests: admin without MFA is refused on approve, execute, key creation, policy change; admin with MFA succeeds; enrollment cannot be skipped by calling the API directly.
- Status: **IMPLEMENTED AND TESTED** as of 16 November 2026. Baseline status before remediation: PARTIALLY IMPLEMENTED (MFA existed, enforcement did not). Evidence: ackend/tests/admin-mfa.test.mjs, docs/security-hardening/PHASE-1.1-ADMIN-MFA.md.

#### SF-BKP-01: Database backups are not encrypted

- Category: data protection / backup
- Severity: High if backups leave the host, Medium while they stay on it
- Affected: `backend/scripts/backup.mjs` (`createBackup`, `verifyBackup`)
- Evidence: the script writes a SQLite copy plus a SHA-256 sidecar, prunes by retention and can verify integrity. There is no encryption step, no key handling and no audit record for a backup download or restore.
- Attack scenario: a backup file is copied to shared storage or a laptop. It contains password hashes, sessions, audit logs, event metadata and encrypted IP vault rows.
- Impact: offline password cracking and disclosure of security records.
- Recommended correction: encrypt with a key from the deployment secret store (age or GPG), store the key separately, record create/download/restore in the audit log, and document a restore drill.
- Required regression tests: encrypted backup cannot be read without the key; verify detects a modified file; prune keeps the retention count; restore into a temporary database passes integrity checks.
- Status: **PARTIALLY IMPLEMENTED** (integrity and retention only).

### Medium

#### SF-AUTH-02: Email ownership is never verified

- Category: authentication / account lifecycle
- Severity: Medium
- Affected: `backend/src/routes/auth.js` (`POST /register`), `backend/src/migrations/001_init.sql` (`users`)
- Evidence: registration accepts any syntactically valid email and creates an active admin immediately. There is no verification token, no `email_verified` column and no mail delivery path.
- Attack scenario: an operator mistypes an address, or registers with a colleague's mailbox; notifications and future recovery mail go to the wrong person.
- Impact: misdelivery of security notifications, no trustworthy recovery channel.
- Recommended correction: add a verification token with expiry, keep the account usable only for enrollment until verified, and record the event in the audit log. If no mail provider exists, mark verification as BLOCKED and document it.
- Required regression tests: unverified account cannot receive privileged notifications; token expiry; replay rejected; verification audited.
- Status: **MISSING**.

#### SF-AUTH-03: No password reset or recovery flow

- Category: authentication
- Severity: Medium
- Affected: `backend/src/routes/auth.js`
- Evidence: no `/auth/password/forgot`, `/reset` or reset-token table exists. A user who forgets the password depends on another administrator changing it through Settings, which requires knowing the old password or direct database access.
- Attack scenario: not an attack vector by itself, but it pushes operators toward shared admin accounts or manual database edits.
- Impact: availability and accountability risk; weak operational workarounds.
- Recommended correction: one-time, hashed, short-lived reset tokens; constant response regardless of account existence; invalidate sessions on reset; audit both request and completion.
- Required regression tests: unknown email returns the same response; token single use and expiry; sessions revoked; audit rows written.
- Status: **MISSING**.

#### SF-AUTH-04: Session hardening gaps

- Category: session management
- Severity: Medium
- Affected: `backend/src/lib/auth.js` (`setSessionCookie`, `createSession`, `attachUser`)
- Evidence: the session cookie is `HttpOnly`, `SameSite=Lax`, 7-day absolute expiry, and `Secure` only when `NODE_ENV === 'production'`. There is no idle timeout, no `__Host-` prefix, and no re-check that the session's stored IP or user agent still matches. Sessions are hashed at rest, capped at ten per user, and rotated on password change.
- Attack scenario: a stolen cookie is replayed from another network for up to seven days; if the deployment forgets `NODE_ENV=production`, the cookie travels without `Secure`.
- Impact: extended replay window after cookie theft.
- Recommended correction: add an idle timeout, set `Secure` whenever the request is HTTPS or `SF_TRUST_PROXY=true`, consider the `__Host-` prefix, and record session IP/UA changes as a security event rather than trusting them silently.
- Required regression tests: idle expiry; secure flag behind a trusted proxy; rotation on password change; revoked session rejected; mismatch event recorded.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-AUTH-05: Password hashing cost below current guidance

- Category: password storage
- Severity: Medium
- Affected: `backend/src/lib/auth.js` (`hashPassword`, `verifyPassword`)
- Evidence: scrypt with Node's default parameters (N=16384, r=8, p=1), 16-byte random salt, 64-byte key, `timingSafeEqual`. OWASP recommends a higher scrypt work factor (N=2^17 class) or Argon2id. There is no rehash-on-login migration path.
- Attack scenario: an attacker with a database copy cracks weak passwords faster than necessary.
- Impact: lower offline cracking cost.
- Recommended correction: raise parameters or move to Argon2id, store the parameter set with the hash, rehash opportunistically on successful login.
- Required regression tests: old hashes still verify; new hashes use the new parameters; rehash occurs once; wrong password fails.
- Status: **PARTIALLY IMPLEMENTED** (sound construction, dated parameters).

#### SF-AUTH-06: Registration reveals whether an email exists

- Category: authentication / enumeration
- Severity: Medium (Low if registration is not public)
- Affected: `backend/src/routes/auth.js` (`POST /register`)
- Evidence: an existing address returns `409 An account with this email already exists`; a new one returns `201`. Login is enumeration-resistant (dummy scrypt hash, identical message).
- Attack scenario: an attacker enumerates customer or staff addresses, then targets phishing or credential stuffing.
- Impact: address discovery; small privacy leak.
- Recommended correction: always accept the request and send a neutral confirmation, or use a generic conflict message plus rate limiting. Keep the rate limit at 6 per hour.
- Required regression tests: identical status and body for new and existing addresses; no account created twice; rate limit still enforced.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-DB-01: SQLite file relies on OS permissions and has no at-rest encryption

- Category: database security
- Severity: Medium
- Affected: `backend/src/db.js`, deployment
- Evidence: WAL, `foreign_keys=ON`, `busy_timeout=5000` are set. There is no `secure_delete`, no application-level encryption of ordinary columns, and no check that the database file mode is restrictive. The IP vault is separately encrypted with AES-256-GCM.
- Attack scenario: another local account or a stolen disk image reads the database file, including password hashes, audit logs and event metadata.
- Impact: offline disclosure; deleted rows may remain in free pages.
- Recommended correction: enable `PRAGMA secure_delete`, document and verify file permissions, require full-disk encryption on the host, keep the vault key outside the database.
- Required regression tests: pragma asserted at startup; permission check script; deleted row not recoverable in a raw scan; vault requires the key.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-RL-01: Default rate limiting is per process

- Category: API security / availability
- Severity: Medium in multi-instance deployments, Low single instance
- Affected: `backend/src/index.js`, `backend/src/lib/ratelimit.js`
- Evidence: the store defaults to memory; Redis is optional. Sensitive policies use `failMode: 'closed'` and the limiter reports a degraded header, but two instances without Redis each allow the full quota.
- Attack scenario: an attacker spreads requests across instances and exceeds the intended login or ingestion limit.
- Impact: brute-force and ingestion abuse at scale.
- Recommended correction: require `SF_REDIS_URL` in any multi-instance deployment and fail startup or mark degraded when it is missing in production.
- Required regression tests: shared counter across two app instances; Redis outage behaviour for closed and local policies.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-UPL-01: Production does not require a malware scanner

- Category: file upload / malware
- Severity: Medium
- Affected: `backend/src/routes/forensics.js`, `backend/src/lib/clamav.js`, `backend/src/lib/config.js`
- Evidence: uploads are limited to 5 MB, MIME allowlist, magic-byte check, random storage name outside the web root. ClamAV scanning runs only when `CLAMAV_HOST` is set. In production a scanner error refuses storage, but an unset scanner only produces a startup warning and the file is stored as `not_scanned`.
- Attack scenario: a malicious file is sealed as evidence and later opened by an analyst.
- Impact: malware exposure through the evidence workflow.
- Recommended correction: require `CLAMAV_HOST` in production or make unscanned uploads unavailable for download until reviewed; record scanner version with each scan.
- Required regression tests: no scanner in production blocks upload; infected file rejected; scanner error keeps the file quarantined; clean file stored with version.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-AUD-01: Audit chain is local to the database

- Category: audit integrity
- Severity: Medium
- Affected: `backend/src/lib/audit.js` (`hashRecord`, `verifyAuditChain`), `GET /api/settings/audit-logs/verify`
- Evidence: entries are hash-chained over the previous hash and verified per organisation. No anchor is exported, so a database owner can rewrite the chain and recompute it.
- Attack scenario: an insider with database write access alters an entry and rebuilds the chain.
- Impact: tamper evidence is weaker than it appears.
- Recommended correction: periodically export the head hash to an append-only sink, sign checkpoints, and document the trust boundary.
- Required regression tests: tampering detected without a new anchor; verify passes after a legitimate append; checkpoint export recorded.
- Status: **PARTIALLY IMPLEMENTED**.

#### SF-DB-02: Migrations are forward-only

- Category: reliability / database
- Severity: Medium
- Affected: `backend/src/db.js`, `backend/src/migrations/*.sql`
- Evidence: schema upgrades are applied by `PRAGMA user_version`, with no down migration or pre-migration backup gate. Rollback guidance is "restore a backup".
- Attack scenario: a failed deploy leaves a partially migrated schema and the previous image cannot start.
- Impact: extended outage during a bad release.
- Recommended correction: take an automatic pre-migration backup, test upgrades on a copy, document per-version rollback or forward-fix steps.
- Required regression tests: upgrade from each prior schema on a copy; failed migration rolls back cleanly; backup created before migration.
- Status: **PARTIALLY IMPLEMENTED**.

### Low

| ID | Finding | Evidence | Correction | Status |
| --- | --- | --- | --- | --- |
| SF-API-01 | Global JSON body limit is 8 MB | `express.json({ limit: '8mb' })` in `index.js`; evidence uses a 5 MB decoded cap | Lower the global limit, keep a larger limit only on the evidence route | IMPLEMENTED (accepted risk) |
| SF-API-02 | CSP allows inline styles | `Content-Security-Policy` in `index.js`: `style-src 'self' 'unsafe-inline'` | Move to hashed or nonce styles when the design system allows | ACCEPTED |
| SF-LOG-01 | Full error objects are logged | `errorHandler` calls `console.error(..., err)`; no redaction layer | Log a structured error with code and request id; keep stack in a protected sink | PARTIALLY IMPLEMENTED |
| SF-KEY-01 | API key rotation is manual | `backend/src/services/websiteKeys.js`: create, revoke, no scheduled rotation | Add overlap window and expiry defaults | PARTIALLY IMPLEMENTED |
| SF-MON-01 | Detection thresholds are fixed constants | `backend/src/services/websiteRules.js` | Move thresholds into a per-organisation policy record | PARTIALLY IMPLEMENTED |
| SF-SEC-01 | Secret scan is a narrow regex set | `scripts/check-secrets.mjs` | Add entropy scanning and a pre-commit hook | PARTIALLY IMPLEMENTED |

### Blocked and unverified

| ID | Area | Status | Reason |
| --- | --- | --- | --- |
| SF-TRI-01 | Live nftables, Cloudflare, Suricata, Wazuh, ClamAV enforcement | BLOCKED / UNVERIFIED | No Linux host, nft binary, provider token, manager, sensor or daemon on this machine. Code contracts are tested with injected transports. |
| SF-DB-03 | Database audit log monitoring | MISSING | Requires a database audit export or log shipper. The website SDK carries application-emitted metadata only, and the product says so. |
| SF-AI-01 | AI-assisted analysis | MISSING | No model provider is configured; nothing in the product is labelled AI analysis. |

## 3. Working protections (verified)

| Control | Evidence |
| --- | --- |
| Password hashing | scrypt, unique 16-byte salt, 64-byte key, `timingSafeEqual`; hashes never returned by `publicUser` |
| Login throttling | 12 per 15 minutes per IP plus 10 account failures per 15 minutes; dummy hash equalises timing |
| MFA | TOTP, hashed single-use recovery codes, five-attempt challenge cap, step-up with password plus code |
| Session storage | Random 32-byte token, SHA-256 stored, HttpOnly cookie, ten-session cap, rotation on password change |
| CSRF | SameSite=Lax, Origin check, double-submit token bound to the session hash |
| Headers | `nosniff`, `DENY` framing, Referrer-Policy, Permissions-Policy, COOP/CORP, HSTS behind HTTPS, CSP on the SPA |
| Input validation | Zod schemas on API bodies, strict website event allowlist, forbidden-key rejection, size and type checks |
| SQL injection | Parameterised statements throughout; dynamic SQL only for constant fragments and whitelisted columns |
| Tenant isolation | `org_id` from the session, 404 for foreign records, cross-tenant tests in `isolation.test.mjs` and TriShield suites |
| API keys | Scoped, SHA-256 hashed, prefix + secret, expiry, revocation audited, last-used tracking |
| Uploads | 5 MB cap, MIME allowlist, magic-byte verification, random names outside the web root, ClamAV when configured |
| SSRF | URL parser based host checks, private and reserved address refusal, tests in `security.test.mjs` |
| Audit | Hash chain with verify endpoint; chain break reports the row |
| Dependencies | `npm audit --omit=dev`: 0 vulnerabilities in backend and frontend |
| Secret scan | `npm run scan:secrets` clean |

## 4. Test and build evidence

| Check | Command | Result |
| --- | --- | --- |
| Backend | `npm test` | 169 tests, 167 passed, 2 skipped, 0 failed |
| Frontend | `npx playwright test` (frontend) | 81 passed |
| Types | `npm run typecheck` | clean |
| Build | `npm run build` | success |
| Secret scan | `npm run scan:secrets` | clean |
| Dependency audit | `npm audit --omit=dev` (both packages) | 0 vulnerabilities |

The two skipped backend tests require PostgreSQL and Redis services that are not
installed on this machine; CI runs the Redis case against a real server.

## 5. What is simulated or not real

- Response automation actions are recorded simulations, labelled in the interface.
- Threat simulation runs are synthetic and labelled.
- No live firewall, WAF, IDS, endpoint, malware scanner or database audit source
  is connected here. TriShield reports `NOT CONFIGURED`, `UNAVAILABLE` or
  `BLOCKED` rather than claiming protection.

## 6. Audit limitations

- This was a code and test review, not a penetration test.
- No production deployment, TLS terminator, backup storage or secret manager was
  available to inspect.
- Dynamic behaviour under load and hostile concurrency was not tested beyond the
  existing suite.
- Findings reflect commit `b0aeb52`; later changes require a delta review.
