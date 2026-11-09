# Security test matrix

All tests use `node:test` with an isolated server and temporary database per file. Status reflects the run on 9 November 2026: **42 passing, 0 failing**.

| Control | Test file | Test | Status |
| --- | --- | --- | --- |
| Registration, admin bootstrap | auth.test.mjs | registration creates an organization and signs the admin in | PASS |
| Duplicate account handling | auth.test.mjs | duplicate registration is rejected with 409 | PASS |
| Account enumeration | auth.test.mjs | login rejects a wrong password with the same message as an unknown account | PASS |
| Session requirement, logout | auth.test.mjs | session is required for protected routes and logout clears it | PASS |
| Input validation envelope | auth.test.mjs | validation errors return a field level envelope | PASS |
| RBAC viewer vs analyst | auth.test.mjs | viewer cannot write, analyst can | PASS |
| RBAC admin routes | auth.test.mjs | admin only routes reject analysts | PASS |
| CSRF token required | hardening.test.mjs | authenticated mutations require a session bound CSRF token | PASS |
| Origin enforcement | hardening.test.mjs | authenticated mutations require a session bound CSRF token (cross-origin leg) | PASS |
| Missing-Origin no longer bypasses | hardening.test.mjs | valid token without Origin accepted; missing token rejected | PASS |
| Account throttling | hardening.test.mjs | account based login throttling survives IP rotation | PASS |
| MFA enrolment | mfa.test.mjs | MFA enrol, login step-up, recovery code and disable | PASS |
| MFA bypass prevention | mfa.test.mjs | no session before the second factor; wrong code rejected | PASS |
| Recovery code single use | mfa.test.mjs | recovery code works once, reuse rejected | PASS |
| MFA endpoints authorization | mfa.test.mjs | MFA endpoints require a session | PASS |
| Demo account gating | mfa.test.mjs | demo accounts endpoint is gated by demo mode | PASS |
| Cross-tenant read/write/delete | isolation.test.mjs | records from another organization are invisible and immutable | PASS |
| Client-supplied org id ignored | isolation.test.mjs | the organization id in the request body is ignored | PASS |
| CSRF/origin cross-origin write | isolation.test.mjs | cross origin writes are rejected by the origin check | PASS |
| Detection rules and explanations | detection.test.mjs | repeated authentication failures produce explainable detections | PASS |
| Duplicate detection suppression | detection.test.mjs | the same signal is not duplicated on a second rule pass | PASS |
| Detection feedback and promotion | detection.test.mjs | detection feedback and promotion create a linked incident | PASS |
| Rule enable/disable | detection.test.mjs | disabled rules stop producing detections | PASS |
| SSRF private ranges | security.test.mjs | URL scanner refuses loopback, private, link local and reserved targets | PASS |
| SSRF scheme allowlist | security.test.mjs | only http and https schemes are accepted | PASS |
| SSRF embedded credentials | security.test.mjs | URLs with embedded credentials are refused | PASS |
| Scan history tenant scope | security.test.mjs | scan history is scoped to the organization | PASS |
| Simulation scenario catalog | simulation.test.mjs | all five scenarios are exposed with agent rosters | PASS |
| Simulation input validation | simulation.test.mjs | an unknown scenario is rejected | PASS |
| Simulation execution and report | simulation.test.mjs | a run executes rounds, records agents and produces a report | PASS |
| Simulation cancellation | simulation.test.mjs | a running simulation can be cancelled and keeps its status | PASS |
| Simulation state guard | simulation.test.mjs | a second start on a completed run is rejected | PASS |
| MiroFish unconfigured honesty | simulation.test.mjs | MiroFish reports an honest unconfigured state | PASS |
| Incident lifecycle guard | workflow.test.mjs | incident lifecycle enforces allowed transitions | PASS |
| Incident timeline | workflow.test.mjs | incident notes appear in the timeline | PASS |
| Evidence integrity and tamper detection | workflow.test.mjs | evidence is hashed on intake, verified, and tampering is detected | PASS |
| Evidence type allowlist | workflow.test.mjs | unsupported evidence types are refused | PASS |
| Report generation and export | workflow.test.mjs | reports are generated from stored records and export | PASS |
| SOAR approval gate | workflow.test.mjs | workflow approval gate records simulated actions | PASS |
| Audit hash chain | hardening.test.mjs | audit log is hash chained and tampering is detected | PASS |
| SOAR approval cannot be disabled | hardening.test.mjs | destructive workflows cannot disable approval and approvals expire | PASS |
| SOAR idempotency | hardening.test.mjs | workflow idempotency returns the original execution | PASS |
| SOAR emergency pause | hardening.test.mjs | paused automation refuses new runs | PASS |
| Evidence signature validation | hardening.test.mjs | evidence rejects declared types that do not match the file signature | PASS |
| CSV formula injection | hardening.test.mjs | report CSV neutralises formula injection | PASS |
| Production config validation | hardening.test.mjs | production configuration rejects demo mode and insecure origins | PASS |

## Not covered by automated tests

| Area | Reason | Manual or future check |
| --- | --- | --- |
| Cookie `Secure` flag in production | Test server runs outside production | Inspect `Set-Cookie` on a TLS deployment |
| MFA enforcement policy | Not implemented | See SECURITY_PROGRESS |
| Password reset / email verification | No transport | Blocked |
| Live ClamAV scan | No daemon here | Run against a ClamAV container |
| Distributed rate limiting | No Redis | Scale-out test |
| PostgreSQL RLS | SQLite only | Migration project |
| TLS, HSTS, proxy headers | No deployment | Production checklist |
| Audit atomicity under crash | Requires fault injection | Transaction refactor |

## How to reproduce

```powershell
npm test
npm run typecheck --prefix frontend
npm run build --prefix frontend
npm audit --prefix backend
npm audit --prefix frontend
```
