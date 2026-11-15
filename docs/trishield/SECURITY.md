# TriShield security model

## Threat model

| Asset | Adversary | Entry point | Control | Residual risk |
| --- | --- | --- | --- | --- |
| Firewall rules | Malicious insider, stolen admin session | `/api/trishield/actions*` | Admin role, approval state, expiry, recent auth for permanent changes, rate limit, audit chain | A compromised admin session can still approve. Step-up only covers permanent changes. |
| Collector ingestion | External attacker, buggy agent | `/api/trishield/ingest/:kind` | Per-collector bearer token hashed at rest, kind binding, 600/min limit, payload validation | A leaked token allows event injection for one tenant. Revoke and recreate. |
| Original infrastructure addresses | Curious insider, log reader | `/api/trishield/ip/*`, discovery | Masked by default, AES-256-GCM vault, admin-only reveal with reason, rate limit, audit | Values are visible to administrators and to anyone reading the browser after a reveal. |
| Container of truth (SQLite file) | Host compromise | Filesystem | Application-level auth, audit chain with verification | A host-level attacker reads the whole database. Full disk encryption is a deployment control. |
| Firewall host itself | Misconfigured policy | nftables connector | Protected-address refusal, management interface refusal, allowlist, explicit apply flag, verification | The connector runs with the privileges of the API process. Use a dedicated namespace and do not run the API as unrestricted root. |
| Audit trail | Privileged insider | Database write | Hash chain plus verification endpoint | A database owner can rewrite the chain and re-hash. The chain is tamper evident, not tamper proof. Append-only storage or an external log sink is required for that. |

## Controls in this layer

| Control | Implementation | Test |
| --- | --- | --- |
| Authentication | Existing session, scrypt hashes, MFA, step-up | Existing suite, unchanged |
| Authorisation | `requireRole` on every mutating route, viewer read only | `trishield-api.test.mjs` role matrix |
| Tenant isolation | Every query filters `org_id` from the session, never the body | Cross tenant action, allowlist and event tests |
| CSRF | Existing double-submit token, ingestion routes outside it and token authenticated | Existing suite |
| Rate limits | Action proposal 10/min, reveal 10/min, ingestion 600/min, all fail closed | Existing limiter tests |
| Input validation | Zod schemas on every body, IP classification before use | Invalid address, private address, short reason, permanent by analyst |
| Idempotency | Idempotency key plus open-action lookup per target | Duplicate proposal test |
| Verification | Provider read back before `succeeded` | Fake provider and failure path |
| Audit | Chained audit entries for propose, approve, reject, execute, rollback, reveal, policy change, collector change | Existing audit chain tests |
| Secret handling | Tokens hashed, Cloudflare token environment only, vault keys environment only | No secret returned by any route |

## OWASP ASVS 5.0 mapping

| ASVS area | TriShield response | Status |
| --- | --- | --- |
| V2 Authentication | Reuses the hardened session, MFA and recent-auth checks. No new authentication path was introduced. | IMPLEMENTED, TESTED (existing suite) |
| V3 Session management | No new cookie or token surface. Collector tokens are bearer credentials, hashed at rest, separate from sessions. | IMPLEMENTED, TESTED |
| V4 Access control | Server side `requireRole`, tenant scoping in every statement, 404 for unknown or foreign resources. | IMPLEMENTED, TESTED |
| V5 Input validation | Zod on all bodies, IP parsed and classified, unknown WAF category refused, records validated per provider. | IMPLEMENTED, TESTED |
| V6 Cryptography | HMAC-SHA-256 keyed fingerprints, AES-256-GCM vault with per-record nonce and tag, key versioning. | IMPLEMENTED, TESTED |
| V7 Error handling and logging | Provider errors truncated and stored, no stack traces to clients, no secrets in logs, request id returned. | IMPLEMENTED |
| V8 Data protection | Masked by default, vault segregated from data, reveal audited. Full disk encryption is a deployment control and is not provided here. | PARTIALLY IMPLEMENTED |
| V9 Communication | TLS termination is a deployment responsibility. `SF_ALLOW_ORIGIN` must be HTTPS in production. | DEPLOYMENT |
| V10 Malicious code | No upload path in TriShield. Evidence scanning is covered by the existing ClamAV pipeline. | EXISTING |
| V11 Business logic | Approval lifecycle, expiry, duplicate prevention, no automatic permanent rule. | IMPLEMENTED, TESTED |
| V12 Files and resources | No file upload in TriShield. Evidence limits remain in the existing route. | EXISTING |
| V13 API and web service | Versioned JSON contract, role checks, pagination limits, 409 on provider refusal. | IMPLEMENTED, TESTED |
| V14 Configuration | Production config check errors on live firewall without an IP key, refuses non-HTTPS public IP discovery. | IMPLEMENTED, TESTED by inspection |

## NIST SP 800-207 Zero Trust mapping

| Tenet | How TriShield follows it | Limit |
| --- | --- | --- |
| All data sources are resources | Addresses, agents, providers and rules are all tenant scoped records. | A provider account can span tenants in reality; SecureFlow models one organisation per credential set. |
| All communication is secured | Collector traffic is token authenticated and must be HTTPS at the proxy. | The app does not terminate TLS itself. |
| Per request access decision | Every route re-checks the session, role, tenant and resource state on each call. | No continuous device posture signal. |
| Policy is dynamic and computed | Risk class comes from the action (temporary versus permanent), not from the caller. | Risk scoring for incidents is unchanged and deterministic. |
| Monitor and measure integrity | Health checks record status and time, actions record verification, audit chain verifies. | No independent attestation of the host. |
| Enforce least privilege | Admin only for approval, execution, reveal, health, policy, collectors. Analysts may propose. | Two-person approval is not implemented. |

## Prompt injection and AI boundaries

TriShield does not give AI a tool path. There is no code where a model response
can call a connector, approve an action or modify a rule. Event text, WAF
payloads, filenames and threat intelligence are treated as untrusted data
wherever they are displayed, and no field is rendered with
`dangerouslySetInnerHTML`.

If a future change adds an AI recommendation for a firewall action, it must land
as a proposal with `requested_by` naming the human, and it must pass the same
policy and approval checks. Recommend-only is the safe default.

## Known gaps

| Gap | Risk | Mitigation |
| --- | --- | --- |
| Two-person approval | A single compromised admin can approve and execute | Keep the admin group small; review the audit chain |
| No live firewall evidence in this environment | Enforcement is unproven here | Run `scripts/trishield-firewall-check.mjs` on a disposable Linux host |
| Inline IPS not implemented | Blocking from an IDS feed is impossible by design | Documented; the UI never claims IPS |
| No forward chain | Gateway traffic is not filtered | Documented scope limit |
| No automatic key rotation | Long lived keys | Documented rotation procedure |
| Audit chain is database local | A database owner can rewrite history | Ship audit logs to an append-only sink in production |
| No penetration test | Unknown exploitable issues | Schedule independent testing before production |
