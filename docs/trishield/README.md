# TriShield: implemented code versus verified protection

SecureFlow TriShield is one application with three defensive layers. A layer is
only labelled ACTIVE after a real connector answers a real health check. The
table below is the authoritative status for this checkout.

Status vocabulary used everywhere in this folder:

| Label | Meaning |
| --- | --- |
| IMPLEMENTED | Code exists and is wired into the running application. |
| TESTED | Exercised by an automated test or a recorded manual run. |
| CONFIGURED | Credentials or a socket are present, but no successful provider exchange has happened yet. |
| ACTIVE | A real health check succeeded and, where applicable, a verified change is recorded. |
| SIMULATED | Deliberately fabricated data or a fake executor. Always labelled. |
| BLOCKED | Correct code exists, but the environment cannot verify it. |
| UNVERIFIED | No evidence either way. |
| NOT CONFIGURED | The integration is absent. |

## What this checkout proves

| Area | Status | Evidence |
| --- | --- | --- |
| Database schema v7 (8 TriShield tables plus health history) | TESTED | `backend/tests/trishield.test.mjs` applies v1 to v7 on a fresh database. |
| Integration health engine | TESTED | `backend/tests/trishield-health.test.mjs` covers every state transition and the read model. |
| Health API and role gate | TESTED | `backend/tests/trishield-health-api.test.mjs`: viewer read, admin check, audit entry. |
| Integration Setup Center | TESTED | `frontend/e2e/trishield-integrations.spec.ts` checks six cards, setup steps and a real check. |
| IP classification, masking, keyed fingerprint | TESTED | Unit tests cover IPv4, IPv6, private, loopback, link local, reserved and public ranges. |
| AES-256-GCM address vault | TESTED | Round trip plus tamper rejection in the unit test. |
| nftables connector command construction | TESTED | A stateful emulator asserts table, set, base chain, drop rule, element, timeout and delete. |
| nftables health states | TESTED | UNAVAILABLE off Linux, DEGRADED when unprovisioned or apply is off, VERIFIED after a real check. |
| nftables enforcement on a real kernel | BLOCKED | No Linux host, WSL distribution, container runtime or `nft` binary on this machine. Runner: `scripts/trishield-firewall-check.mjs`. |
| Cloudflare firewall connector | IMPLEMENTED, TESTED with a fake fetch | Create, list, verify and delete against an injected `fetch`. No live account token exists here. |
| Approval gate, idempotency, expiry, rollback | TESTED | Service tests with a fake provider and API tests with the real HTTP route. |
| Deterministic auto-block policy | TESTED | Default disabled, approval mode, and auto mode still stops when `TRISHIELD_AUTO_APPLY` is off. Synthetic events are skipped. |
| Suricata EVE, Wazuh and WAF normalization | TESTED | Parsers, dedupe and tenant scoping covered. |
| Suricata EVE tailer | TESTED | `backend/tests/trishield-eve-tail.test.mjs` sends real records, skips malformed lines and never replays after restart. |
| Wazuh manager API client | TESTED with an injected fetch | Authenticates, reads manager info, lists agents, reports ERROR with the HTTP status. |
| ClamAV VERSION check | TESTED | Parser plus scanner-down path; a missing scanner is ERROR or NOT CONFIGURED, never clean. |
| Collector token authentication | TESTED | Bearer token, wrong kind, revoked token, missing token and cross tenant isolation. |
| Live Suricata, Wazuh, ClamAV, YARA, Falco feeds | BLOCKED | No collector, daemon or endpoint agent is installed here. |
| TriShield user interface | TESTED | Lazy route, real API data, six tabs, empty and error states, administrator gating, a11y in both themes. |
| Production readiness | NOT CLAIMED | No staging or production deployment, no penetration test, no live firewall run. |

## Rules this implementation obeys

1. No fake address is ever stored or displayed as an infrastructure address.
   Discovery reads `os.networkInterfaces`, or an explicitly configured HTTPS
   public IP endpoint whose answer is recorded as an unverified origin.
2. A configured integration is not VERIFIED. Only a successful real check sets
   VERIFIED, and a failed check records ERROR with the provider message. The
   states are NOT CONFIGURED, CONFIGURED, CONNECTED, VERIFIED, DEGRADED, ERROR
   and UNAVAILABLE.
3. An action that is not approved cannot execute, and an execution that the
   provider did not confirm is reported as failed, never as succeeded.
4. Blocking refuses private, loopback, link local, multicast, reserved,
   allowlisted, management and SecureFlow own addresses.
5. Nothing high impact runs from a page load. The backend re-checks the role,
   the approval state, the expiry and, for a permanent change, recent
   authentication.

## Where to go next

- [ARCHITECTURE.md](ARCHITECTURE.md): layers, data flow, tables, API surface.
- [IP_SHIELD.md](IP_SHIELD.md): masking, fingerprints, vault, reveal, origin.
- [INTEGRATIONS.md](INTEGRATIONS.md): each provider, its configuration and its
  failure behaviour.
- [SECURITY.md](SECURITY.md): threat model, ASVS 5.0 and NIST 800-207 mapping,
  known limits.
- [OPERATIONS.md](OPERATIONS.md): isolated verification, key rotation,
  troubleshooting, rollback.
- [TEST_EVIDENCE.md](TEST_EVIDENCE.md): exact commands and results.
