# TriShield architecture

TriShield is one Express application, one React application and one SQLite
database. It is not a set of separate services. The three defensive layers share
the existing event, incident, asset, audit and approval machinery.

```
                       SecureFlow AI (Express + React + SQLite)

  Layer 1: perimeter and network          Layer 2: application               Layer 3: endpoint and data
  ------------------------------          ----------------------             --------------------------
  nftables connector (host)               sessions, CSRF, CSP                Wazuh agent telemetry
  Cloudflare access rules (cloud)         RBAC, tenant scope                 ClamAV evidence state
  Suricata EVE collector (IDS)            MFA, step-up, rate limits          YARA rule registry (config)
  WAF collector (cloudflare/modsec)       audit hash chain                   Falco runtime feed (config)
  IP allowlist and allow-protection       policy engine                      endpoint asset mapping

                     \                        |                        /
                      \                       v                       /
                       +---- security_events, network_events --------+
                                      |
                                      v
                       deterministic policy evaluation (trishieldPolicy)
                                      |
                     monitor  ---------+---------  auto
                        |                          |
                        v                          v
                   no action                proposal (firewall_actions)
                                                   |
                                    awaiting_approval -> approved -> executing
                                                   |                    |
                                                   |                    v
                                                   |             provider call + verification
                                                   |                    |
                                                   +---------------> succeeded / failed -> rollback
                                                   |
                                              audit_logs (chained)
```

## Layer responsibilities

| Layer | What it proves | What it does not prove |
| --- | --- | --- |
| Perimeter | A provider connector answers, a rule exists in the provider, a rule was verified and can be rolled back. | That all traffic paths are filtered. nftables covers the host input chain only. Cloudflare covers account access rules only. |
| Application | The running API authenticates, authorises, scopes by tenant and records audited changes. | That every deployment hardening step is complete. TLS termination, secret storage and backup restore are deployment duties. |
| Endpoint | Agents that reported are listed with staleness; evidence scans record a state. | That an endpoint without an agent is protected. No agent means NOT CONFIGURED. |

## Data flow for one blocked source

1. A collector posts Suricata EVE JSON to `/api/trishield/ingest/suricata` with
   its bearer token. The organisation comes from the token row, never the body.
2. `trishieldIngest` validates, normalises into `security_events`, drops
   duplicates by `dedupe_key`, and upserts the collector heartbeat.
3. `trishieldPolicy.evaluateEventForBlock` reads
   `trishield_policies.firewall.auto_block`. It refuses anything that is not a
   public, unprotected address, and it never creates a permanent rule.
4. In `approval` mode it writes a `firewall_actions` row. In `auto` mode it still
   stops unless `TRISHIELD_AUTO_APPLY=true` **and** `TRISHIELD_FIREWALL_APPLY=true`.
5. An administrator approves. `executeAction` re-checks status, expiry and
   provider availability, calls the connector, then calls `verify` on the same
   connector before writing `succeeded` and an active `firewall_rules` row.
6. Every transition writes an `audit_logs` entry through the existing chain.

## Database additions (schema v6)

Eight tables are added. Existing tables are reused rather than duplicated.

| Table | Purpose | Tenant scoped |
| --- | --- | --- |
| `infra_addresses` | Real infrastructure addresses, scope, interface, management flag. | `org_id` |
| `ip_vault` | AES-256-GCM sealed original address, key version, nonce, tag. | `org_id` |
| `trishield_allowlist` | Addresses that must never be blocked. | `org_id` |
| `firewall_rules` | Verified rules per provider, with state and expiry. | `org_id` |
| `firewall_actions` | Full lifecycle of a requested change, approval and verification. | `org_id` |
| `trishield_policies` | Deterministic response policy and its configuration. | `org_id` |
| `endpoint_agents` | Agent identity, host, last heartbeat, asset mapping. | `org_id` |
| `trishield_collectors` | Hashed collector tokens, kind, status, last seen. | `org_id` |

Reused: `security_events`, `network_events`, `assets`, `integration_configs`,
`audit_logs`, `forensic_evidence`, `users`, `sessions`, `login_attempts`.

`firewall_rules` has a partial unique index on
`(org_id, provider_key, cidr, action) WHERE state = 'active'` so a duplicate
active rule cannot be recorded.

## API surface

All routes require a session and are mounted at `/api/trishield`.

| Method | Path | Minimum role | Notes |
| --- | --- | --- | --- |
| GET | `/overview` | viewer | Per layer status, connector health, counts, origin evidence. |
| GET | `/status` | viewer | Firewall and collector health. |
| GET | `/integrations` | viewer | Integration configuration summary. |
| GET | `/firewall/status` | viewer | Provider status, apply flag, active rule count. |
| GET | `/firewall/rules` | viewer | Recorded rules and their state. |
| POST | `/firewall/health` | admin | Runs a real health check and records the result. |
| GET | `/firewall/allowlist` | viewer | Allowlisted addresses. |
| POST | `/firewall/allowlist` | admin | Adds an address, refuses invalid input. |
| DELETE | `/firewall/allowlist/:id` | admin | Removes an entry. |
| GET | `/actions` | viewer | Approval queue with status filter. |
| POST | `/actions` | analyst | Proposes a block or unblock. Rate limited, fail closed. |
| POST | `/actions/:id/approve` | admin | Only from `awaiting_approval`. |
| POST | `/actions/:id/reject` | admin | Terminal. |
| POST | `/actions/:id/execute` | admin | Requires `approved`; permanent needs recent auth. |
| POST | `/actions/:id/rollback` | admin | Only a successful block can be rolled back. |
| GET | `/network/events` | viewer | Suricata events, paginated. |
| GET | `/waf/events` | viewer | WAF events, paginated. |
| GET | `/endpoints` | viewer | Agents, collectors, ClamAV state, recent evidence scans. |
| GET | `/ip/addresses` | viewer | Masked addresses plus origin evidence. |
| POST | `/ip/discover` | admin | Reads local interfaces, optional HTTPS public IP. |
| POST | `/ip/:id/reveal` | admin | Requires a reason, writes an audit entry, rate limited. |
| GET | `/ip/allowlist` | viewer | Protected address list. |
| GET | `/policies` | viewer | Response policies. |
| PATCH | `/policies/:id` | admin | Enable, mode, config. |
| GET | `/collectors` | admin | Collector list, never the token. |
| POST | `/collectors` | admin | Token returned exactly once. |
| DELETE | `/collectors/:id` | admin | Revokes the token. |

Ingestion routes are mounted before the session and CSRF middleware because a
collector has no cookie session:

| Method | Path | Authentication |
| --- | --- | --- |
| POST | `/api/trishield/ingest/suricata` | `Authorization: Bearer tsk_...` |
| POST | `/api/trishield/ingest/wazuh` | Same, kind must match |
| POST | `/api/trishield/ingest/waf` | Same, kind must match |

A token of the wrong kind is rejected with 403. A missing, unknown or revoked
token is rejected with 401.

## Response lifecycle

```
PROPOSED -> AWAITING_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING -> SUCCEEDED
                  |                             |             |
                  +-> REJECTED                  +-> FAILED    +-> FAILED (rollback available)
                  +-> EXPIRED                                +-> ROLLED_BACK
```

`executeAction` is idempotent for an action that already succeeded. A second
proposal for the same live target returns the open action with
`duplicate: true` instead of queueing another approval.

## Frontend

`frontend/src/pages/TriShield.tsx` is lazy loaded from `App.tsx` and appears in
the sidebar as `TriShield defense`. Five tabs: Overview, Perimeter, Endpoints,
IP Shield, Approvals. Data comes only from the API above. There are no hardcoded
metrics, and each provider carries its own badge so one healthy component cannot
hide a failed one. Administrator controls are hidden from viewers and the
backend rejects them regardless.

## What is deliberately absent

- No packet capture and no payload storage. Suricata metadata only.
- No inline IPS toggle. Passive IDS and inline IPS are different deployments and
  the UI never claims blocking from an IDS feed.
- No host firewall chain for forwarded traffic. Only the input hook is
  provisioned, which is documented in INTEGRATIONS.md.
- No AI execution path. AI output is advisory text in the existing detection
  centre; it cannot call a connector.
