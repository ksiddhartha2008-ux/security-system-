# TriShield integrations

Every provider below is a real adapter with a defined contract. None is
simulated, and none is labelled ACTIVE until a health check succeeds. Where this
machine cannot reach the provider, the adapter still exists, the failure is
recorded with the provider message, and live verification is BLOCKED.

## Status model

| Displayed | Meaning |
| --- | --- |
| `NOT CONFIGURED` | Required setting or credential absent. |
| `CONFIGURED` | Credentials or platform present, no successful check yet. |
| `ACTIVE` | Health check succeeded and the last recorded status is connected. |
| `ERROR` | Present, but the last check failed. The provider message is shown. |
| `UNAVAILABLE` | This host cannot run the connector. |
| `CONNECTED - NO RECENT EVENTS` | Collector exists and is enabled, but no event arrived in 15 minutes. |
| `DISABLED` | Collector token revoked. |

## Linux nftables

**Contract**: `createNftConnector({ bin, table, applyEnabled, platform, run })`.

**Commands** are an argument vector passed to `execFile`, never a shell string.
The binary path is configuration, not request input.

What provisioning does, in order, and why each step matters:

```
nft add table inet secureflow
nft add set inet secureflow blocked_v4 { type ipv4_addr; flags timeout; }
nft add set inet secureflow blocked_v6 { type ipv6_addr; flags timeout; }
nft add chain inet secureflow input { type filter hook input priority 0; policy accept; }
nft add rule inet secureflow input ip saddr @blocked_v4 drop comment "secureflow-block-v4"
nft add rule inet secureflow input ip6 saddr @blocked_v6 drop comment "secureflow-block-v6"
nft add element inet secureflow blocked_v4 { 203.0.113.7 timeout 3600s }
```

A set without the chain and drop rule blocks nothing. That is why the connector
installs both and why `verify` checks the element **and** the drop rule before it
returns verified. Verification is read only: it never repairs the rule it checks.

`health` reads `nft list table inet secureflow` and reports `unprovisioned` with
the missing tokens when the table exists but the sets or rules do not.

**Failure behaviour**: unavailable platform, missing binary, permission denied,
apply flag off, or a verification that does not confirm the rule all surface as a
failed action with the provider message. Nothing is reported as success on the
strength of an exit code alone.

**Scope limit**: only the `input` hook is provisioned. Traffic forwarded through
the host is not filtered by this connector. A gateway deployment needs a forward
chain, which is not implemented here.

**Configuration**: `SF_NFT_BIN`, `TRISHIELD_FIREWALL_APPLY=true`, a Linux host
with `nft`, and enough privilege to modify nftables. The API process should run in
a dedicated network namespace or with a capability that allows only this table,
not as an unrestricted root shell.

## Cloudflare firewall access rules

**Contract**: `createCloudflareConnector({ token, accountId, fetchImpl, applyEnabled })`.

- Base URL: `https://api.cloudflare.com/client/v4/accounts/<account>/firewall/access_rules/rules`.
- Block: `POST` a rule with mode `block`, notes from the action reason.
- Verify: list rules filtered by address and confirm a `block` mode rule exists.
- Unblock: `DELETE` the stored rule id.
- Timeout: 8 seconds per request.

**Failure behaviour**: a non-2xx response or `success: false` raises with the
Cloudflare error message. The action becomes `failed` and no active rule is
recorded. An invalid token therefore produces an honest failure, which is what
the API test asserts.

**Configuration**: `SF_CLOUDFLARE_API_TOKEN`, `SF_CLOUDFLARE_ACCOUNT_ID`,
`TRISHIELD_FIREWALL_APPLY=true`. The token is read from the environment on each
call and is never returned by any route. `GET /integrations` reports only whether
it is configured.

## Suricata (IDS and IPS)

Collector endpoint: `POST /api/trishield/ingest/suricata` with
`Authorization: Bearer tsk_...`.

Accepted shapes: a single EVE object, an array of objects, or
`{ "records": [...] }`.

Normalisation: `event_type`, `src_ip`, `dest_ip`, `proto`, `dest_port`,
`alert.signature`, `alert.signature_id`, `alert.category`, `alert.severity`
(1 is treated as critical, 2 high, 3 medium, otherwise low), `timestamp`.

Deduplication: a stable key over event type, signature id, source and timestamp.
A duplicate is counted and dropped, never stored twice.

**IDS versus IPS**: an EVE alert feed is passive. It proves detection, never
blocking. Inline prevention requires Suricata deployed in the traffic path with
`-q`/NFQUEUE or AF_PACKET inline mode, which changes availability risk. The
product does not enable it and the UI does not claim it.

**Configuration**: create a collector in the TriShield page, copy the token once,
point `eve.json` at the endpoint. Tokens are stored as SHA-256 hashes.

## Wazuh

Collector endpoint: `POST /api/trishield/ingest/wazuh`.

Accepted shape: `{ agent: { id, name, ip }, rule: { id, level, description }, timestamp, ... }`.
Level 12 and above is critical, 10 high, 7 medium, otherwise low. Each accepted
record upserts an `endpoint_agents` row with `last_seen_at`, so an agent that
stops reporting becomes `stale` after 15 minutes and the page shows that state
instead of a healthy one.

**Failure behaviour**: a payload without an agent id or rule description is
rejected as malformed and counted, not stored.

**Scope limit**: the integration is telemetry ingestion. It does not deploy or
manage Wazuh agents, and it does not claim an endpoint is protected without one.

## WAF (Cloudflare, ModSecurity and compatible)

Collector endpoint: `POST /api/trishield/ingest/waf`.

Accepted shape: `{ provider, category, action, sourceIp, ruleId, target, severity, observedAt }`.
Categories map to a normalised set: `sqli`, `xss`, `path_traversal`, `bot`,
`flood`, `auth_abuse`, `protocol_anomaly`, `suspicious`. An unknown category is
refused rather than guessed.

Severity is derived from the category and action deterministically: a blocked
injection attempt is critical, a challenged bot is low, and so on. A
client-supplied severity is never trusted.

Source: stored as `waf:<provider>`, e.g. `waf:cloudflare`.

## ClamAV, YARA and Falco

| Tool | Status here | What exists |
| --- | --- | --- |
| ClamAV | Adapter in the evidence pipeline, not installed | `CLAMAV_HOST` (host or host:port, default port 3310) drives a minimal INSTREAM client in `backend/src/lib/clamav.js`. An infected file is refused at upload. In production a scanner error fails closed with 503 and nothing is stored. Outside production the evidence is stored with `scan_status = error`, never `clean`. TriShield shows the configured state and the last 20 evidence scan results. |
| YARA | Configuration only (`YARA_RULES_PATH`) | No rule engine is executed in this checkout. No claim is made. |
| Falco | Not implemented | Runtime monitoring needs a Falco deployment and a collector. The layer reports `NOT CONFIGURED`. |

A scanner that is down is not a clean scan. That rule is enforced in the evidence
pipeline, not just displayed.

## Threat intelligence

VirusTotal and AbuseIPDB keys are optional (`VIRUSTOTAL_API_KEY`,
`ABUSEIPDB_API_KEY`). Without a key the lookup stays local and the UI says so. A
reputation score never proves an address is malicious, and no automatic block is
derived from a reputation score alone.

## Adding a provider

1. Write the adapter with `available`, `applyEnabled`, `health`, `list`, `block`,
   `unblock`, `verify`.
2. Register it in `firewallProviders()` with a key, a human name and an honest
   `detail` string.
3. Pass its options through `providerConnector`, and inject `fetch` or a command
   runner so tests never touch the network or the host.
4. Add a unit test with an injected transport and an API test for the role gate.
5. Document the failure mode and the scope limit here before enabling it.
