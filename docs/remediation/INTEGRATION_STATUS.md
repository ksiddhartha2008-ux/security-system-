# Integration status

Every integration is reported as one of REAL, SIMULATED, DISABLED, UNAVAILABLE or ERROR. `REAL` means real provider code exists and credentials are configured. `verified` means a call actually succeeded; a configured but unused provider is not verified.

Measured on 13 November 2026 on a host with no provider keys and no external services.

## 1. Reputation providers

| | VirusTotal | AbuseIPDB |
| --- | --- | --- |
| Provider | virustotal.com API v3 | api.abuseipdb.com v2 |
| Connector | `backend/src/services/reputation.js` | same module |
| Authentication | `x-apikey` header, backend only | `Key` header, backend only |
| Configured here | no | no |
| Status | UNAVAILABLE | UNAVAILABLE |
| Verified | no | no |
| Test performed | stub server: success, 404, 500 retry, bad shape, 403, cache | stub server: success after retry |
| External verification | none, no key | none, no key |
| Real or simulated | real code path, unverified provider | real code path, unverified provider |
| Residual risk | provider response shape can change | abuse score is one signal, not a verdict |

The Settings page shows the provider status and the reason. With no key, lookups stay local and say so.

To verify with credentials: set `VIRUSTOTAL_API_KEY` and call `POST /api/threat-intel/lookup`, then `GET /api/settings/integrations`. A successful call flips the record to REAL with `verified: true`.

## 2. Malware scanning

| Field | Value |
| --- | --- |
| Provider | ClamAV daemon, INSTREAM protocol |
| Connector | `backend/src/lib/clamav.js` |
| Authentication | network location only |
| Configured here | no (`CLAMAV_HOST` empty) |
| Status | UNAVAILABLE |
| Verified | no, no daemon available |
| Behaviour | evidence is stored as `not_scanned`; in production a configured but failing scanner returns 503 and the file is not stored |
| Real or simulated | real protocol implementation, unverified daemon |
| Residual risk | a clean scan is not proof of safety |

## 3. Simulation service

| Field | Value |
| --- | --- |
| Provider | MiroFish, separate AGPL service |
| Connector | `backend/src/services/mirofish.js` |
| Configured here | no (`MIROFISH_BASE_URL` empty) |
| Status | UNAVAILABLE |
| Verified | no |
| Behaviour | the native deterministic engine runs alone; results are labelled synthetic |
| Real or simulated | real HTTP adapter, unverified service |

## 4. Event sources

| Source | Status | Detail |
| --- | --- | --- |
| SecureFlow Node SDK | REAL, TESTED | 13 SDK tests, ingestion covered by backend tests |
| Generic HTTP ingestion | REAL, TESTED | `/api/v1/ingest/website-events` with scoped keys |
| Wazuh | DISABLED | catalogue entry only, no connector code |
| Suricata | DISABLED | catalogue entry only; alerts can be posted through the generic event API |
| Zeek | DISABLED | catalogue entry only |
| Sysmon | DISABLED | catalogue entry only |
| YARA | DISABLED | catalogue entry only |

No connector is displayed as connected without a successful call. The Settings page distinguishes configured, connected, error and unconfigured.

## 5. Response actions

| Action | Status | Detail |
| --- | --- | --- |
| Isolate host | SIMULATED | requires approval, recorded as simulated, no endpoint integration |
| Block IP | SIMULATED | same |
| Disable user | SIMULATED | same |
| Notify | SIMULATED | no mail or chat provider configured |
| Force password reset | SIMULATED | same |

The execution log states "No production system was contacted" for these runs. See `SOAR_VERIFICATION_REPORT.md`.

## 6. What would make an integration REAL and verified

1. Credentials or an endpoint that the operator is allowed to use.
2. A staging instance of the external system.
3. One recorded call with its request id and the provider response, stored as evidence.
4. A failure test: wrong key, timeout, and a 5xx, each producing an explicit error rather than a silent success.
5. Status updated only after 3 and 4.

Until then the status stays as shown above.
