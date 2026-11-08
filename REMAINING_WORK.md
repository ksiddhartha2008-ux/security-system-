# Remaining work

Ordered by what a production team would need first. Each item states an acceptance test so it is not a vague wish list.

## P1 - before handling real data

1. **Password reset and account lifecycle.** Currently an admin creates passwords manually. Add a signed single use reset token, an SMTP configuration, and account deletion that removes owned evidence files.
   *Acceptance:* a user can request a reset, receive it through a configured transport, set a new password, and all old sessions are invalidated.

2. **Shared rate limiting.** Move limits to Redis or the reverse proxy so they survive restarts and apply across instances.
   *Acceptance:* limits hold with two API processes behind a load balancer.

3. **Real collectors.** Wazuh, Sysmon, Suricata, Zeek, ClamAV and YARA currently have status surfaces and ingestion endpoints only. Build one collector properly (Wazuh first, because its API is documented) before claiming integration.
   *Acceptance:* the integration screen shows a real last sync time, a count of ingested events, and a clear error when the upstream is unreachable.

4. **Response actions.** Wire the automation engine to one real provider (an EDR isolation API or a firewall block API) behind a feature flag, with a dry run mode.
   *Acceptance:* a test environment actually isolates a host, the execution log records the provider response id, and the action is reversible.

## P2 - depth and operations

5. **PostgreSQL migration.** Replace the SQLite driver with a pool and move the JSON1 lookups to `jsonb` operators.
   *Acceptance:* the full test suite passes against PostgreSQL in CI.

6. **WebAuthn and SSO.** TOTP is implemented and tested. Add hardware security keys and SAML/OIDC for teams that require them.
   *Acceptance:* a WebAuthn credential can complete login without a TOTP code, and an SSO login maps to a workspace role.

7. **Retention job.** The stored retention value is not enforced. Add a scheduled job that deletes expired events, detections, scans and evidence in batches, with an audit entry per run.
   *Acceptance:* a record older than the retention window is removed; a record inside it is not.

8. **Real-time detection on a stream.** Rules currently run on ingest and on demand. Add a windowed aggregator so sustained patterns (for example slow password spraying) are detected without a manual pass.

9. **Investigation correlation.** Correlation currently uses high severity telemetry and shared assets. Add explicit entity graph edges (indicator to event, account to asset) so an investigation can walk hops.

10. **Search.** Replace `LIKE` filters with FTS5 for events and evidence metadata.
    *Acceptance:* a 100k event dataset returns searches in under 100 ms.

11. **Pagination consistency.** A few tables render all rows when the data set is small. Cap and paginate consistently once collectors land.

## P3 - polish

12. **Playwright suite.** The automated coverage is API level plus recorded manual browser checks. Add a Playwright suite for login, navigation, incident creation and a simulation run, run in CI against the production build.

13. **Accessibility audit.** Manual review covered focus traps, skip link, labels and non-colour severity. Run an automated axe pass on every route and fix what it reports.

14. **Dark and light themes.** The design is dark only. Add a light theme through the existing tokens.

15. **CSV import for assets and vulnerabilities.** Analysts currently add records one at a time.

16. **Report scheduling.** Reports are on demand. Add a scheduled generation with a notification.

17. **Webhook delivery for notifications.** Automation records a notify step but nothing is delivered.

## External blockers from this session

| Item | Blocker | What would unblock it |
| --- | --- | --- |
| MiroFish live run | Python 3.11-3.12 required, LLM key and Zep Cloud key absent | A dedicated Python environment and provider credentials; then verify create, prepare, start, status and report against a real instance |
| API Anything MCP connection | Not installed, and it is deliberately out of the runtime path | A developer machine with the MCP client; keep it read only and never share production credentials |
| VirusTotal and AbuseIPDB enrichment | No API keys | Add keys to the server environment and confirm a lookup returns provider data |
| HSTS and TLS verification | No deployed host | A host you control behind TLS; then enable HSTS and test the redirect |

## Not planned

- Becoming a SIEM replacement. The event model is intentionally small and focused on triage.
- Shipping an ML model in the decision path. If one is added, it must remain advisory and store its features with every detection.
- Storing real credentials for third party services in the database.
