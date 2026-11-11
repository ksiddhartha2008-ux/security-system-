# Threat model and test coverage

Abuse cases A1 to A30 from the supplied prompt. "Test" names are in `backend/tests/` or `packages/sdk-node/test/`. A row marked **partial** has a control but no automated test for the exact abuse case, and says why.

| ID | Abuse case | Control | Test / status |
| --- | --- | --- | --- |
| A1 | Claim a domain you do not own | DNS control, random token bound to the site, exact match only | `website-api` verification test; `website-dns` exact match test. Covered. |
| A2 | Reuse another organization's published token | Token is generated per site and challenge, never derived from input. Lookup is by the site pending row | `website-api` create and verify tests. Covered. |
| A3 | Two organizations verify the same hostname at once | Transactional overlap check plus partial unique index; second returns conflict | `website-api` concurrent verification test. Covered. |
| A4 | Claim a public suffix or platform domain | `tldts` with private suffixes; platform denylist from `SF_PLATFORM_DOMAINS` | `website-normalize` public suffix test. Covered. |
| A5 | Claim reserved, internal or IP literal names | Specific error codes for reserved names and IP literals | `website-normalize` reserved and IP tests. Covered. |
| A6 | Homograph or look alike domain | Punycode stored, Unicode shown, mixed script warning | `website-normalize` IDN and Cyrillic tests. Covered. |
| A7 | Make the platform fetch a hostile URL (SSRF) | v1 never requests the entered URL; normalization is pure | `website-normalize` test replaces `fetch` with a throwing stub. Covered. |
| A8 | Abuse verification to flood DNS or the job queue | 6 per hour per site, 30 per day per organization, 10 pending sites, resolver timeout and record caps | `website-api` rate limit and pending cap tests; `website-dns` caps test. Covered. |
| A9 | Stale ownership after a domain transfer | Daily re-verification, failure marker, lapse after grace | `website-scheduler` re-verification test. Covered. |
| A10 | Verification record left on a domain sold to a new owner | Lapse releases the verified hostname and suspends keys; the old owner can no longer ingest | Lapse is tested. A full transfer scenario with a second organization is **partial**: the unique index and status transition are tested, the business handover is not. |
| A11 | Steal a key and inject events | Key scoped to one site, rate limits, revocation, trust level from the key | `website-api` revocation test; `website-sdk` key secrecy tests. Covered. |
| A12 | Key leaks in logs, URLs or error reports | Header only, query keys refused, audits exclude key and token, secret scan | `website-api` query-string test and audit metadata assertion; `npm run scan:secrets`. Covered. |
| A13 | Timing oracle on key lookup | Unknown ids still perform a hash comparison; equal length `timingSafeEqual` | Implementation only. No timing measurement was performed. **Partial.** |
| A14 | Write events into another tenant | Organization and site come from the key; body ids are rejected as unknown fields | `website-api` tenant isolation test. Covered. |
| A15 | Force high severity through spoofed fields | No client severity field; unknown field rejects the event; detection computes severity | `website-api` envelope test; `website-detection` corpus. Covered. |
| A16 | Event flood to exhaust storage, CPU or notifications | 256 KiB, 100 events, 600 per minute per key, 100,000 per day per site, throttled notifications | `website-api` ingestion limit test; `website-detection` notification suppression. Covered. |
| A17 | Stored XSS through event fields | React text rendering, no `dangerouslySetInnerHTML` in the new pages, CSP on the SPA | Hostile path is stored and rendered as text in the walkthrough. No automated browser XSS scan. **Partial.** |
| A18 | Log injection through control characters | Control characters rejected in actor ids and URLs, stripped from user agents and paths | `website-api` control character test; `website-sdk` user agent test. Covered. |
| A19 | CSV or report formula injection | Website export is JSON only, no CSV | **N/A** for this feature. The existing report CSV sanitiser is unchanged. |
| A20 | SQL injection | Parameterized statements only; hostile path stored as data | `website-api` hostile path test; manual review found no string-built SQL with request values. Covered. |
| A21 | Prototype pollution through JSON | Forbidden keys rejected at envelope level, strict event fields | `website-api` polluted envelope test. Covered. |
| A22 | IDOR on sites, keys, events | Every lookup filters by the authenticated organization and returns 404 | `website-api` tenant isolation test covers detail, update, verify, keys, events, detections, incidents and delete. Covered. |
| A23 | Non admin creates or revokes keys | RBAC plus recent authentication plus audit | `website-api` key test. Covered. |
| A24 | Replay of a batch | `(site, event_id)` unique and dedupe key | `website-api` replay and duplicate-in-batch tests. Covered. |
| A25 | Timestamp abuse to hide or fabricate history | Accepted window, server `received_at` stored | `website-api` old timestamp test. Covered. |
| A26 | Host spoofing to attribute events to the wrong site | Host check per scope, rejection counted, health warning after five | `website-api` host mismatch test. Covered. |
| A27 | CSRF against the ingestion route | Route mounted before cookies, API key only | `website-api` cookie only request test. Covered. |
| A28 | PII over collection by the SDK or server | Denylist on both sides, no bodies or headers | `website-sdk` sanitization test; `website-api` sensitive attribute test. Covered. |
| A29 | DNS spoofing of the verification answer | Optional two resolver corroboration is not implemented; daily re-checks limit the window | `website-dns` error classification and `website-scheduler` behaviour are tested. Spoofing itself is **not mitigated**. Documented residual risk. |
| A30 | Alert storms used to hide a real incident | Correlation into one incident, 15 minute cooldown, priority escalation, hourly cap, suppression reason | `website-detection` one incident and suppression assertions. Covered. |

## Security second pass on the critical controls

Five ways an attacker could still defeat the controls, and what was done.

### Credentials

1. **Replay a key after revocation.** Tested: revocation purges the cache and the next request returns 401 (`website-api` revocation test).
2. **Guess a key id.** Key ids have 60 bits of entropy and an unknown id still performs a constant comparison. No timing measurement was done, so this remains a residual risk.
3. **Use a key against another site.** The site comes from the key row; there is no body field that can change it. Tested by the tenant isolation test.
4. **Read the key from a log or audit row.** Audit metadata stores key id and last four characters only; the test asserts the full key is absent.
5. **Exploit the two key limit under concurrency.** Creation runs inside `BEGIN IMMEDIATE` and re-counts active keys, so two simultaneous creations cannot both pass the limit. This is covered by code review, not by a concurrent HTTP test. A dedicated load test would be needed.

### Verification

1. **Publish someone else's token.** Tokens are random per site and challenge; the check reads the record name derived from the site.
2. **Rely on a substring or case variant.** The comparison is exact after trimming.
3. **Race two organizations.** Tested: one 200, one 409, one verified row.
4. **Keep a stale claim after the domain changes hands.** Daily re-check and lapse are tested; the handover itself is not.
5. **Use a DNS outage to force a lapse.** Resolver errors do not set the failure marker; tested in the scheduler suite.

### Ingestion

1. **Send cookies instead of a key.** Rejected with 401; tested.
2. **Send a key in the query string.** Rejected; tested.
3. **Send a huge body.** 413 before parsing; tested.
4. **Pollute the prototype.** Envelope rejected; tested.
5. **Spoof severity or organization.** Both fields do not exist; unknown fields reject the event.

### Tenant isolation

1. **Guess an id.** Scoped query returns 404 for every endpoint; tested.
2. **List another organization's sites.** Empty list; tested.
3. **Verify another organization's site.** 404; tested.
4. **Revoke another organization's key.** 404; tested.
5. **Read another organization's events or incidents.** 404; tested.

## Not covered by an automated test

- Timing side channels on key lookup.
- Browser XSS and accessibility scans. The pages render hostile values as text and were read manually at 424 px width.
- Multi-host rate limiting and scheduler coordination.
- DNS spoofing and resolver compromise.
- A real customer domain, real DNS propagation and a real mail or webhook channel.
