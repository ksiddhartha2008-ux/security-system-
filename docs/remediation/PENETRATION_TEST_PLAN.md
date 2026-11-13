# Penetration test plan

Purpose: give an independent tester a reproducible scope. This is a plan, not evidence of a test. Automated checks in this repository are not a penetration test.

## 1. Target and build

- Commit under test: record `git rev-parse HEAD`.
- Staging URL over HTTPS with a TLS terminator, `SF_TRUST_PROXY=true`, demo data only.
- Two organizations, one admin, one analyst, one viewer each, so cross tenant cases have a counterpart.
- Redis enabled so shared limits are exercised.
- Website protection enabled with a test hostname and the DNS fixture resolver.
- No production credentials, no real customer data.

## 2. Rules of engagement

- Testing window agreed in writing.
- No denial of service beyond 10 requests per second against any endpoint.
- No destructive action against shared infrastructure.
- Findings reported with request and response evidence, excluding secrets.
- Stop and report immediately if real personal data is encountered.

## 3. Scope

In scope:

- `/api/auth/*` including MFA, step-up, password change, registration.
- Every `/api` resource route, including website protection and ingestion.
- `/api/v1/ingest/website-events` with API key authentication.
- The SPA at `/`, `/login`, and all authenticated routes.
- File upload through `/api/forensics`.
- The phishing scanner's SSRF controls.
- Workflow approval and any response action.
- Docker and compose configuration, environment handling, health endpoints.

Out of scope:

- Third party providers (VirusTotal, AbuseIPDB) and their infrastructure.
- MiroFish, ClamAV, Wazuh and any external system not deployed for the test.
- Physical access, social engineering, supply chain.

## 4. Test cases

### Authentication

1. Password policy, lockout after repeated failures, lockout keyed by account not only IP.
2. Session fixation: token changes at login; old token invalid.
3. Cookie flags in production: HttpOnly, Secure, SameSite.
4. CSRF: mutation without token, with a token from another session, with a cross origin Origin header.
5. MFA: challenge expiry, replay of a used code, recovery code single use.
6. Step-up: website key creation and data deletion require recent password entry.
7. Logout invalidates the session server side, not only the cookie.
8. Timing comparison for unknown email versus wrong password.

### Authorization and tenancy

9. Every route with a viewer, analyst and admin account; compare with the documented matrix.
10. IDOR: replace every id with another tenant's id; expect 404, never data.
11. Organization id supplied in a body or query is ignored.
12. Role escalation through mass assignment on user update.
13. API key from one site used against another site or another tenant.
14. Revoked key and expired key rejected immediately.

### Injection and output

15. SQL injection in every string field, including path, hostname and search.
16. Stored XSS in event fields, incident notes, investigation findings, website display name.
17. CSV formula injection in report export.
18. Header injection through user agent and forwarded headers.

### SSRF and file handling

19. Phishing scanner against loopback, private ranges, link local, IPv6 mapped, DNS rebinding and redirect chains.
20. Upload with a mismatched extension and magic bytes; oversized file; path traversal in filename; executable content type.
21. Evidence download authorization and hash verification.
22. ClamAV unavailable in production fails closed.

### Rate limiting and abuse

23. Login and MFA limits across two instances behind one load balancer.
24. Spoofed `X-Forwarded-For` with and without trusted proxy.
25. Redis stopped: login fails closed, global API uses the marked local fallback.
26. API key and per user buckets are independent.

### Business logic

27. Incident transition rules, including reopening a closed incident.
28. Workflow approval: analyst cannot self approve a destructive action; approval expires.
29. Report generation with hostile date ranges.
30. Demo reset scope: cannot delete real records or another tenant's data.

### Deployment

31. Security headers and CSP on the SPA and API.
32. Error responses contain a request id and no stack trace or SQL.
33. Health endpoints expose no tenant data.
34. Container runs as non-root, no secrets in image layers or environment dumps.
35. Backup file permissions and restore procedure.

## 5. Evidence to collect

- Request and response pairs, redacted.
- Server log lines with request id.
- Database state before and after, for authorization cases.
- Browser console and network log for client issues.

## 6. Exit criteria

- Every critical and high finding fixed and retested, or accepted in writing with a compensating control.
- Medium findings fixed or scheduled with an owner.
- A retest report signed by the tester.
- Status updated from NOT VERIFIED to the actual outcome. Until then the application must not claim an independent test.

## 7. Current status

NOT VERIFIED. No independent tester has run this plan. The automated evidence available today is listed in `REGRESSION_TEST_REPORT.md`.
