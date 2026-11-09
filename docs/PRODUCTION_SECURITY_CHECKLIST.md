# Production security checklist

No production deployment was performed. This is the gate to pass before one.

## 1. Build and configuration

- [ ] `NODE_ENV=production`
- [ ] `SF_DEMO_MODE` unset (production refuses to start with it on unless `SF_ALLOW_INSECURE_DEMO=true`, which is only for a throwaway demo host)
- [ ] `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD` set for the first start; password at least 12 characters and unique
- [ ] First admin signs in, enables TOTP MFA, stores recovery codes offline
- [ ] Demo workspace, if present, deleted before real data
- [ ] `SF_TRUST_PROXY=true` only behind a trusted proxy that overwrites `X-Forwarded-For`
- [ ] `SF_ALLOW_ORIGIN` unset, or an exact `https://` origin
- [ ] Data directory on a persistent volume with restrictive filesystem permissions
- [ ] `backend/data` and `.env` excluded from version control (they are in `.gitignore`)

## 2. TLS and transport

- [ ] HTTPS terminates at a reverse proxy with a valid certificate
- [ ] HTTP redirects to HTTPS
- [ ] `Strict-Transport-Security` set at the proxy after HTTPS is confirmed on every hostname
- [ ] HSTS preload **not** enabled without the owner's explicit decision
- [ ] Proxy forwards `Host` unchanged (the origin check depends on it)
- [ ] Proxy disables buffering for `/api/stream` (SSE)

## 3. Authentication and sessions

- [ ] Cookies carry `Secure` in production (the app adds it automatically when `NODE_ENV=production`)
- [ ] `sf_session` is HttpOnly, `sf_csrf` is readable by design, `sf_mfa` is Strict
- [ ] MFA enabled for every administrator (manual today; policy enforcement is on the backlog)
- [ ] Password change revokes all sessions (implemented)
- [ ] Login throttling confirmed: 10 failures per account per 15 minutes, plus per-IP limits
- [ ] No shared admin accounts

## 4. Authorization and tenancy

- [ ] Confirm every user belongs to the intended organization
- [ ] Roles reviewed: admin least privilege, analysts for operations, viewers for reporting
- [ ] Cross-tenant test run against the deployed database if seeded from an import
- [ ] Reports and evidence exports restricted to the intended roles

## 5. Evidence handling

- [ ] `CLAMAV_HOST` configured and reachable; a test upload reports `scan_status=clean`
- [ ] If the scanner is configured and unavailable, uploads fail closed (503) in production
- [ ] Evidence directory is not inside a web root
- [ ] Backup includes the database and evidence files together
- [ ] SHA-256 verification of a sample artefact from the UI

## 6. Audit

- [ ] `GET /api/settings/audit-logs/verify` returns `ok: true`
- [ ] Audit log export/retention agreed; external log shipping considered
- [ ] Critical operations produce an audit row with a request id
- [ ] Known limitation: audit atomicity is partial; the chain detects tampering, not a crash between business write and audit write

## 7. Automation

- [ ] Every destructive workflow requires approval (enforced regardless of config)
- [ ] Approval window understood (30 minutes)
- [ ] Workspace pause tested (Settings `automationPaused`)
- [ ] No real EDR/firewall/identity integration is configured unless it has been tested against a non-production target
- [ ] Execution logs reviewed and understood as **simulated** where no integration exists

## 8. Integrations and secrets

- [ ] Provider keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) only in the server environment
- [ ] `MIROFISH_BASE_URL` points to a private address; MiroFish UI is not publicly exposed
- [ ] API Anything is not installed on the production host
- [ ] Secrets not present in the browser bundle (search the build output)
- [ ] Rotation plan for every key

## 9. Data protection and resilience

- [ ] Database backup schedule and restore test
- [ ] Evidence backup and restore test
- [ ] Disk space alerting (evidence grows; 5 MB per file limit)
- [ ] Log retention and access control
- [ ] Incident response contact and rollback procedure

## 10. Verification commands

```powershell
npm test
npm run typecheck --prefix frontend
npm run build --prefix frontend
npm audit --prefix backend
npm audit --prefix frontend

# production start (expected to refuse without bootstrap)
$env:NODE_ENV='production'; node backend/src/index.js

# health and audit chain (replace host/cookie)
curl.exe -s https://your-host/api/health
```

## 11. Known blockers before a real production claim

| Blocker | Impact | Needed |
| --- | --- | --- |
| No password reset / email verification | Users cannot self-recover; no address verification | SMTP provider and token flow |
| MFA policy not enforced | An admin can remain password-only | Enrolment-required session state and UI |
| No shared rate limiting | Limits reset on restart, per instance only | Redis or proxy-level limits |
| No PostgreSQL RLS | Isolation relies on application filters | Migration project |
| Collectors not implemented | No automatic telemetry from Wazuh/Sysmon/Suricata/Zeek | Collector services |
| ClamAV not verified live | Malware scanning unproven | ClamAV daemon in staging |
| Audit atomicity partial | Rare crash window without audit row | Transaction refactor per critical route |
