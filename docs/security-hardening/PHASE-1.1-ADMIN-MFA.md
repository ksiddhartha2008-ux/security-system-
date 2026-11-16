# Phase 1.1: administrator MFA enforcement (SF-AUTH-01)

Implemented: 16 November 2026
Finding: SF-AUTH-01, administrator MFA optional
Status: **IMPLEMENTED AND TESTED**
No database migration was required.

## Policy

An administrator without an enrolled second factor cannot perform an
administrator-only mutation. The check runs in the backend on every request; the
frontend banner is guidance, not the control.

| Allowed without MFA | Blocked without MFA |
| --- | --- |
| Sign in, sign out, session refresh | Approve, reject, execute or roll back a response action |
| Read pages and read-only APIs | Create, rotate or revoke website API keys |
| Start and complete MFA enrolment | Create or change users and administrator roles |
| Use analyst and viewer workflows | Change organisation settings and integration configuration |
| | Run firewall health checks, discover or reveal IPs, edit allowlists |
| | Create or revoke collectors, change response policies |
| | Generate or reset demo data, create or verify websites |

The rule is: `requireRole('admin')` on a state-changing method requires
`mfa_enabled = 1` for the signed-in administrator. Routes where an analyst is
also allowed are not administrator-only and keep their existing behaviour.

## Backend

- `backend/src/lib/auth.js`
  - `attachUser` now loads `u.mfa_enabled` into `req.user.mfaEnabled`.
  - `requireRole` refuses an administrator-only mutation with
    `403 ADMIN_MFA_ENROLLMENT_REQUIRED` when the factor is absent.
  - The denial writes `auth.admin_mfa_required` to the audit chain with the
    method and route. An audit write failure is logged and never changes the
    refusal into an allow.
- No new authorization framework. The existing role check, recent-auth check,
  CSRF check and tenant scoping still run in their existing order.
- Existing MFA endpoints are unchanged: setup, enable, disable, recovery codes,
  login challenge, recovery-code login and step-up.

## Frontend

- A banner appears in the app shell for an administrator whose session reports
  `mfaEnabled: false`. It links to `/settings?tab=security`, which now accepts a
  deep link to the existing Security tab.
- Enable MFA already refreshes the auth context, so the banner disappears after
  successful enrolment.
- A blocked action shows the server message: "Enrol multi-factor authentication
  before performing administrator actions."
- No new page, route or navigation item was added.

## Tests

| File | Coverage |
| --- | --- |
| `backend/tests/admin-mfa.test.mjs` | Seven tests: every privileged mutation refused with the machine-readable code; reads and enrolment allowed; wrong code cannot enable; enrolment unlocks the same calls; denial audited and chain verifies; password-only step-up refused once MFA is active; analyst and viewer boundaries unchanged |
| `backend/tests/helpers.mjs` | Test helper signs in through the real MFA challenge and enrols an administrator through the real setup and enable endpoints |
| Existing backend suites | Administrators in fixtures now enrol MFA; demo, website, TriShield, simulation and workflow suites keep their original assertions |
| `frontend/e2e/auth.setup.ts`, `e2e/totp.ts` | The e2e administrator enrols with a real TOTP code; the secret is kept only in the ignored `e2e/.auth` folder |
| `frontend/e2e/journey.spec.ts` | UI sign-in completes the MFA challenge with a generated code |
| `frontend/e2e/trishield-integrations.spec.ts` | An enrolled administrator can still run a real integration check |

Commands run:

```
npm test                      176 tests, 174 pass, 2 skipped, 0 fail
npx playwright test           81 passed
npm run typecheck             clean
npm run build                 success
npm run scan:secrets          clean
npm audit --omit=dev          0 vulnerabilities (backend and frontend)
```

The two skipped backend tests require PostgreSQL and Redis, which are not
installed on this machine; CI runs the Redis case against a real service.

## Remaining limitations

- Read-only administrator APIs remain available before enrolment. This is
  deliberate so the Security tab can be opened to enrol. Sensitive reads such as
  the audit log are therefore readable by an unenrolled administrator session.
- One policy applies to every administrator. There is no per-role or
  per-organisation opt-out, and no "break glass" account.
- Disabling MFA is still allowed for an administrator, but the next privileged
  mutation is blocked until they enrol again. The last administrator cannot lose
  access to read pages or to enrolment.
- Recovery codes are displayed when setup starts, before the first code is
  confirmed. They are stored hashed and are single use. Moving the display to
  after confirmation would be a usability hardening change, not a security gap in
  enforcement.
- OTP replay inside the accepted TOTP window is limited by the standard
  `verifyTotp` window, not by a per-user last-used-step table.
- The audit write for a denial is best effort by design: the request is already
  denied, and a database failure is logged to the process output.
- This does not prove production readiness. No production deployment, external
  identity provider, or independent penetration test is included.
