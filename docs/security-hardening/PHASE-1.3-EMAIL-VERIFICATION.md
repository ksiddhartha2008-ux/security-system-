# Phase 1.3: email ownership verification (SF-AUTH-02)

Implemented: 16 November 2026
Finding: SF-AUTH-02, email ownership is never verified
Status: **IMPLEMENTED, TESTED, live delivery PARTIALLY VERIFIED**

Migration: schema v8, `backend/src/migrations/008_email_verification.sql`.
The database now has 51 tables (50 before, plus `email_verification_tokens`).
The schema version reported at startup is 8.

## 1. Original finding

Registration accepted any syntactically valid address and created an active
administrator. There was no `email_verified` column, no token, no mail path and
no audit event, so a mistyped or borrowed address received security mail for an
account it did not own.

## 2. What was built

### Database (migration v8)

- `users.email_verified` (`INTEGER NOT NULL DEFAULT 0`, checked to 0 or 1) and
  `users.email_verified_at` (`TEXT`).
- `email_verification_tokens`: `id`, `user_id` (cascade delete), `token_hash`
  (unique), `expires_at`, `consumed_at`, `created_at`, plus an index per user and
  one on `expires_at`.
- Only the SHA-256 hash of the token is stored. The raw token exists in the
  outbound message and in the request that consumes it, nowhere else.

**Grandfathering policy.** The migration marks every account that already exists
as verified, with `email_verified_at = created_at`. Those accounts were created
before verification existed, no evidence either way is available, and silently
requiring verification would lock out the operators of an existing deployment
with no mail channel to recover. This is a one-time legacy decision, it is
written into the migration, and every account created after v8 starts
unverified. The same rule is applied to seeded demo accounts
(`backend/src/seed.js`) and to the operator-created bootstrap administrator
(`backend/src/lib/bootstrap.js`), because both are created by the deployment
itself rather than through the public form.

### Token lifecycle (`backend/src/services/emailVerification.js`)

- Token: 32 random bytes, base64url encoded.
- Expiry: 24 hours from issue.
- One active token per account: issuing a new token marks the previous
  unconsumed rows consumed, so an older link stops working.
- Consumption runs inside `BEGIN IMMEDIATE` and then a conditional
  `UPDATE ... WHERE id = ? AND consumed_at IS NULL`. A second consumer of the
  same token loses the race and receives `used`.
- Outcomes: `invalid` (unknown hash), `used` (already consumed or superseded),
  `expired`. Each maps to a `400` with a specific code and a plain sentence.

### Delivery boundary (`backend/src/services/email/`)

- `resend-provider.js` wraps the official `resend` Node SDK. It checks the
  `error` field of the SDK result, applies an 8 second timeout, and returns a
  short reason. The API key and the token never appear in a log line, an audit
  row, an error message or a response.
- `service.js` builds the link as `${APP_BASE_URL}/verify-email?token=...` and
  exposes `available` so a deployment without a provider is visible instead of
  silently pretending to send.
- `templates.js` renders escaped HTML and a plain text alternative with the
  link, the expiry and a "we will never ask for your password" notice.
- `backend/src/routes/auth.js` depends on the service interface, not on Resend,
  so the provider can be replaced without touching the routes.

A provider failure, a timeout, or a missing provider returns `ok: false` and is
audited as `auth.email_verification_failed` with the code. It is never reported
as delivered. In this development environment `RESEND_API_KEY` and `EMAIL_FROM`
are set, so the provider is configured.

### Restricted access while unverified

`backend/src/lib/auth.js` adds `requireVerifiedEmail`, mounted at `/api` after
the CSRF check in `backend/src/index.js`. A signed-in but unverified account can
only reach:

- `/auth/me`, `/auth/logout`, `/auth/sessions`
- `/auth/verify-email`, `/auth/resend-verification`
- `/auth/step-up` and the `/auth/mfa/*` routes

Everything else answers `403 EMAIL_VERIFICATION_REQUIRED`. The gate runs after
authentication, CSRF and organization scoping, so no existing control is
weakened. MFA enrolment stays reachable on purpose: an unverified administrator
can finish enrolment while the mailbox is being resolved, and the Phase 1.1 rule
that admin mutations need an enrolled factor still applies afterwards.

### Routes

- `POST /api/auth/register` still answers the Phase 1.2 neutral `202`. The
  message changed to "If registration can be completed, check your email for the
  next step." because the next step is no longer "sign in". A token is issued
  and one message is sent; the outcome is audited as
  `auth.email_verification_sent` or `auth.email_verification_failed`.
- `POST /api/auth/verify-email`: Zod token between 20 and 200 characters, 20
  attempts per 15 minutes per client, fail closed. Returns `{ verified: true }`,
  or `400` with `verification_expired`, `verification_used`,
  `verification_invalid`. Rejections are audited as
  `auth.email_verification_rejected` with the reason only.
- `POST /api/auth/resend-verification`: requires a session, 3 per hour per
  client, fail closed, and a per-account budget of 3 issued tokens per hour
  which is audited as `auth.email_verification_throttled`. The answer is always
  the same neutral `202`, including for a verified account, an unknown account
  and a throttled request.

The response never states whether an address exists, whether it is verified, or
whether a message was actually sent.

### Frontend

- `frontend/src/lib/auth.tsx`: `User.emailVerified`.
- `frontend/src/components/VerificationPending.tsx`: replaces the shell for an
  unverified account. It names the address, offers resend and sign out, shows
  the neutral resend sentence as a `role="status"` message, and states that the
  link is single use and expires in 24 hours. No navigation is mounted, so no
  route can be reached from it.
- `frontend/src/pages/Public.tsx`: public `VerifyEmailPage` at `/verify-email`,
  lazy loaded in `App.tsx`. It consumes the token from the query string once,
  then reports "Email verified" or the API sentence.
- Login page: the registration notice now says to check the email and verify
  before signing in.
- Settings: an "Email address" card shows the address and a text badge,
  `verified` or `not verified`; the status is text, not colour alone.
- No new dashboard, chart or navigation item; existing tokens and layout are
  reused.

### Configuration

- `APP_BASE_URL` (default `http://localhost:4000`), `EMAIL_FROM`,
  `RESEND_API_KEY`.
- `backend/src/lib/loadEnv.js` reads the ignored `.env` file for local runs.
  It never overrides an existing variable, skips the file when `NODE_ENV=test`
  or `SF_SKIP_ENV_FILE=true`, and logs only a count.
- `backend/src/lib/config.js` warns in production when either email variable is
  missing, and refuses a non-HTTPS `APP_BASE_URL` because a verification token
  must not travel over plain HTTP.

## 3. Tests

`backend/tests/email-verification.test.mjs` (4 tests, in process):

1. Only the hash is stored; issuing a new token invalidates the previous link.
2. A token cannot be replayed; an expired token is refused.
3. The template escapes `<b>` in the address and carries the link in text.
4. The service returns `not_configured` without a provider, passes the built
   link to the provider, and surfaces a provider failure as a failure.

`backend/tests/email-verification-api.test.mjs` (4 tests, real HTTP and a real
database):

1. Register (neutral 202, no cookie), sign in, `/auth/me` reports
   `emailVerified: false`, workspace routes answer `403
   EMAIL_VERIFICATION_REQUIRED`, resend is neutral, a known token verifies,
   the workspace opens, replay is `verification_used`, an unknown token is
   `verification_invalid`, an expired token is `verification_expired`, a short
   token is `400`, and the audit chain verifies.
2. Resend is neutral three times, the fourth is `429 rate_limited`, and the
   throttle is audited.
3. An already verified account keeps full access.
4. Two simultaneous requests with one token produce exactly one `200` and one
   `400`.

`frontend/e2e/email-verification.spec.ts` (3 tests): a new account lands on the
pending screen instead of the shell, the resend sentence appears, sign out
returns to sign in, `/overview` is closed again, the verification page reports
accepted and rejected links.

Existing suites were updated to mark their own registered accounts verified
through the test database (`markEmailVerified` in `backend/tests/helpers.mjs`),
which mirrors what a real person does by opening the link. Demo users, the
bootstrap administrator and the Playwright administrator are verified by seed
and bootstrap, so the existing 81 browser tests are unchanged.

Commands and results:

```
npm test                      190 tests, 188 pass, 2 skipped, 0 fail
npx playwright test            84 passed
npm run typecheck             clean
npm run build                 success
```

## 4. Live delivery evidence

- A test message was sent through the official SDK to the owner's address and
  Resend accepted it: message id `01a1e430-07a0-7db5-acab-f64193daca4b`.
- **Acceptance is not inbox delivery.** Nothing on this machine can read the
  destination mailbox, so inbox arrival, spam placement and link click-through
  are **UNVERIFIED**. The status of live delivery is therefore
  **PARTIALLY IMPLEMENTED / UNVERIFIED**, not "working email".
- `EMAIL_FROM` is `SecureFlow AI <onboarding@resend.dev>`, the Resend test
  sender. It only delivers to the account owner's address; a real domain must be
  verified in Resend before other recipients receive mail. Until then, a
  registration with a different address will be accepted by the API, recorded
  as `auth.email_verification_failed`, and the person will not receive a link.

## 5. Remaining limitations

- Inbox delivery and the full click-through from a real mailbox are unverified,
  for the reason above.
- A provider that accepts a message can still fail later (bounce, spam). No
  webhook consumes Resend delivery events, so the audit trail ends at provider
  acceptance.
- The per-account resend budget counts issued tokens, not sent messages, so a
  failed send still spends budget. Three failures per hour per account is the
  worst case.
- Verification does not expire an existing session, and it does not change the
  session cookie. It only flips the gate for the next request.
- The migration grandfather decision is permanent for pre-v8 accounts. A
  deployment that wants those addresses proven must add its own re-verification
  campaign; no such campaign exists.
- Password reset (SF-AUTH-03) is still open. The mail channel now exists, so it
  is unblocked but not implemented here.
- The token travels in the query string of `/verify-email?token=...`, so a
  browser extension, a proxy access log or a leaked `Referer` header could
  observe it. The page only counts it once, links on it are same-origin, and the
  server never writes it to a log, an audit entry or a response. A path-based or
  POST-based handoff would remove this class of leak and is not implemented.
- No staging deployment or independent penetration test was performed. This is
  not a production-readiness claim.
