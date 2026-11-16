# Phase 1.2: registration email enumeration prevention (SF-AUTH-06)

Implemented: 16 November 2026
Finding: SF-AUTH-06, registration reveals whether an email exists
Status: **IMPLEMENTED AND TESTED**
No database migration was required.

## 1. Original vulnerability

`POST /api/auth/register` returned:

- `201` with the new user and an authenticated session for a new address.
- `409 An account with this email already exists` for a registered address.

An unauthenticated attacker could therefore test addresses at six attempts per
hour and learn which ones had accounts. The successful path also set a session
cookie, so the difference was visible in the response body, status and headers.

## 2. Root cause

The handler performed a duplicate lookup and threw `conflict`, then created the
organisation and user and called `createSession`. The two branches were written
for product convenience and never treated as an enumeration surface.

## 3. Backend changes

`backend/src/routes/auth.js`

- Both outcomes return `202 Accepted` with exactly:
  `{ "data": { "message": "If registration can be completed, you can continue by signing in." } }`.
- No session, CSRF cookie or redirect is created for either outcome.
- A duplicate is answered without a second database write.
- The duplicate path still performs a bounded amount of work and waits for a
  250 ms floor, so the response does not return instantly compared with the
  scrypt path. This is a band, not a proof of equal timing.
- A concurrent insert that loses the unique index is caught, the transaction is
  rolled back, and the same neutral response is returned. No orphan organisation
  remains.
- The successful registration writes `auth.register` into the new workspace's
  audit chain. A duplicate attempt writes `auth.register_duplicate` on the
  system chain, because no tenant is known and the address must not be stored in
  audit metadata.
- Email normalisation is the existing Zod schema: trim, lowercase, validate,
  maximum 180 characters. Registration and login share it. The database
  uniqueness constraint remains on `users.email`.
- The registration limiter is unchanged: six attempts per hour per client,
  fail closed when the shared store is unavailable.

`backend/src/lib/http.js`: added the `accepted` helper for the 202 envelope.

## 4. Frontend changes

- `frontend/src/lib/auth.tsx`: registration posts and no longer refreshes the
  auth context, because no session exists.
- `frontend/src/pages/Public.tsx`: after registration the person is sent to
  `/login?registered=1`. The login page shows a neutral notice that is identical
  for a new and an existing address. No "already exists" message is shown.
- No new page, route or navigation item. Existing validation, layout and login
  navigation are unchanged.

## 5. Session behaviour

Registration never authenticates. Both branches return no `Set-Cookie` header,
no `sf_session` and no `sf_csrf`. The person signs in through the existing login
route, which is where MFA, lockout and session rotation already live. Phase 1.1
administrator MFA enforcement remains active after that login.

## 6. Database concurrency

- Organisation and user creation stay inside the existing `BEGIN IMMEDIATE`
  transaction.
- The `users.email` unique constraint is the final arbiter.
- A concurrent duplicate is caught by message match, returns the neutral 202 and
  leaves no partial organisation.
- Regression test opens the server database read only and asserts one user for
  the address and zero organisations without a user.

## 7. Rate limiting

Unchanged: six per hour, keyed by the client address through the existing
trusted-proxy configuration, fail closed. The limiter runs before the handler, so
a limited request reveals nothing about the address. The test sends the seventh
request with an existing address and receives `429 rate_limited`.

## 8. Tests

`backend/tests/registration-enumeration.test.mjs` (6 tests):

1. New and existing addresses return identical status, body, no cookie and no
   redirect; neither client has a session afterwards.
2. Only one workspace exists; the existing account can sign in; the duplicate is
   audited; the new workspace owns its registration audit entry.
3. Mixed case and surrounding whitespace normalise to the same account, and login
   uses the same normalisation.
4. Invalid input is still `400 validation_failed`, not the neutral response.
5. The sixth request is accepted and the seventh is `429`, independent of whether
   the address exists.
6. Five simultaneous registrations for one address all return 202, create one
   user and no orphan organisation.

Updated existing suites: `auth.test.mjs`, `isolation.test.mjs`, `demo.test.mjs`,
`website-api.test.mjs`, `trishield-api.test.mjs`, `data-protection.test.mjs`,
`mfa.test.mjs`, `admin-mfa.test.mjs` and `helpers.mjs` now register and then sign
in through the real login route, including TOTP enrolment where the fixture
needs admin actions.

Commands and results:

```
npm test                      182 tests, 180 pass, 2 skipped, 0 fail
npx playwright test           81 passed
npm run typecheck             clean
npm run build                 success
npm run scan:secrets          clean
npm audit --omit=dev          0 vulnerabilities (backend and frontend)
```

The two skipped tests need PostgreSQL and Redis, which are not installed here;
CI runs the Redis case against a real server.

## 9. Remaining limitations

- Timing is equalised with a 250 ms floor, not proven equal. A slow host can push
  the hashing path past the floor, and network jitter remains. Perfect timing
  equality is not claimed.
- There is still no email verification or password recovery. Until a mail channel
  exists, registration can create an account for an address the person does not
  control; this is documented in SF-AUTH-02 and SF-AUTH-03 and is out of scope
  for this phase.
- A neutral 202 means legitimate users also cannot tell whether the account was
  created until they try to sign in. The login page explains that next step.
- Rate limiting is per client address. An attacker with many addresses can still
  test six addresses per hour per address, as before.
- The duplicate audit entry is on the system chain, not the tenant chain, because
  revealing the owning tenant would defeat the purpose.
- No production deployment, external mail provider or penetration test was
  available; this is not a production-readiness claim.
