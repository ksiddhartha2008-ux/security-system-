# Phase report W2: credentials and ingestion

Date: 2026-11-11 UTC. Commit: `7d58cd1`.

## Delivered

- `site_api_keys` with key id, SHA-256 secret hash, last four, scopes, timestamps, revocation reason.
- `backend/src/lib/apiKeys.js`: generation from a CSPRNG, parsing, constant time comparison, ten second cache, cache purge on revoke.
- `POST /api/auth/step-up` and `requireRecentAuth`, with TOTP when MFA is enabled.
- `POST /v1/websites/:id/keys`, `GET`, `DELETE`, all scoped and audited.
- `POST /v1/ingest/website-events`, mounted before cookies and CSRF, raw body limit, strict validation, idempotency, durable counters and a post commit pipeline job.
- SDK package `packages/sdk-node`.

## Evidence

- [W2.1](../verification/W2.1.md): key creation, recent auth, limit, metadata, revocation.
- [W2.2](../verification/W2.2.md): cookies, query keys, media type, oversized body, prototype pollution, rejects, replay, limits.

## Issues found and fixed

- The smoke script called `/v1/ingest` instead of `/api/v1/ingest`; the route was correct.
- The SDK shutdown raced a sleeping retry and left the test process alive. Fixed with an abort flag and bounded retry timing.

## Not delivered

- Automatic key rotation. Rotation is manual with a two key overlap.
- Email or webhook delivery of any notification.
