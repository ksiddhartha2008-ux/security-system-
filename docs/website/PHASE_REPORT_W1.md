# Phase report W1: onboarding and ownership

Date: 2026-11-11 UTC. Commit: `7d58cd1`.

## Delivered

- Schema v5: `website_sites`, `domain_verifications`, `website_verification_attempts`, partial unique index on verified hostnames, composite foreign keys.
- `backend/src/lib/websiteNormalize.js`: WHATWG parsing, one trailing dot removed, IP literals refused, reserved names, public suffix handling with `tldts`, punycode storage, Unicode display, homograph warning.
- `backend/src/lib/dnsTxt.js`: resolver abstraction, file resolver for tests, exact comparison, record and character caps, error classification.
- `backend/src/services/websiteSites.js`: create, idempotent pending create, challenge creation, manual and scheduled checks, conflict handling, asset creation, soft delete, lapse and restore.
- Routes and the website list, wizard and verification tab.

## Evidence

- [W1.1](../verification/W1.1.md): 13 normalization tests pass.
- [W1.2](../verification/W1.2.md): integration tests for missing, mismatch, resolver error, success, race, domain overlap and rate limits.

## Issues found and fixed

- A test assumed the registrable domain of `example.test` was the entered subdomain. Corrected the fixture to a real registrable name.
- `.test` was initially rejected even in test mode because the option and the environment variable were combined incorrectly. Fixed and covered by the production refusal test.

## Not delivered

- File and meta tag verification methods (D2, D7).
- Two resolver corroboration.
