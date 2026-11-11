# Phase report W4: dashboard, SDK and operations

Date: 2026-11-11 UTC. Commit: `7d58cd1`, `60e02c8`.

## Delivered

- `frontend/src/pages/Websites.tsx`, `WebsiteNew.tsx`, `WebsiteDetail.tsx`, `components/RecentAuth.tsx`, `lib/website.ts`.
- Navigation entry gated by the feature flag, routes, responsive layout rules.
- Key management with one time display and acknowledgement, step-up dialog, verification record with copy controls, event, detection and incident tabs, settings, export and deletion.
- Scheduler with a lease, daily re-verification, retention, health jobs.
- SDK tests and the snippet parse test.
- Documentation in this folder.

## Evidence

- [W4.1](../verification/W4.1.md): manual walkthrough at 424 px, type check, production build.
- [W5.1](../verification/W5.1.md): scheduler and retention tests, migration on a copy of the live database.
- [W7.1](../verification/W7.1.md): 13 SDK tests.

## Issues found and fixed

- The key list did not refresh after creating or revoking a key until the page was reloaded. A version counter now reloads it.
- The verification banner showed only for pending sites; it now also covers expired and lapsed sites.

## Not delivered

- Automated accessibility engine, screen reader testing, 360 px device testing.
- Browser SDK.
