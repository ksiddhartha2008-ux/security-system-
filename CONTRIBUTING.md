# Contributing

This repository is a working application, not a scaffold. Changes should keep the server, the client and the tests in step.

## Setup

Requirements: Node.js 24 (the SQLite driver is built in), npm 11.

```powershell
npm run install:all
npm run dev:api    # API on :4000
npm run dev:web    # Vite on :5173
```

The first start seeds a demo workspace outside production. Demo accounts are listed in the README. The database lives in `backend/data` and is ignored by Git.

## Before you open a pull request

```powershell
npm test            # backend and unit tests, isolated database per file
npm run test:sdk    # Node SDK tests, local HTTP server only
npm run typecheck   # TypeScript project check
npm run build       # production bundle
npm run scan:secrets
```

All five must pass. Do not report a check as passing unless you ran it in this working tree.

## Code conventions

- **Server**: ES modules, Express 4, `zod` validation, `node:sqlite`. Use `lib/http.js` helpers (`ok`, `created`, `paginated`, `validate`, `ApiError`) so envelopes stay consistent.
- **Database**: parameterized statements only. Every tenant query filters by `org_id` from the session or API key. Schema changes are new numbered migrations; never edit an applied migration.
- **Client**: React 19, TypeScript, Tailwind v4 utilities already defined in `styles.css`. Reuse `components/ui.tsx` rather than adding a second component style.
- **Copy**: plain and specific. No marketing claims, no invented numbers, no em dashes in user interface text.
- **Synthetic data**: label it. Demo records use the `DEMO` origin, simulation records `SIMULATED`, and test hostnames use `.test`. Never present synthetic activity as real.

## Security rules

- Never commit `.env`, database files, evidence uploads, logs or build output.
- Never log or return a password, API key, session token or challenge secret.
- New secrets are generated with `node:crypto`; compare them with `timingSafeEqual`.
- New tenant tables need `org_id`, a foreign key, and a test that a second organization receives `404`.
- New sensitive actions need an audit entry written in the same transaction as the change.
- A failing security check must deny, not allow.

## Tests

- Backend tests live in `backend/tests` and use `node:test` with `startServer()` from `helpers.mjs`.
- Tests never contact the internet. The website tests inject a file resolver through `SF_DNS_FAKE_FILE`.
- Security controls need a negative test: the attack case, not only the happy path.
- A new rule needs a benign near-miss fixture and an attack fixture. Report measured numbers, not estimates.

## Commit messages

Use a short type prefix and the area:

```
feat(website): add key rotation overlap
fix(auth): reject replayed MFA challenge
test(detection): cover benign near misses
docs(website): record gate status
chore(ci): run the SDK suite
```

One logical change per commit. Do not amend or rewrite pushed commits. Never force push.

## Documentation

- User facing behaviour: `README.md`.
- Architecture and data model: `docs/ARCHITECTURE.md`.
- Security controls and gaps: `docs/SECURITY.md` and `docs/website/STATUS.md`.
- API: `docs/API_DOCUMENTATION.md`.
- A feature is not finished until its status and evidence are recorded. Use the labels `IMPLEMENTED`, `TESTED`, `SIMULATED`, `PARTIALLY IMPLEMENTED`, `PLANNED`, `UNVERIFIED`.
