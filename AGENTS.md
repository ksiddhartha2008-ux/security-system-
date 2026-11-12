# SecureFlow AI: repository instructions for coding agents

Read this before changing the frontend. It records the conventions that the application already follows.

## Project

- `backend/`: Node 24, Express 4, `node:sqlite`, Zod. Schema v5, 41 tables. Do not change business logic for a UI task.
- `frontend/`: React 19, TypeScript, Vite 6, Tailwind CSS v4, Astryx 0.7.13.
- `packages/sdk-node/`: private Node SDK for website event ingestion.
- `docs/website/`: website protection evidence pack.

## Commands

```powershell
npm run dev:api        # API on :4000
npm run dev:web        # Vite on :5173
npm test               # backend and SDK-adjacent backend tests
npm run test:sdk       # Node SDK tests
npm run typecheck
npm run build
npm run scan:secrets
```

## Astryx rules

1. Use the installed package, never an unscoped `astryx` package. Components are imported from a subpath:

   ```ts
   import {Badge} from '@astryxdesign/core/Badge';
   import {Card} from '@astryxdesign/core/Card';
   import {Button} from '@astryxdesign/core/Button';
   ```

2. Before using a component, read its real documentation:

   ```powershell
   cd frontend
   npx --no-install astryx component --list
   npx --no-install astryx component Table
   npx --no-install astryx docs theme
   ```

   Do not invent props, slots, variants or CSS class names.

3. The theme source is `frontend/src/lib/theme/secureflowTheme.ts`. Generated files beside it are build output. After editing the theme run:

   ```powershell
   npm run theme:build
   npm run check:theme
   ```

   Never edit `secureflow.css`, `secureflow.js` or the generated `.d.ts` files by hand.

4. Keep Astryx inside the frontend. It must never reach the API client, server routes or database. The existing `api.ts`, `auth.tsx` and all routes stay authoritative.

5. Use application components for domain behaviour: status and severity mapping, tables with stored factors, charts, dialogs with evidence, and any component that needs SecureFlow data. Use Astryx for design primitives and layout.

6. Dark mode is the current analyst experience. The theme contains light values but the legacy application CSS is dark-first, so do not expose a light-mode switch without migrating the remaining hardcoded colours.

7. Do not use `@astryxdesign/charts` or `@astryxdesign/lab`. Charts are application-owned SVG components; the Astryx chart packages are canary or unpublished.

## Security rules

- Never put an API key, session token or password in the frontend.
- Never add a client-supplied organization id or severity.
- Do not bypass the API's authorization; a hidden route is not a permission check.
- Do not render event fields with `dangerouslySetInnerHTML`.
- Do not add fake dashboard data. If a value is unavailable, show an empty state or an error with the request id.

## UI conventions

- Plain, specific copy. No marketing language, no invented numbers, no em dashes in user-facing text.
- Every status badge includes readable text, not colour alone.
- Every icon-only button has an accessible name.
- Reuse `components/ui.tsx` and `components/design.tsx` before creating another primitive.
- New routes in `App.tsx` are lazy loaded. Keep the initial bundle from growing without a reason.
