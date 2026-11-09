# Dependency security report

Date: 9 November 2026
Runtime: Node 24.20.0, npm 11.19.0, Windows 11.

## Runtime dependencies

### Server (`backend/package.json`)

| Package | Version | License | Notes |
| --- | --- | --- | --- |
| express | 4.21.2 | MIT | HTTP framework |
| zod | 4.6.7 | MIT | Request and response validation |

`node:sqlite`, `node:crypto`, `node:http`, `node:https`, `node:dns` and `node:net` are built into Node; no database driver, ORM, JWT library or HTTP client dependency is used.

### Web (`frontend/package.json`)

| Package | Version | License |
| --- | --- | --- |
| react | 19.0.0 | MIT |
| react-dom | 19.0.0 | MIT |
| react-router-dom | 7.1.1 | MIT |
| lucide-react | 0.469.0 | ISC |

Build tooling (dev only): vite 6, @vitejs/plugin-react, typescript 5.7, tailwindcss 4, @tailwindcss/vite, @types/react, @types/react-dom.

## Audit results

```
npm audit --prefix backend
0 vulnerabilities (70 production dependencies)

npm audit --prefix frontend
0 vulnerabilities (9 production, 156 development, 82 optional)
```

## Changes made

| Package | From | To | Reason | Verification |
| --- | --- | --- | --- | --- |
| zod | 3.23.8 | 4.6.7 | GHSA-mrhx-c7xc-m3w5: memory exhaustion with oversized constrained collections (high) | Full suite 42/42, production build, manual login |

Compatibility work for the major upgrade:

- `z.record(valueSchema)` changed to `z.record(z.string(), valueSchema)` in events, settings and simulations.
- No other schema API used by the project changed behaviour; all 42 tests pass.

## Packages deliberately not added

| Candidate | Reason |
| --- | --- |
| LangChain / LangGraph / CrewAI / AutoGen | No LLM feature exists; adding an agent framework would add attack surface with no capability |
| Redis client | No Redis deployment available; the shared rate-limit adapter is not implemented rather than faked |
| Postgres driver | SQLite is the current store; a migration is a project, not a dependency swap |
| JWT library | Sessions are opaque server-side tokens stored as hashes |
| Chart / UI kit | Charts are hand-written SVG; the design system is local CSS |
| Malware scanner client | ClamAV is spoken to over a raw TCP INSTREAM socket in `lib/clamav.js` |

## Third-party source included in the repository

| Repository | License | Used at runtime? | Obligations |
| --- | --- | --- | --- |
| MiroFish (`666ghj/MiroFish`) | AGPL-3.0 | No; optional separate service via HTTP adapter | If modified and hosted, offer source (AGPL section 13). License text is preserved under `third_party/`. |
| API Anything (`goodnight000/api-anything`) | MIT | No; documented development tool | Preserve copyright and permission notice if redistributed. |

Neither is linked into the application process. The Threat Simulation Lab uses the native engine.

## Supply chain controls

- Lockfiles are committed for server, web and both third-party repositories.
- `npm ci` is used in CI and the Docker build.
- No install scripts are executed for application dependencies; the only postinstall seen was esbuild's binary installer, required by Vite.
- GitHub Actions runs `npm ci`, the test suite and the production build.
- No package is installed at runtime.

## Residual risk

1. Transitive dev dependencies (Vite, Tailwind) are not scanned at runtime but are present in the build environment. Audit currently reports none.
2. A future `zod` major upgrade must repeat the schema review.
3. `npm audit` is a snapshot; pinning and periodic review are required.
4. Third-party repositories may contain their own advisories; they are not executed by SecureFlow.
