# API Anything integration

## What API Anything actually is

Source inspected: `third_party/api-anything/api-anything-main` (extracted from `api-anything-main.zip`, original repository `https://github.com/goodnight000/api-anything`).

| Fact | Finding |
| --- | --- |
| Package | `api-anything` version 0.4.0, MCP name `io.github.goodnight000/api-anything` |
| License | MIT |
| Runtime | Node `>=22.13.0`; the available runtime is Node 24.20.0 |
| Type | TypeScript CLI plus MCP server (`bin: dist/cli.js`), not a frontend or backend framework |
| Capability | Learns the HTTP request a website's own page makes, then replays it over plain HTTP; shares learned operations with cookies and tokens stripped |
| Distribution | `npx -y api-anything setup`; connects MCP clients such as Codex, Claude Code, Cursor or VS Code |
| Local mode | `setup --local-only` keeps everything on the machine |
| Repository content | `src/` (learn, execute, heal, classify, browser), `sites/` catalog, `registry/` Cloudflare worker, `python/` client, tests |

## Evaluation

**Useful for:** development workflows where an agent needs a site that has no API, and for learning a request shape once instead of driving a browser on every call. It can shorten research and data gathering during development.

**Not suitable for:**

- SecureFlow's backend, authentication, database or detection engine. It has none of those responsibilities and no security model for multi-tenant data.
- Runtime dependencies. The product must work with no MCP client installed.
- Operations against authenticated production systems. Learned operations may carry cookies; publishing them could leak access.

**Security observations from the source and README:** the tool stores learned operations locally, strips cookies and tokens when sharing, and drives a browser to learn. Any tool that replays authenticated requests is a credential handling risk if pointed at production. It must never receive SecureFlow session cookies, API keys or customer data.

## What was configured

Deliberately minimal:

1. `API_ANYTHING_ENABLED` environment flag, default `false`.
2. An integration row in Settings with status `disabled`, the MIT license fact, and a description that says it is a development tool.
3. A configuration test endpoint that returns `disabled` without trying to launch anything.
4. This document.

No package was installed into the application, no MCP client was configured, and no website operation was learned or published. That is intentional: the master prompt says to configure it only if useful and safe, and to keep it out of production.

## If your team wants to use it during development

On a developer machine, outside this repository's runtime:

```sh
npx -y api-anything setup --local-only
```

Then choose the MCP client you use. Keep these guardrails:

- Use a dedicated browser profile that is not signed in to anything you would not want learned.
- Never point it at the SecureFlow application while signed in; a learned operation could capture your session cookie.
- Review anything before publishing to a shared catalog. `--local-only` avoids publishing entirely.
- Do not add its token or cookies to this repository or to `.env`.
- Treat learned operations as untrusted code paths: they replay requests, so scope them to read only endpoints.

## Why it is not a dependency

| Criterion | Result |
| --- | --- |
| Needed to build or run SecureFlow | No |
| Adds an attack surface to the server | Yes, if installed with a browser backend |
| Handles credentials | Yes, by design |
| Stable interface for production | No; it is a fast moving developer tool (0.x) |
| License compatibility | MIT, compatible, but irrelevant while unused |

Verdict: **evaluated, documented, not installed, not required.** The application has no import of the package and no runtime call to it.

## Verification

- `backend/src/routes/settings.js` exposes the row and test endpoint; the UI shows `disabled`.
- `backend/package.json` and `frontend/package.json` contain no `api-anything` dependency.
- `npm ls api-anything` in both packages reports an empty tree.

## Licensing

MIT. If you later bundle or redistribute it, include the copyright notice and permission notice. Nothing in SecureFlow's license changes by documenting it.
