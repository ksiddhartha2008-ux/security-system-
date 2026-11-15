# TriShield test evidence

Environment for every run below:

| Item | Value |
| --- | --- |
| Date | 15 November 2026 |
| Baseline commit | `acd3de4` |
| Platform | Windows 11 Home Single Language |
| Node | 24.20.0 |
| Database | `node:sqlite`, schema v6 |
| Linux, WSL, Docker, nft | absent |
| Cloudflare account | absent |
| Suricata, Wazuh, ClamAV, YARA, Falco | absent |

## Service and policy tests

```
cd backend
node --test tests/trishield.test.mjs
```

Result: 14 tests, 14 pass, 0 fail.

| Test | What it proves |
| --- | --- |
| address classification and masking | IPv4 and IPv6 scope mapping, masking, invalid input returns null |
| HMAC fingerprints | Stable per key version, different with another key, `ipfp_` format |
| vault | AES-256-GCM round trip and tamper rejection |
| protected addresses | Loopback and private refused, public allowed |
| nftables installs drop rules | Table, sets, base chain, both drop rules, element, timeout, delete |
| nftables verification without the drop rule | Verification fails when the rule is missing even if the element exists |
| nftables health | `unprovisioned` with the missing tokens, never ok |
| apply flag off | Block refuses before touching the host |
| Cloudflare connector | Create, verify and delete against an injected fetch |
| action lifecycle | Not approved is refused, approved executes and verifies, rollback restores |
| idempotency | A second proposal returns the same action |
| policy gate | Auto mode still stops when the apply flag is off |
| parsers | Suricata, Wazuh and WAF normalization, unknown category refused |
| ingestion | Duplicate counted and dropped, tenant scope preserved |

## API tests

```
cd backend
node --test tests/trishield-api.test.mjs
```

Result: 8 tests, 8 pass, 0 fail. The server ran with
`SF_CLOUDFLARE_API_TOKEN` and `SF_CLOUDFLARE_ACCOUNT_ID` set to invalid test
values, so the connector contract was exercised for real.

| Test | Result |
| --- | --- |
| overview honesty | Three layers, endpoint not ACTIVE without an agent, provider detail present |
| role matrix | Viewer and analyst refused on propose, policy, collector, health and discovery; analyst refused on approve |
| validation | Invalid, private, loopback, metadata, short reason, permanent by analyst all refused with 400 |
| propose and approve | Analyst proposes, admin approves, execution fails against the invalid credential and records `failed` with no active rule |
| duplicate proposal | Second request returns the same action with `duplicate: true` |
| unavailable provider | nftables on Windows refused with 409, never simulated |
| collector tokens | Bearer accepted, wrong kind 403, forged 401, revoked 401, other tenant sees nothing |
| cross tenant | Foreign action approve, reject, execute and allowlist delete all 404; list responses never include a raw address |
| reveal and allowlist | Analyst 403, empty reason 400, duplicate allowlist 409, invalid address 400 |

## Feature flag tests

```
cd backend
node --test tests/trishield-flag.test.mjs
```

Result: 2 tests, 2 pass. With `TRISHIELD_ENABLED=false` the API returns 404 and
`/auth/me` reports the feature off. A default server reports the feature on with
`apply` and `autoApply` false.

## Full backend suite

```
cd C:\Users\ksidd\OneDrive\Pictures\Desktop\hack
npm test
```

Result: 147 tests, 145 pass, 0 fail, 2 skipped. The two skips are the existing
PostgreSQL and Redis cases that need services which are not installed here.

## Type checking and build

```
npm run typecheck
npm run build
```

Result: typecheck clean. Build succeeded. `TriShield` is a separate lazy chunk at
26.15 kB (7.15 kB gzip) and does not grow the initial bundle.

## Accessibility and motion

```
cd frontend
npx playwright test --project=chromium
```

Result: 49 pass, 0 fail, including `/trishield` in light and dark with real API
data. The route was added to `ROUTES` in `e2e/a11y.spec.ts`, so any future
regression on this page fails the suite.

## Secret scan

```
npm run scan:secrets
```

Result: `Secret scan clean`.

## Live interface check on the development server

The API was restarted on port 4000 with the new code and driven through a real
session as the demo administrator.

| Step | Observed |
| --- | --- |
| `POST /api/trishield/ip/discover` | `discovered=8`, `sealed=0`, `vaultConfigured=false` |
| `GET /api/trishield/ip/addresses` | 8 rows, all masked, no `address` field in the payload, 2 management |
| `GET /api/trishield/overview` | perimeter `NOT CONFIGURED`, application `ACTIVE`, endpoint `NOT CONFIGURED` |
| Provider status | nftables `UNAVAILABLE`, cloudflare `UNAVAILABLE` |
| Browser, `/trishield` | Overview cards, five tabs, IP Shield table with masked values, Perimeter feed with `simulated` badges on seeded rows |

## What was not tested, and why

| Item | Status | Reason |
| --- | --- | --- |
| nftables enforcement on a kernel | BLOCKED | No Linux host, WSL distribution, container runtime or `nft` binary here. Runner: `scripts/trishield-firewall-check.mjs`, which refuses to run unless `TRISHIELD_ISOLATED=1` and `--apply` are present, and prints BLOCKED on this platform (verified: exit code 2). |
| Cloudflare against a live account | BLOCKED | No token. The invalid-token test proves the failure path only. |
| Suricata, Wazuh, WAF live feeds | BLOCKED | No collector services. Parsers and ingestion were tested with recorded payload shapes. |
| ClamAV, YARA, Falco | BLOCKED | Not installed. |
| Staging or production deployment | NOT PERFORMED | No target environment. |
| Independent penetration test | NOT PERFORMED | Requires an external engagement. |

## Reproduction notes

- Tests that touch a database create their own temporary file and never read
  `backend/data/secureflow.db`.
- Tests that touch a provider always inject a transport. No test contacts
  Cloudflare with a real credential.
- The API test with invalid credentials does reach the Cloudflare endpoint and
  expects a failure. It asserts a failure, never a success.
