# Website protection

A business owner registers a website, proves ownership with DNS, receives a scoped API key, installs the Node SDK and sees website events, detections and incidents beside the rest of the platform.

This folder is the evidence pack. Read [STATUS.md](STATUS.md) first.

## Workflow

1. **Register.** `POST /api/v1/websites` normalizes the URL with the WHATWG parser, refuses IP literals, public suffixes, reserved names and embedded credentials, and stores the ASCII hostname plus its Unicode form. It returns the TXT record to publish.
2. **Verify.** `POST /api/v1/websites/:id/verify` resolves the record through the injectable resolver and compares it exactly. A scheduler retries pending checks every five minutes for two hours, then hourly, and re-checks verified sites daily.
3. **Asset.** Verification creates an `assets` row of type `website` in the existing inventory.
4. **Key.** An admin with a recent password confirmation creates a key. The secret is shown once. Only a SHA-256 hash is stored. Two active keys allow a rotation overlap.
5. **Ingest.** `POST /api/v1/ingest/website-events` authenticates with the key alone, validates each event, de-duplicates by `(site, event_id)` and stores accepted events in `security_events`.
6. **Detect.** Nine website rules run in the existing deterministic engine. Detections store their factors.
7. **Correlate.** Detections sharing a website, source address or account become one incident. Notifications are throttled and suppression is recorded.
8. **Operate.** Health signals show a silent SDK, private client addresses and host mismatches. Admins can export, delete event data, or delete the website.

## Endpoints

| Method | Path | Who |
| --- | --- | --- |
| POST | `/api/v1/websites` | admin |
| GET | `/api/v1/websites`, `/api/v1/websites/:id` | any signed in role |
| POST | `/api/v1/websites/:id/verify`, `/verification/restart` | admin |
| PATCH, DELETE | `/api/v1/websites/:id` | admin, delete needs recent auth |
| POST, GET, DELETE | `/api/v1/websites/:id/keys` | admin, write needs recent auth |
| GET | `/api/v1/websites/:id/events`, `/detections`, `/incidents` | any signed in role |
| GET | `/api/v1/websites/:id/export` | admin |
| POST | `/api/v1/websites/:id/data-deletion` | admin, recent auth |
| POST | `/api/v1/ingest/website-events` | website API key |

Full request and error details are in [HTTP_API.md](HTTP_API.md) and [EVENT_MAPPING.md](EVENT_MAPPING.md).

## Feature flag

`SF_WEBSITE_PROTECTION` (or `WEBSITE_PROTECTION_ENABLED`) turns the feature on. When unset it is on outside production and off in production. When off, the routes return `404` and the navigation item is hidden.

## Local walkthrough

```powershell
$env:SF_WEBSITE_PROTECTION='true'
$env:SF_ALLOW_TEST_HOSTNAMES='true'
$env:SF_DNS_FAKE_FILE='backend/data/demo-dns.json'
npm start
```

Sign in as an admin, open **Websites**, add `https://demo-shop.example.test`, read the record from the Verification tab, write it into `backend/data/demo-dns.json` as:

```json
{ "records": { "_secureflow-challenge.demo-shop.example.test": ["secureflow-site-verification=<token>"] }, "errors": {} }
```

Then press **Verify now**. The resolver seam is refused when `NODE_ENV=production`.

## Folder map

| File | Contents |
| --- | --- |
| [STATUS.md](STATUS.md) | Cards, gates, decisions applied, verdict |
| [REUSE_MAP.md](REUSE_MAP.md) | Existing code reused, with paths |
| [DECISIONS.md](DECISIONS.md) | D1 to D16, deviations, defaults |
| [EVENT_MAPPING.md](EVENT_MAPPING.md) | Event vocabulary and stored shape |
| [HTTP_API.md](HTTP_API.md) | Raw ingestion API |
| [THREAT_MODEL.md](THREAT_MODEL.md) | A1 to A30 and coverage |
| [SECRET_SCANNING.md](SECRET_SCANNING.md) | Key pattern and response steps |
| [PHASE_REPORT_W1.md](PHASE_REPORT_W1.md) to [W4](PHASE_REPORT_W4.md) | What each phase delivered |
| [verification/](verification/) | Evidence files with commands and results |

## Status summary

Development ready, not production ready. Gate G1 (verified email before adding a website) is blocked because the product has no email verification. G2 uses an interim password and TOTP step-up. G5 is single node. There is no independent penetration test. The full gate matrix and residual risks are in [STATUS.md](STATUS.md).
