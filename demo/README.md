# Demo database snapshot

`secureflow-demo.db` is a sanitized SQLite snapshot of the Meridian demo workspace. It is a reference dataset, not the running database.

## Provenance

- Built from the local development database on 12 November 2026.
- Source schema: v5, 41 tables.
- Command: `npm run demo:snapshot`
- Generator: `scripts/export-demo-snapshot.mjs`
- The source database is never modified.

## Contents

| Table | Rows |
| --- | ---: |
| Organizations | 1 (`org_meridian`) |
| Users | 3 demo accounts |
| Assets | 15 |
| Security events | 302 |
| Detections | 19 |
| Incidents | 9 |
| Vulnerabilities | 12 |
| Network events | 169 |
| Indicators | 12 |
| Simulations | 3 |
| Reports | 2 |
| Verified websites | 1 (`demo-shop.example.test`) |

Event origins include `DEMO` (seed batch `seed-v1`), `SIMULATED` (simulation lab mirroring) and `REAL` (26 events from the local `.test` website SDK). The `.test` website is labelled as a test domain in the interface.

## Removed before publishing

- Every session and MFA challenge.
- Every login attempt.
- Every audit log row.
- Every website API key.
- Every evidence and custody record.
- The personal organization and user account that existed in the live development database.
- All rows belonging to any organization other than `org_meridian`.

The generator fails if a non-demo user, non-demo email or any of those sensitive tables remains.

## Restore for local exploration

Stop the server first, then replace the local database with the snapshot:

```powershell
Copy-Item demo\secureflow-demo.db backend\data\secureflow.db -Force
npm start
```

The demo accounts are the documented ones:

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@secureflow.dev` | `Admin#2026` |
| Security analyst | `analyst@secureflow.dev` | `Analyst#2026` |
| Viewer | `viewer@secureflow.dev` | `Viewer#2026` |

## Demo DNS record

`demo-dns.json` contains the TXT record used by the local `.test` website. It is only a DNS challenge value for a reserved test hostname. It is not a credential.

```powershell
$env:SF_WEBSITE_PROTECTION='true'
$env:SF_ALLOW_TEST_HOSTNAMES='true'
$env:SF_DNS_FAKE_FILE='demo/demo-dns.json'
npm start
```

The production configuration refuses fake resolver files and test hostnames.

## Validation

```powershell
node -e "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync('demo/secureflow-demo.db');console.log(d.prepare('SELECT COUNT(*) c FROM organizations').get(), d.prepare('SELECT COUNT(*) c FROM users').get(), d.prepare('SELECT COUNT(*) c FROM sessions').get(), d.prepare('SELECT COUNT(*) c FROM audit_logs').get());"
```

Expected: `1` organization, `3` users, `0` sessions, `0` audit rows.

## Why this is not the live database

The live database contained a personal account, active sessions and audit rows. Committing it would publish personal data and session material. The snapshot keeps the synthetic demo state needed to explore the application and removes the rest.
