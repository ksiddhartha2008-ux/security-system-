# Deployment

No deployment was performed as part of this build. Everything below was exercised locally.

## Local development

```powershell
npm run install:all
npm run dev:api    # http://localhost:4000
npm run dev:web    # http://localhost:5173, proxies /api to 4000
```

The Vite proxy keeps the browser same-origin for API calls, so the session cookie behaves exactly as it does in production.

## Single process (production style)

```powershell
npm run install:all
npm run build          # writes web/dist
$env:NODE_ENV = "production"
$env:PORT = "4000"
npm start
```

`server/src/index.js` serves `web/dist` when it exists, with the SPA fallback and CSP for HTML responses. If the directory is missing, `/` returns a JSON note instead of a broken page.

### Environment

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `4000` | |
| `NODE_ENV` | `development` | `production` adds the `Secure` cookie flag |
| `SF_DATA_DIR` | `server/data` | Database and evidence live here |
| `SF_DB_PATH` | `<data>/secureflow.db` | Override the database file only |
| `SF_TRUST_PROXY` | `false` | Set `true` only behind a trusted proxy that sets `X-Forwarded-For` |
| `SF_DEMO_MODE` | on outside production | `true` seeds the synthetic workspace with demo accounts. Never enable it on a real deployment |
| `SF_BOOTSTRAP_EMAIL`, `SF_BOOTSTRAP_PASSWORD` | empty | Required to create the first admin on an empty production database |
| `SF_BOOTSTRAP_ORG`, `SF_BOOTSTRAP_NAME` | defaults | Organization and display name for the bootstrap admin |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | empty | Optional reputation providers |
| `MIROFISH_BASE_URL`, `MIROFISH_API_KEY` | empty | Optional separate service |

Copy `.env.example` as a reference. The server does not load `.env` itself; export the variables in the process manager or compose file.

## First run

```powershell
$env:NODE_ENV = "production"
$env:SF_BOOTSTRAP_EMAIL = "you@your-domain.example"
$env:SF_BOOTSTRAP_PASSWORD = "a long unique passphrase"
$env:SF_BOOTSTRAP_ORG = "Your Organization"
$env:PORT = "4000"
npm start
```

With `NODE_ENV=production` and no `SF_DEMO_MODE`, demo mode is off. On an empty database the server creates the organization and admin from the bootstrap variables. If they are missing it prints what to set and exits rather than falling back to demo credentials. Migrations run automatically, including schema v2 for TOTP MFA.

For a throwaway demo deployment, set `SF_DEMO_MODE=true` to seed synthetic records and the three known demo accounts. Do not do this with real data.

## Docker

```powershell
docker compose build
# first run: create the first admin (demo mode is off in production)
$env:SF_BOOTSTRAP_EMAIL = "you@your-domain.example"
$env:SF_BOOTSTRAP_PASSWORD = "a long unique passphrase"
docker compose up -d
docker compose logs -f secureflow
```

For a throwaway demo container, set `SF_DEMO_MODE=true` and skip the bootstrap variables. That seeds synthetic records and the three known demo accounts; never do it on a host with real data.

The image builds the web client in a first stage, installs production server dependencies in a second, and runs as the non-root `secureflow` user with `/data` as a volume. The health check calls `/api/health`.

The database is created and seeded on first start. To keep state across rebuilds, keep the `secureflow-data` volume. To reset the demo workspace, remove the volume.

## Reverse proxy

Terminate TLS in front of the Node process and forward the original host.

Caddy example:

```
secureflow.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:4000
    header {
        Strict-Transport-Security "max-age=31536000"
    }
}
```

Nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name secureflow.example.com;

    ssl_certificate     /etc/letsencrypt/live/secureflow.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/secureflow.example.com/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass         http://127.0.0.1:4000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_buffering    off;   # required for Server-Sent Events
        proxy_read_timeout 120s;
    }

    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

Only enable HSTS once HTTPS works on every hostname you serve. Do not enable preload without the owner's decision.

If the proxy does not forward `Host`, the origin check will reject writes. Keep `Host` intact or set `SF_ALLOW_ORIGIN` to the exact public origin.

## Operations

**Before real data:** confirm `NODE_ENV=production`, `SF_DEMO_MODE` unset, a bootstrap admin you control, HTTPS at the proxy, and that the demo workspace (if any) has been removed. Enable MFA for every admin from Settings, Security.

**Backups.** Stop writes or use SQLite's online backup while copying `secureflow.db`, `secureflow.db-wal` and the `evidence/` directory together. A database copy without the matching evidence files is incomplete.

**Upgrades.** Replace the application files, run the build, restart. Migrations are versioned with `PRAGMA user_version`; schema v1 applies once on an empty database. Future migrations must be additive and idempotent.

**Logs.** The server logs startup, migration application, error stack traces and simulation recovery. It does not log request bodies or secrets.

**Health.** `GET /api/health` is unauthenticated and returns no tenant data. `GET /api/settings/health` (authenticated) returns database status, MiroFish adapter status, uptime and record counts.

**Resource use.** Simulation drivers run one timer per active run with a 650 ms default round delay. Long runs with many rounds are bounded to 30 rounds by validation.

## What is not provided

- TLS certificates, DNS and domain configuration.
- A managed PostgreSQL or object storage option.
- Horizontal scaling. The SQLite file and in-process session and simulation state assume one API process.
- Email delivery, so password reset and invitations are manual.
