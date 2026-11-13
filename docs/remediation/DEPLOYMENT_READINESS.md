# Deployment readiness

## Status

| Area | Status | Evidence |
| --- | --- | --- |
| Container image definition | IMPLEMENTED, NOT VERIFIED | `Dockerfile` reviewed; no Docker on this host |
| Compose with Redis | IMPLEMENTED, NOT VERIFIED | `docker-compose.yml` updated |
| Production configuration gate | IMPLEMENTED, TESTED | `backend/src/lib/config.js`, startup refusal |
| Liveness and readiness probes | IMPLEMENTED, TESTED | `/api/health`, `/api/health/ready` |
| Security headers | IMPLEMENTED, TESTED | `backend/src/index.js` |
| Structured logs with request id | PARTIALLY IMPLEMENTED | request id on every response; logs are plain lines |
| Backup and restore | IMPLEMENTED, TESTED | `backend/scripts/backup.mjs`, 5 tests |
| Staging deployment | NOT VERIFIED | no Docker or staging host available |
| Production deployment | NOT VERIFIED | explicitly out of scope |

## 1. What the deployment looks like

One stateless API container serves the built SPA and the API on port 4000. A named volume holds the SQLite database and evidence files. Redis provides shared rate limit counters. TLS terminates at a reverse proxy in front of the container.

There is no PostgreSQL service in compose because the application cannot use it yet. Adding one would imply support that does not exist. See `DATABASE_MIGRATION_REPORT.md`.

## 2. Required configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `NODE_ENV=production` | yes | enables secure cookies and HSTS |
| `PORT` | no, default 4000 | listen port |
| `SF_DATA_DIR` | yes in a container | writable volume for database and evidence |
| `SF_BOOTSTRAP_EMAIL` | first start only | first administrator |
| `SF_BOOTSTRAP_PASSWORD` | first start only | 12 or more characters |
| `SF_BOOTSTRAP_ORG` | no | organization name |
| `SF_TRUST_PROXY=true` | behind a proxy | correct client IP and limits |
| `SF_ALLOW_ORIGIN` | behind a separate origin | exact https origin allowed for mutations |
| `SF_REDIS_URL` | recommended | shared rate limits |
| `SF_RATE_LIMIT_FAIL_MODE` | no, default `local` | `closed` refuses when Redis is down |
| `CLAMAV_HOST` | recommended | evidence scanning; production fails closed without it |
| `VIRUSTOTAL_API_KEY` | optional | reputation lookups |
| `ABUSEIPDB_API_KEY` | optional | IP reputation |
| `MIROFISH_BASE_URL` | optional | separate simulation service |

Never commit a filled `.env`. The repository only contains `.env.example`.

## 3. Startup gate

`checkProductionConfig()` refuses to start when:

- demo mode is on without the explicit throwaway flag
- the allowed origin is not https
- the DNS test seam is configured
- test hostnames are allowed

It warns when the proxy, scanner, provider keys or MiroFish are missing, because those degrade features rather than break security.

## 4. Probes

| Probe | Meaning | Body |
| --- | --- | --- |
| `GET /api/health` | process is alive | status, service, time, version |
| `GET /api/health/ready` | database answers, store named | status, checks.database, checks.rateLimitStore |

Both return no tenant data. Both are rate limited with the global policy. A reverse proxy should use `/api/health/ready` for readiness and `/api/health` for liveness.

## 5. Observability

- Every response carries `X-Request-Id`; error bodies repeat it as `request_id`.
- Errors are logged once with method, path and the error object; no request body is logged.
- The audit chain records security relevant actions per organization.
- `GET /api/settings/health` returns service checks for an authenticated user.
- Metrics are not exported. A Prometheus endpoint is NOT IMPLEMENTED; the recommended next step is an OpenTelemetry SDK with an OTLP exporter, keeping tenant ids out of labels.

## 6. Secrets

- Provider keys and the ClamAV host are read from the process environment only.
- Site API keys are stored hashed and shown once.
- The container image contains no secret.
- Rotation: replace the environment value and restart; sessions and API keys are unaffected. Provider key rotation invalidates only the provider cache.

## 7. TLS and proxy

- Redirect HTTP to HTTPS at the proxy.
- Keep HSTS enabled only after HTTPS works, because it is sent by the app in production.
- Set `SF_TRUST_PROXY=true` only when exactly one proxy hop sits in front of the app.
- The proxy must preserve `Host` and `Origin`; the app rejects mutations whose origin does not match the host.
- WebSocket is not used. Server sent events need buffering disabled on `/api/stream` (`X-Accel-Buffering: no` is already sent).

## 8. Rollback

1. Keep the previous image tag.
2. Database migrations are forward only; take a backup before deploying a new schema.
3. Roll back the image, not the database, unless the migration is incompatible. Restore from backup only as a last resort; the restore procedure is in `BACKUP_RECOVERY_GUIDE.md`.

## 9. Blockers for staging verification

- This host has no Docker, so the image and compose file were reviewed but not executed.
- No staging host, DNS name or TLS certificate is available.
- No PostgreSQL instance, so the migration rehearsal cannot run.
- No legitimate provider credentials, so live integration calls remain BLOCKED.

These are environment blockers, not code defects. Each is recorded so the status is not overstated.
