# Staging deployment guide

This guide prepares a staging deployment. It has not been executed on this host because Docker is not installed. Treat every step as unverified until it runs on a staging machine.

## 1. Prerequisites

- Docker 24 or newer with compose v2
- A host with at least 2 GB RAM and 10 GB disk
- A DNS name and TLS certificate, or a TLS terminating proxy
- Outbound HTTPS for provider calls, if keys are configured
- No production data

## 2. Prepare the environment

```bash
git clone https://github.com/ksiddhartha2008-ux/security-system-.git
cd security-system-
git checkout <commit>
cp .env.example .env
```

Set at least:

```
NODE_ENV=production
SF_BOOTSTRAP_EMAIL=admin@staging.example
SF_BOOTSTRAP_PASSWORD=<12 or more characters, from a secret manager>
SF_BOOTSTRAP_ORG=Staging Workspace
SF_TRUST_PROXY=true
SF_ALLOW_ORIGIN=https://staging.example
SF_RATE_LIMIT_FAIL_MODE=closed
```

Leave `SF_DEMO_MODE` empty. Leave provider keys empty unless the test needs them.

## 3. Start the stack

```bash
docker compose up -d --build
docker compose ps
```

Expected: `secureflow` healthy, `redis` healthy.

## 4. Verify

```bash
curl -fsS https://staging.example/api/health
curl -fsS https://staging.example/api/health/ready
curl -fsSI https://staging.example/ | grep -i -E 'content-security-policy|strict-transport-security|x-frame-options'
```

Readiness must report `"database":"ok"` and `"rateLimitStore":"redis"`.

## 5. First login and smoke test

1. Sign in with the bootstrap account, change the password immediately.
2. Create an analyst and a viewer account.
3. Confirm the viewer sees read only pages and no write buttons.
4. Load every module once and confirm no error banner.
5. Toggle light, dark and system in the account menu.
6. Generate one report and delete it.
7. Create a website in test mode only if DNS verification is configured.

The API sweep can be pointed at staging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/health-check.ps1 -Base https://staging.example/api
```

It signs in with the demo accounts, so it only applies to a demo seeded workspace.

## 6. Shared rate limit check

```bash
for i in $(seq 1 15); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://staging.example/api/auth/login -H 'content-type: application/json' -d '{"email":"nobody@example.test","password":"wrong"}'; done
```

The last responses must be 429, and the same must hold when a second container is added behind the proxy.

## 7. Backup before any migration

```bash
docker compose exec secureflow node backend/scripts/backup.mjs --source /data/secureflow.db --out-dir /data/backups --label staging
```

Copy the backup off the volume and confirm the `.sha256` file.

## 8. Stop and roll back

```bash
docker compose down
```

Data stays in the named volume. To roll back a release, check out the previous commit and rebuild. Do not restore a database backup unless the new release changed the schema incompatibly.

## 9. What to record

- Commit hash and image digest
- Compose output of `ps`
- Status code and body of both probes
- Header dump
- Result of the rate limit loop
- Backup path and checksum
- Any console error seen in the browser

Attach these to the staging sign off. Until then the deployment remains NOT VERIFIED.
