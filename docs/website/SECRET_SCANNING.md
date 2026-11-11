# Secret scanning

## Key pattern

```
sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}
```

The `sfk_` prefix exists so scanners can find a leaked key. The key id (12 characters) is not secret and is safe to show in logs and dashboards. The 43 characters after the second underscore are the secret and must never be logged, stored in a browser or committed.

## Repository scan

```powershell
npm run scan:secrets
```

`scripts/check-secrets.mjs` walks the repository, skips `.git`, `node_modules`, `dist`, `data`, `.zwork` and `.env` files, and fails on:

- a value matching the website key pattern,
- a PEM private key header,
- an AWS access key id.

The command runs in CI after the test steps. It is intentionally independent of any hosted scanner so it works on a clean runner.

Manual search:

```powershell
rg -n --hidden -g '!**/node_modules/**' -g '!backend/data/**' -g '!.git/**' "sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}" .
git grep -nE "sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}"
```

## Hosted scanner configuration

If the repository is connected to gitleaks:

```toml
[[rules]]
id = "secureflow-website-key"
description = "SecureFlow website API key"
regex = '''sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}'''
tags = ["key", "secureflow"]
```

TruffleHog custom detector regex is the same pattern.

## What the application does to reduce exposure

- The secret is returned once, with `Cache-Control: no-store`.
- Only `key_id`, `last4`, a SHA-256 hash, scopes and timestamps are stored.
- Audit metadata records `keyId` and `last4`, never the key or the hash.
- The browser never writes the key to local storage, session storage or a cookie.
- The SDK keeps the key in a private class field. `toString`, `JSON.stringify` and `util.inspect` do not include it.
- The ingestion route rejects keys in a query string and never logs the URL value.
- Revocation purges the in-process validation cache immediately.

## If a key leaks

1. Open the website, **Keys**, and revoke the key. Ingestion stops immediately.
2. Create a replacement key, install it on the server and confirm the connection.
3. Review events in the exposure window for unexpected sources.
4. Check the audit log for `website.key_revoked` and record who revoked it.
5. Rotate the actor pepper only if identifiers, not just the key, may have leaked. Rotating it breaks pseudonym continuity.

The feature does not rotate keys automatically. Rotation is create the second key, deploy it, revoke the first. The two key limit exists for that overlap.
