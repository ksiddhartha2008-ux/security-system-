# Backup and recovery guide

## Status

| Item | Status |
| --- | --- |
| Backup tool with integrity check and checksum | IMPLEMENTED, TESTED |
| Restore tool with checksum and integrity verification | IMPLEMENTED, TESTED |
| Restore rehearsal | TESTED locally against the sanitized demo database |
| Scheduled off site backup | NOT IMPLEMENTED, operational task |
| Encryption at rest | NOT IMPLEMENTED, depends on the storage layer |

## 1. What must be backed up

| Path | Contents | Notes |
| --- | --- | --- |
| `<SF_DATA_DIR>/secureflow.db` | all tenant data, audit chain, sessions | the database |
| `<SF_DATA_DIR>/evidence/` | sealed evidence files | not in the database, must be copied with it |
| `.env` or the secret manager export | provider keys, bootstrap values | never in the same backup as the database |

The backup tool covers the database. Evidence files are copied with the object storage or volume snapshot of the same host, and their hashes are in the database, so a restore can detect a mismatch.

## 2. Procedure

```bash
node backend/scripts/backup.mjs \
  --source /data/secureflow.db \
  --out-dir /data/backups \
  --label nightly \
  --keep 7
```

The tool:

1. checkpoints the write ahead log
2. creates a consistent copy with `VACUUM INTO`
3. runs `PRAGMA integrity_check` on the copy
4. writes a SHA-256 sidecar file
5. removes older backups beyond the retention count

Output is JSON with the path, checksum, size, integrity result and how many old files were pruned.

## 3. Verify a backup

```bash
node backend/scripts/backup.mjs --verify --backup /data/backups/secureflow-2026-11-13T02-00-00-000Z-nightly.db
```

It compares the checksum sidecar and runs an integrity check. Exit code 1 means the file must not be used.

## 4. Restore

```bash
node backend/scripts/backup.mjs \
  --backup /data/backups/secureflow-2026-11-13T02-00-00-000Z-nightly.db \
  --target /data/secureflow.db \
  --force
```

Behaviour:

- refuses to run if the checksum or integrity check fails
- refuses to overwrite an existing database without `--force`
- writes to a staging file, verifies it, keeps the previous database beside it as `<target>.pre-restore-<timestamp>`
- moves the verified file into place

Stop the API before restoring. Sessions are stored in the database, so a restore also restores the sessions that existed at backup time. If that is not wanted, delete the `sessions` rows after the restore.

## 5. Tested evidence

`backend/tests/backup.test.mjs`:

1. a backup is written, hashed and passes an integrity check
2. a restore reproduces the same organization, user and incident counts as the source
3. a tampered checksum blocks the restore
4. an existing target is not overwritten without force, and a safety copy is kept when forced
5. retention keeps only the requested number of backups

Run subset:

```
node --test backend/tests/backup.test.mjs
```

Result on 13 November 2026: 5 tests, 5 passed.

## 6. Objectives

| Measure | Target | Basis |
| --- | --- | --- |
| RPO | 24 hours | nightly backup; lower requires WAL shipping or a managed database |
| RTO | 1 hour | copy and verify a database of this size; measured restore of the demo database takes under a second |
| Retention | 7 daily, 4 weekly, 12 monthly | operational policy; the tool only enforces the local count |

These are targets, not measurements from a production incident.

## 7. Encryption and off site copies

- Encrypt the backup before it leaves the host, for example with `age` or the storage provider's server side encryption.
- Keep at least one copy outside the host and outside the same cloud region.
- Restrict access to the backup directory to the service account.
- A backup that has never been restored is not a backup; schedule a monthly restore rehearsal into a scratch directory and run the verification command.

## 8. Limitations

- SQLite is single node. The backup is consistent for that node; it is not a replication strategy.
- Evidence files are not included by this tool.
- The restore procedure replaces the whole database. There is no partial table restore.
- A PostgreSQL deployment would need `pg_dump` and point in time recovery instead; that path is not implemented.
