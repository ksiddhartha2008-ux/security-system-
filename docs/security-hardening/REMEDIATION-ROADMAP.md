# SecureFlow AI: security hardening roadmap

Source: [BASELINE-AUDIT.md](BASELINE-AUDIT.md) at commit `b0aeb52`.
This roadmap orders work by actual risk and by dependency, not by category. No
item here is implemented yet.

## First five fixes (next phase)

| Order | Finding | Why first | Effort | Dependency |
| --- | --- | --- | --- | --- |
| 1 | SF-AUTH-01 Enforce MFA for administrators | One stolen admin password currently leads to full workspace and firewall approval rights | S | None; MFA already exists |
| 2 | SF-AUTH-06 Stop registration enumeration | Small change, removes a free address oracle used for phishing | S | None |
| 3 | SF-BKP-01 Encrypt backups and audit backup access | A copied backup is an offline copy of hashes, sessions and audit records | M | Secret store or key file outside the database |
| 4 | SF-AUTH-04 Session hardening | Shortens the replay window after cookie theft and removes the `NODE_ENV` trap | M | None |
| 5 | SF-UPL-01 Require a scanner or block unscanned downloads in production | Evidence files are opened by analysts; an unset scanner currently stores `not_scanned` | M | ClamAV host, or a product decision to quarantine unscanned files |

These five are independent of any external provider except ClamAV and the backup
key. They can ship without changing the database schema.

> Completed on 16 November 2026: item 1, SF-AUTH-01 administrator MFA
> enforcement, and item 2, SF-AUTH-06 registration enumeration. See
> [PHASE-1.1-ADMIN-MFA.md](PHASE-1.1-ADMIN-MFA.md) and
> [PHASE-1.2-REGISTRATION-ENUMERATION.md](PHASE-1.2-REGISTRATION-ENUMERATION.md).
> The other three remain open.

## Phase 1: access and account lifecycle

| Item | Findings | Scope | Required tests | Risk if deferred |
| --- | --- | --- | --- | --- |
| 1.1 Admin MFA enforcement | SF-AUTH-01 | Server guard on privileged routes, enrollment gate on role assignment, UI banner | Admin without MFA refused on approve/execute/key/policy; enrolled admin succeeds | High |
| 1.2 Registration enumeration | SF-AUTH-06 | Neutral response for existing addresses, keep 6/hour limit | Same status and body for both cases; no duplicate account | Medium |
| 1.3 Email verification | SF-AUTH-02 | Token table, expiry, resend limit, audit event. **Blocked on a mail provider decision** | Token expiry, replay, audit, unverified restrictions | Medium |
| 1.4 Password reset | SF-AUTH-03 | Hashed single-use token, constant response, session revocation. **Blocked on mail** | Unknown email identical, single use, sessions revoked | Medium |
| 1.5 Session hardening | SF-AUTH-04 | Idle timeout, `Secure` behind trusted proxy, optional `__Host-` prefix, IP/UA change event | Idle expiry, secure flag, rotation, revocation | Medium |

Mail delivery is the only hard dependency. Without it, items 1.3 and 1.4 stay
BLOCKED and the manual admin reset path must be documented instead.

## Phase 2: data at rest and recovery

| Item | Findings | Scope | Required tests | Risk if deferred |
| --- | --- | --- | --- | --- |
| 2.1 Encrypted backups | SF-BKP-01 | Encrypt with a key from the deployment secret store, audit create/download/restore, document restore drill | Keyless restore fails; tamper detected; retention intact | High |
| 2.2 Database at rest | SF-DB-01 | `PRAGMA secure_delete`, file mode check, host disk encryption requirement, vault key separation | Pragma asserted; deleted row not recoverable; vault requires key | Medium |
| 2.3 Migration safety | SF-DB-02 | Pre-migration backup, upgrade test from each version, documented forward-fix path | Upgrade on a copy; failed migration leaves a usable database | Medium |
| 2.4 Audit checkpoint | SF-AUD-01 | Export the chain head to an append-only sink, sign checkpoints, document the trust boundary | Tamper detected without a new anchor; append verifies | Medium |
| 2.5 Clipboard of secrets | SF-LOG-01 | Structured logs with code and request id, stack to a protected sink | No password/token in logs; request id present | Low |

## Phase 3: platform hardening

| Item | Findings | Scope | Required tests | Risk if deferred |
| --- | --- | --- | --- | --- |
| 3.1 Password hash upgrade | SF-AUTH-05 | Argon2id or scrypt N=2^17, parameter metadata, rehash on login | Old hash verifies, new hash uses new params, rehash once | Medium |
| 3.2 Shared rate limits | SF-RL-01 | Require Redis in multi-instance, startup error when missing in production | Two-instance counter, outage behaviour | Medium |
| 3.3 Upload scanner policy | SF-UPL-01 | Require ClamAV in production or block unscanned downloads; record engine and signature version | No scanner blocks; infected rejected; clean stored with version | Medium |
| 3.4 API key rotation | SF-KEY-01 | Expiry defaults, overlap window, rotation reminder | Old and new key overlap, old key revoked after window | Low |
| 3.5 Configurable thresholds | SF-MON-01 | Per-organisation rule thresholds with audit | Threshold change audited; rule fires at new value | Low |
| 3.6 Broader secret scan | SF-SEC-01 | Entropy scan plus pre-commit hook | Known token shapes detected; false positives documented | Low |

## Phase 4: infrastructure-dependent verification

| Item | Findings | Dependency | What must be true before claiming success |
| --- | --- | --- | --- |
| 4.1 nftables enforcement | SF-TRI-01 | Linux host with `nft`, `CAP_NET_ADMIN` | Table, sets, drop rules installed; block and rollback read back from the kernel |
| 4.2 Cloudflare firewall | SF-TRI-01 | Account token with access-rule permission | Rule created, listed, verified and deleted against the real API |
| 4.3 Suricata feed | SF-TRI-01 | Sensor sending EVE JSON | Events arrive, dedupe works, collector shows VERIFIED |
| 4.4 Wazuh manager | SF-TRI-01 | Manager URL and read-only user | Authenticate, manager info, agent list returned |
| 4.5 ClamAV scanner | SF-TRI-01 | clamd on a private network | VERSION returns engine and signatures; infected file rejected |
| 4.6 Database audit monitoring | SF-DB-03 | Database audit export or log shipper | Database events arrive and detection rules fire on real records |
| 4.7 AI analysis | SF-AI-01 | Model provider and redaction pipeline | Output labelled analysis, cannot approve actions, redaction tested |

## Sequencing rules

1. Do not start Phase 4 while Phase 1 admin MFA is open.
2. Do not enable automatic firewall policy while SF-AUTH-01 and SF-AUD-01 are open.
3. Do not enable multi-instance deployment while SF-RL-01 is open.
4. Do not accept customer evidence uploads in production while SF-UPL-01 is open.
5. Re-run the baseline audit after each phase; findings that change status need
   new evidence, not a rewritten history.

## Definition of done per item

- Code reviewed and merged on `main`.
- Regression tests added and passing in CI.
- Documentation updated with the new behaviour and its limits.
- Finding status changed only when the evidence supports it.
- No existing control removed to make the change pass.
