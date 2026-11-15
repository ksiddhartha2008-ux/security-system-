# TriShield operations

## Safe defaults

| Setting | Default | Effect |
| --- | --- | --- |
| `TRISHIELD_FIREWALL_APPLY` | `false` | No provider change is issued. `execute` refuses with 409 and nothing is touched. |
| `TRISHIELD_AUTO_APPLY` | `false` | The automatic policy can still propose, but it stops for approval. |
| Auto block policy | disabled, mode `approval` | No proposal is created until an administrator enables it. |
| `TRISHIELD_MAX_RULES` | `500` | Proposal is refused once the active rule ceiling is reached. |
| Cloudflare credentials | unset | Connector reports UNAVAILABLE. |
| IP keys | unset | Addresses are listed masked, no fingerprint, no vault. |
| Collector tokens | none | Ingestion is refused with 401. |

Nothing above has to be true for the application to start. The trade is that a
deployment without keys shows masked addresses and unconfigured integrations
instead of inventing data.

## Isolated firewall verification

Real enforcement is verified only on a disposable Linux host. This checkout is
Windows without WSL, Docker or `nft`, so the live run is BLOCKED here. The runner
is committed and refuses to act unless every safety condition holds.

```bash
# On a throwaway Linux VM or container, as root, with nft installed:
TRISHIELD_ISOLATED=1 npm run check:firewall -- --apply
# or directly:
TRISHIELD_ISOLATED=1 node scripts/trishield-firewall-check.mjs --apply
```

What it proves, in order, and what each step reads from the kernel:

1. `nft --version` resolves.
2. Health before provisioning reports a precise state, not a false success.
3. The target is public and not protected.
4. Execution before approval is refused.
5. Approval then execution returns `succeeded` with a verification payload.
6. A verified `firewall_rules` row is `active`.
7. `nft list set inet trishield_check blocked_v4` shows the element.
8. `nft list chain inet trishield_check input` shows the drop rule.
9. Health after provisioning is ok.
10. Rollback returns `rolled_back` and the element disappears.
11. A short expiry installs an element that carries a timeout.
12. A private address cannot be proposed.
13. The check table is deleted, even when an earlier step failed.

The runner uses `inet trishield_check`, not the production `inet secureflow`
table, and deletes it in a `finally` block. Exit code 0 means every check passed.
Exit 2 means it refused to run. Exit 1 means at least one check failed and the
printed line names it.

A container run needs `--cap-add=NET_ADMIN`, or `--privileged` in a disposable
container, plus an `nft` binary. Nothing in this repository ships a privileged
container by default.

## Integration checks

The TriShield page has an Integrations tab, the Integration Setup Center. Each card
shows Configuration, Connection and Verification separately, the last check, the
last success and failure, the latency, the version, the recorded history, the exact
missing requirements and the next action.

`Test connection` calls `POST /api/trishield/health/:key/check`. It runs the real
check for that integration and writes the result, the latency and the provider
version to `trishield_health_checks`. The action is administrator only, rate
limited to 20 per minute, and audited.

What a check can honestly return on this machine:

| Integration | Expected result here |
| --- | --- |
| Linux nftables | UNAVAILABLE, because the platform is Windows |
| Cloudflare | NOT CONFIGURED, because no token is set |
| Suricata, WAF | NOT CONFIGURED, because no collector exists |
| Wazuh | NOT CONFIGURED, because no API URL or collector exists |
| ClamAV | NOT CONFIGURED, because no host is set |

A result of ERROR is not a bug. It means the provider was asked and refused, and
the message is shown to the administrator.

## Suricata tailer

On the sensor host:

```bash
node scripts/trishield-eve-tail.mjs \
  --file /var/log/suricata/eve.json \
  --url https://secureflow.example \
  --token tsk_xxx \
  --follow
```

The tailer stores its byte offset next to the file, so a restart does not replay
old events. `--once` reads the current file and exits, `--all` sends every event
type instead of alerts only, `--dry-run` prints the batches without sending them.

## Deployment sequence

1. Run the production configuration check. It errors when live firewall changes
   are enabled without an IP fingerprint key, or when `SF_PUBLIC_IP_URL` is not
   HTTPS.
2. Set `SF_IP_HMAC_KEYS` and `SF_IP_VAULT_KEYS` as JSON objects of version to
   base64 32 byte secret, and `SF_IP_KEY_VERSION`.
3. Start the API and sign in as an administrator.
4. Open TriShield, press `Discover IPs`, and confirm the listed addresses match
   the host you deployed on.
5. Add the management network and any partner ranges to the allowlist before
   enabling anything.
6. Configure a provider, then press `Check firewall`. ACTIVE here means the
   provider answered and the required table, sets and drop rules are present.
7. Keep `TRISHIELD_FIREWALL_APPLY=false` until the isolated runner passes on a
   disposable host. Then enable it in staging first.
8. Create a collector, copy the token once, and point the agent at
   `/api/trishield/ingest/<kind>`.

Do not enable the automatic policy before the manual approval path has been used
at least once end to end.

## Rollback

| Situation | Action |
| --- | --- |
| A verified block is wrong | Approve nothing further. Use `Rollback` on the action. The provider removes the rule and the recorded rule becomes `removed`. |
| The provider is unreachable during rollback | Fix the provider first. The action stays `succeeded`; rollback refuses until the provider confirms. |
| A rule was applied outside SecureFlow | Remove it with the provider's own tooling. SecureFlow only tracks rules it applied. |
| The nftables table must be removed entirely | `nft delete table inet secureflow`. This removes every SecureFlow block, and the next health check reports ERROR until rebuilt. |
| A collector token leaked | Revoke the collector. Ingestion returns 401 immediately. Create a new collector and update the agent. |
| A vault key leaked | Rotate: add a new version, re-encrypt, remove the old version. Until re-encryption runs, old records need the old key. |
| The API must stop making changes | Set `TRISHIELD_FIREWALL_APPLY=false` and restart. Execution refuses with 409. Existing provider rules stay in place, so remove them with the provider if required. |

## Troubleshooting

| Symptom | Cause | Check |
| --- | --- | --- |
| Provider shows UNAVAILABLE | Platform or credentials missing | `GET /api/trishield/firewall/status` shows `detail`. |
| Provider shows ERROR | Last health check failed | `detail` holds the provider message, truncated to 200 characters. |
| Execute returns 409 with "apply is disabled" | `TRISHIELD_FIREWALL_APPLY` is not true | Set it and restart, or keep the rule unapplied. |
| Execute returns 409 with "Firewall change failed" | The provider refused or did not confirm | The action is `failed` with `error`. No rule was recorded. |
| Execute returns 403 `recent_auth_required` | Permanent change without recent sign-in | Re-authenticate, then execute. |
| Approve returns 409 | The action is not `awaiting_approval`, or it expired | Refresh the queue. |
| Ingest returns 401 | Missing, unknown or revoked token | Create a collector and use the token shown once. |
| Ingest returns 403 | Token kind mismatch | Use the collector created for that kind. |
| Collector says CONNECTED - NO RECENT EVENTS | No event in 15 minutes | Check the agent and the token. |
| Addresses page is empty | Discovery not run, or no interfaces matched | Press `Discover IPs`. On a container with only loopback, expect one loopback entry. |
| Fingerprint shows "key not configured" | `SF_IP_HMAC_KEYS` or `SF_IP_HMAC_KEY` missing | Set a base64 32 byte secret and restart. |
| Reveal returns 404 | The address has no vault record | Vault keys were not configured at discovery time. Run discovery again after setting keys. |

## Isolated test without a firewall

The service layer can be exercised on any platform with a fake transport. That is
what `backend/tests/trishield.test.mjs` does: it asserts the exact argument
vectors, the drop rule installation, the timeout element, protected address
refusal, approval gating, idempotency and rollback. It is labelled as an
emulator, not as enforcement.

## Retention

`firewall_actions` and `firewall_rules` are kept with the rest of the security
records. The demo snapshot exporter purges `infra_addresses`, `ip_vault`,
`trishield_allowlist`, `firewall_rules`, `firewall_actions`, `endpoint_agents`
and `trishield_collectors` so real host addresses and token hashes never leave
the machine in a shared fixture.
