# IP Shield: real addresses, masking, pseudonyms and origin evidence

IP Shield has two separate jobs. Conflating them is how projects end up claiming
that a fake address hides a real one.

1. **Origin protection**: keep the real origin reachable only through a trusted
   proxy, and record what is actually configured.
2. **Source IP privacy**: show masked addresses by default, correlate with a
   keyed pseudonym, and keep the original in an authenticated-encryption vault
   that only an administrator can open, with a reason and an audit entry.

## Real addresses only

Discovery has exactly two sources:

| Source | Function | Recorded metadata |
| --- | --- | --- |
| Local interfaces | `os.networkInterfaces()` | `discovery_source = os.networkInterfaces`, hostname, interface name |
| Configured HTTPS endpoint | `SF_PUBLIC_IP_URL`, 4 second timeout, HTTPS only, must return a public address | `discovery_source = public-ip-service`, note: "Public service answer, not verified as the origin address" |

There is no code path that invents, mirrors or randomises an address. If neither
source yields anything, the table stays empty and the page shows an empty state.

An address observed on a local interface is verified as *present on this host*.
It is not proof that it is the public origin. Only a provider read-back or a
controlled connection test can show that, and neither exists here, so the origin
protection card reports configuration evidence rather than a claim.

## Classification

`classifyAddress` returns `null` for invalid input and a scope otherwise:

| Scope | Examples | Blockable |
| --- | --- | --- |
| `public` | `93.184.216.34` | Yes, after approval |
| `private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7` | No |
| `loopback` | `127.0.0.0/8`, `::1` | No |
| `link_local` | `169.254.0.0/16`, `fe80::/10` | No |
| `multicast` | `224.0.0.0/4`, `ff00::/8` | No |
| `reserved` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`, `::` | No |

Blocking additionally refuses addresses on the organisation allowlist, anything
marked management, and any address SecureFlow itself discovered on this host.
That last rule is what stops the product from firewalling the machine it runs on.

## Masking

| Family | Input | Displayed |
| --- | --- | --- |
| IPv4 | `192.168.1.45` | `192.168.1.xxx` |
| IPv6 | `2001:db8:1:2::5` | `2001:db8:1:xxxx:xxxx` |

Masked values are the only form returned by list endpoints, agent summaries and
incident context.

## Pseudonymous fingerprint

```
fingerprint = "ipfp_" + HMAC-SHA-256(key[version], canonical_address)[0..31]
```

- Keyed. Plain SHA-256 is never used on its own, because the IPv4 space is small
  enough to enumerate.
- Stable within a key version, so events from the same source correlate.
- Versioned. The version is returned with the fingerprint and stored next to it,
  so a rotation does not silently break correlation.
- Keys come from `SF_IP_HMAC_KEYS` as a JSON object of version to base64 encoded
  32 byte secret, `{"v2":"...","v1":"..."}`, with `SF_IP_KEY_VERSION` naming the
  active version. `SF_IP_HMAC_KEY` is a single key fallback used only when the
  plural variable is empty. An unparsable keyring is treated as no key, never as
  a silent fallback.

Rotating a fingerprint key: add the new version to the JSON object, point
`SF_IP_KEY_VERSION` at it, restart, keep the old key for as long as old records
must remain correlatable, then remove it.

## Vault

AES-256-GCM, 12 byte random nonce per record, authentication tag stored with the
ciphertext, key version stored with the record. Key material is environment only
(`SF_IP_VAULT_KEYS`, same JSON shape, or `SF_IP_VAULT_KEY`). Segregation:

| Rule | Implementation |
| --- | --- |
| Key never in the database | Keys are read from the environment at call time. |
| Nonce uniqueness | 12 random bytes per encryption. |
| Tamper detection | GCM tag failure throws; the test mutates the ciphertext and expects a throw. |
| Reveal is restricted | `POST /ip/:id/reveal` requires the admin role, a reason of 6 to 300 characters, and is rate limited to 10 per minute, fail closed. |
| Reveal is audited | `trishield.ip.revealed` with the reason and key version. |
| Normal views stay masked | List endpoints never include the raw address. |

Rotating a vault key requires re-encrypting stored records. There is no automatic
re-encryption job in this checkout. Procedure: add the new version, keep the old
one, decrypt and re-encrypt with a one-off script, verify a sample, then remove
the old key. Until that script runs, old records stay readable with the old key.

## Origin protection evidence

`originProtectionStatus()` reports four booleans and nothing more:

| Field | True when |
| --- | --- |
| `reverseProxyConfigured` | `SF_PUBLIC_ORIGIN` is set or `SF_TRUST_PROXY=true` |
| `trustedProxy` | `SF_TRUST_PROXY=true` |
| `publicIpDiscoveryConfigured` | `SF_PUBLIC_IP_URL` is set |
| `originHostnameConfigured` | `SF_ORIGIN_HOSTNAME` is set |

These are configuration facts. They do not prove the origin is unreachable
directly. Proving that requires an external probe from outside the network, which
is a deployment acceptance step, not an application feature.

## Known limits

- Direct-origin requests are not detected. There is no log analysis of a proxy
  bypass in this checkout.
- There is no automatic key rotation. Rotation is an operator procedure.
- Reveal writes an audit entry; it cannot prevent an administrator from copying
  the value afterwards.
- A public IP service answer is explicitly labelled unverified origin.
