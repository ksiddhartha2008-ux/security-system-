# Event mapping

The SDK sends a small, fixed vocabulary. The server validates it and stores it in `security_events` using the existing model. This file is the contract between the two.

## Envelope

```json
{
  "schema_version": 1,
  "sdk": { "name": "secureflow-sdk-node", "version": "0.1.0" },
  "sent_at": "2026-11-11T09:00:00Z",
  "events": []
}
```

Unknown envelope fields, a different `schema_version`, more than 100 events, or any `__proto__`, `constructor` or `prototype` key rejects the whole batch with `400 invalid_batch`.

## Types

| SDK type | Stored `event_type` | Category | Outcome | Required fields |
| --- | --- | --- | --- | --- |
| `auth.login_failed` | `auth.failure` | identity | failure | `client.ip` |
| `auth.login_succeeded` | `auth.success` | identity | success | `client.ip`, `actor.id` |
| `auth.password_reset_requested` | `auth.password_reset` | identity | unknown | `client.ip` |
| `auth.mfa_failed` | `auth.mfa_failure` | identity | failure | `client.ip`, `actor.id` |
| `auth.signup` | `auth.signup` | identity | success | `client.ip` |
| `access.denied` | `authz.denied` | application | failure | `client.ip`, `request.path` |
| `request.suspicious` | `web.suspicious_request` | application | unknown | `client.ip`, `request.path`, `attributes.category` |
| `request.rate_limited` | `api.rate_limit` | application | unknown | `client.ip` |
| `app.error` | `app.error` | application | failure | `request.path`, `attributes.error_class` |
| `sdk.connectivity_test` | `sdk.connectivity_test` | application | success | none |
| `sdk.heartbeat` | `sdk.heartbeat` | application | unknown | none |

`attributes.category` must be one of `sqli`, `xss`, `path_traversal`, `scanner`, `bad_bot`, `other`. `access.denied` with a status present must use 401 or 403. `app.error` accepts `error_class` only; stack and message keys are rejected.

## Stored row

| Column | Value |
| --- | --- |
| `id` | Server generated `evt_` identifier |
| `event_type` | The stored type in the table above |
| `source` | `secureflow-sdk` |
| `severity` | Always `info`. Severity of a detection is computed by rules, never by the client |
| `category` | From the table above |
| `title` | Fixed label, for example `Failed sign-in` |
| `description` | Type and the verified website hostname |
| `src_ip` | `client.ip` when it parsed as an address |
| `user_email` | `actor.id`, hashed or raw according to the customer's SDK mode |
| `asset_id` | The website asset created at verification |
| `raw` | The validated event plus `ip_class`, `received_at` and the SDK block |
| `occurred_at` | Client timestamp, inside the accepted window |
| `created_at` | Server receive time |
| `trust_level` | `server_sdk` |
| `website_site_id` | The site resolved from the API key |
| `dedupe_key` | `wsite:<site id>:<event id>` |

`raw.request.path` never contains a query string or fragment. `raw.client.user_agent` is stripped of control characters and truncated to 256 characters.

## Validation limits

| Field | Rule |
| --- | --- |
| `event_id` | UUID v4 or ULID, unique per site |
| `occurred_at` | RFC 3339 UTC, from 7 days ago to 5 minutes ahead |
| `actor.id` | At most 128 characters, no control characters |
| `actor.id_mode` | `hash`, `raw` or `omit` |
| `client.ip` | IPv4 or IPv6. An invalid value is dropped and counted, not fatal |
| `client.user_agent` | Control characters stripped, 256 characters |
| `request.host` | Must match the site hostname, or the registrable domain for domain scope |
| `request.method` | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS |
| `request.path` | Starts with `/`, at most 512 characters, query and fragment removed |
| `request.status` | Integer 100 to 599 |
| `attributes` | At most 20 flat keys, `^[a-z][a-z0-9_.]{0,63}$`, string 512, finite number or boolean |

Sensitive attribute keys are dropped on both sides: `password`, `passwd`, `secret`, `token`, `authorization`, `cookie`, `set-cookie`, `api_key`, `apikey`, `session`, `card`, `cvv`, `ssn`.

## Batch limits

Body 256 KiB, 100 events, JSON depth 6, 600 events per minute per key, 100,000 events per day per site. Duplicate `(site, event_id)` pairs are counted in `duplicates` and stored once. Rejected events are listed with their index, event id and code. A rejected event never consumes a row, but it does consume rate budget, which is deliberate: a key that sends garbage still costs the platform work.

## Codes returned per event

`unknown_event_type`, `invalid_event_id`, `invalid_timestamp`, `timestamp_out_of_range`, `invalid_actor`, `invalid_actor_mode`, `invalid_client`, `invalid_request`, `invalid_method`, `invalid_path`, `invalid_status`, `invalid_attributes`, `too_many_attributes`, `invalid_attribute_key`, `invalid_category`, `host_mismatch`, `missing_field`, `forbidden_key`, `unknown_field`, `invalid_event`.

`unknown_field` and `forbidden_key` are event level when they appear inside one event, and batch level when they appear at the envelope.
