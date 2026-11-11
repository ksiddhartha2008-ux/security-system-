# HTTP API for other languages

The Node SDK is a convenience wrapper around this endpoint. Any language can post the same envelope.

## Endpoint

```
POST /api/v1/ingest/website-events
Authorization: Bearer <website key>
Content-Type: application/json
```

The key is created in the dashboard after DNS verification. It is shown once. Send it in the header only. Keys in a query string or a cookie are refused, and the endpoint ignores cookies entirely.

## Request

```json
{
  "schema_version": 1,
  "sdk": { "name": "acme-agent", "version": "1.2.0" },
  "sent_at": "2026-11-11T09:00:00Z",
  "events": [
    {
      "event_id": "0b6f3b6e-6a43-4a3b-8f3e-2a2e8f1f9c11",
      "type": "auth.login_failed",
      "occurred_at": "2026-11-11T08:59:58Z",
      "actor": { "id": "sha256-or-raw-identifier", "id_mode": "hash" },
      "client": { "ip": "203.0.113.10", "user_agent": "Mozilla/5.0 (example)" },
      "request": { "host": "shop.example.com", "method": "POST", "path": "/login", "status": 401 },
      "attributes": { "reason": "bad_password" }
    }
  ]
}
```

`event_id` must be a UUID v4 or a ULID and must be stable across retries. Generate it once per event, not once per attempt.

## Response

Stored, including duplicates:

```json
{
  "accepted": 1,
  "duplicates": 0,
  "rejected": [],
  "dropped_fields": 0
}
```

Status `202`. Re-sending the same batch is safe: the second response reports `accepted: 0` and `duplicates: 1`.

Rejected events:

```json
{
  "accepted": 0,
  "duplicates": 0,
  "rejected": [{ "index": 0, "event_id": "…", "code": "host_mismatch" }],
  "dropped_fields": 2
}
```

## Errors

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_batch` | Envelope, JSON or size problem. Nothing was stored |
| 401 | `invalid_api_key` | Missing, malformed, unknown, revoked or expired key |
| 403 | `site_not_verified` | The key is valid but the website is not verified or has lapsed |
| 413 | `payload_too_large` | Body above 256 KiB |
| 415 | `unsupported_media_type` | Not `application/json`, or a content encoding other than identity |
| 429 | `rate_limited` | Per key or per site limit. `Retry-After` in seconds |
| 503 | `service_unavailable` | The batch could not be stored. Retry with `Retry-After` |

A `5xx` never means "stored". Retry the batch with the same event ids.

## Retry guidance

- Retry `429`, `5xx` and network errors with exponential backoff and jitter.
- Honour `Retry-After`.
- Do not retry other `4xx` responses without changing the payload.
- Five attempts, then drop the batch and record the failure locally.

## Limits

- 256 KiB per request.
- 100 events per request.
- 600 events per minute per key.
- 100,000 events per day per site.
- Timestamps accepted from 7 days ago to 5 minutes ahead.

## Privacy

Send identifiers you are allowed to send. Prefer a keyed hash (`actor.id_mode = "hash"`) computed on your server with a pepper you keep. Do not send request bodies, cookies, authorization headers or form values. The server drops attributes named like credentials, but it is cheaper and safer not to send them.

## Minimal client

```js
async function send(events) {
  const response = await fetch('https://your-secureflow-host/api/v1/ingest/website-events', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${process.env.SECUREFLOW_API_KEY}`,
    },
    body: JSON.stringify({
      schema_version: 1,
      sdk: { name: 'my-agent', version: '1.0.0' },
      sent_at: new Date().toISOString(),
      events,
    }),
  });
  if (!response.ok && response.status !== 429) throw new Error(`ingest failed: ${response.status}`);
  return response.json();
}
```
