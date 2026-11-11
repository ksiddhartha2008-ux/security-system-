# secureflow-sdk-node

Server side Node.js SDK for SecureFlow AI website protection. It sends the events your application chooses to report to the SecureFlow ingestion API. Nothing is captured automatically except a heartbeat.

The package is private to this repository. It is not published to a registry.

## Requirements

- Node.js 24 or newer. This is the only version the test suite ran on.
- An API key created for a verified website in the SecureFlow dashboard.
- Outbound HTTPS from the website server to the SecureFlow ingestion endpoint.

## Install

```bash
npm install /path/to/secureflow-sdk-node
```

Or copy `src/index.js` into your project. It has no runtime dependencies and uses the built in `fetch`, `crypto` and `timers`.

## Configure

```js
import { SecureFlow } from 'secureflow-sdk-node';

const sf = new SecureFlow({
  apiKey: process.env.SECUREFLOW_API_KEY,
  endpoint: 'https://your-secureflow-host/v1/ingest/website-events',
  actorIdMode: 'hash',
  actorPepper: process.env.SECUREFLOW_ACTOR_PEPPER,
});
```

| Option | Default | Meaning |
|---|---|---|
| `apiKey` | required | Key created in the dashboard. It must stay on the server. |
| `endpoint` | required | HTTPS ingestion URL. Plain HTTP is accepted only for localhost in development with `allowInsecureEndpoint: true`. |
| `flushIntervalMs` | `5000` | How often the queue is sent. |
| `maxBatchSize` | `50` | Events per request, 1 to 100. |
| `maxQueueSize` | `1000` | In memory bound. On overflow the oldest event is dropped and counted. |
| `requestTimeoutMs` | `5000` | One request, including a retry attempt. |
| `actorIdMode` | `hash` | `hash`, `raw` or `omit`. |
| `actorPepper` | none | Required for `hash`. At least 16 bytes. Keep it on the server. |
| `heartbeatIntervalMs` | `900000` | Heartbeat period. It also reports dropped and queued counts. |
| `onError` | none | Receives an `Error`. The SDK never throws into the host. |

## Login route example

```js
const context = sf.requestContext(req);
sf.track({
  type: 'auth.login_failed',
  actor: { id: req.body.email, id_mode: 'hash' },
  client: { ip: context.ip, user_agent: context.user_agent },
  request: { host: context.host, method: context.method, path: context.path, status: 401 },
});
```

Call `track()` from your existing handler before you send the response. It is synchronous, writes to an in memory queue and returns immediately. For a successful sign-in send `auth.login_succeeded` with the same shape.

Access denied paths:

```js
sf.track({
  type: 'access.denied',
  actor: { id: req.user?.id ?? 'anonymous', id_mode: 'hash' },
  client: { ip: req.ip, user_agent: req.get('user-agent') },
  request: { host: req.hostname, method: req.method, path: req.path, status: 403 },
});
```

## Client addresses behind a proxy

`requestContext()` reads `req.ip`. Express returns the socket address unless `trust proxy` is configured. Behind a load balancer or CDN, set `app.set('trust proxy', 1)` or the equivalent for your platform, and make sure the proxy overwrites `X-Forwarded-For` rather than appending untrusted values. If the SDK reports private addresses, the SecureFlow dashboard raises a health warning, because IP based detection becomes unreliable.

## Privacy

- No request or response bodies are sent.
- No cookies or authorization headers are sent.
- Query strings and fragments are removed from paths.
- Fields named `password`, `secret`, `token`, `authorization`, `cookie`, `api_key`, `session`, `card`, `cvv` and `ssn` are dropped before sending.
- Actor identifiers are hashed with HMAC-SHA-256 using your pepper when `actorIdMode` is `hash`. The pepper never leaves your server.

## Errors and delivery

- Network errors, `429` and `5xx` are retried with exponential backoff, jitter and `Retry-After`. At most five attempts per batch.
- Other `4xx` responses are not retried. The batch is dropped and reported through `onError`.
- After five consecutive failed batches the SDK pauses sending for 60 seconds.
- Queue overflow drops the oldest event. The count is reported in the next heartbeat as `attributes.dropped`.

## Shutdown

```js
await sf.shutdown({ timeoutMs: 5000 });
```

It stops accepting events, flushes within the deadline and releases timers. Call it from your process signal handler.

## HTTP API for other languages

```http
POST /v1/ingest/website-events
Authorization: Bearer sfk_<key id>_<secret>
Content-Type: application/json

{
  "schema_version": 1,
  "sdk": { "name": "your-agent", "version": "1.0.0" },
  "sent_at": "2026-11-11T09:00:00Z",
  "events": [
    {
      "event_id": "0b6f3b6e-6a43-4a3b-8f3e-2a2e8f1f9c11",
      "type": "auth.login_failed",
      "occurred_at": "2026-11-11T08:59:58Z",
      "actor": { "id": "hashed-or-raw", "id_mode": "hash" },
      "client": { "ip": "203.0.113.10", "user_agent": "Mozilla/5.0 (example)" },
      "request": { "host": "shop.example.com", "method": "POST", "path": "/login", "status": 401 },
      "attributes": { "reason": "bad_password" }
    }
  ]
}
```

`202` means the batch was stored. The response reports `accepted`, `duplicates`, `rejected` and `dropped_fields`. A `401` means the key is unknown, revoked or expired. A `403` means the website is not verified. A `429` includes `Retry-After`.

## Tests

```bash
npm test
```

The suite starts a local HTTP server; it never contacts a real SecureFlow deployment or a customer website.
