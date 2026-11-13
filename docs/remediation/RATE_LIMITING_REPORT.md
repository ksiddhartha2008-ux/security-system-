# Rate limiting report

## Status

| Item | Status |
| --- | --- |
| Shared store abstraction | IMPLEMENTED, TESTED |
| Redis implementation with atomic increment and TTL | IMPLEMENTED, TESTED against a real server in CI |
| Memory implementation for single process use | IMPLEMENTED, TESTED |
| Response headers and accurate Retry-After | IMPLEMENTED, TESTED |
| Redis outage behaviour | IMPLEMENTED, TESTED with an injected failing store |
| Multi-instance bypass check | TESTED in CI with two stores against one Redis |
| Local verification against Redis | NOT VERIFIED, no Redis server on this host |

## 1. Before

`backend/src/lib/ratelimit.js` kept a `Map` of counters in the process. Two API instances each counted separately, so a caller could alternate instances and double the allowed rate. Responses carried no rate limit headers. A 429 always said `Retry-After: 60` regardless of the real window. A restart cleared every counter.

## 2. After

`backend/src/lib/ratelimitStore.js` defines one operation: `hit(key, windowMs)` returns `{count, resetAt}`.

- Memory store: fixed window, bounded at 10,000 keys, expired entries swept on pressure.
- Redis store: one Lua script per call:

```lua
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return {current, redis.call('PTTL', KEYS[1])}
```

Increment and expiry are one atomic server side operation, so two instances cannot both believe they own the first increment.

Key design is explicit: `sf:ratelimit:<policy>:<identity>`, where identity is `user:<id>` when authenticated, `ip:<address>` otherwise, or a policy supplied key such as an API key. Authentication is never keyed by IP alone.

`backend/src/lib/ratelimit.js` adds:

- `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy` on every response.
- `Retry-After` with the real number of seconds on a 429.
- `RateLimit-Store: local-fallback` when a degraded path was used.

## 3. Policies

| Policy | Window | Max | Key | Failure mode |
| --- | --- | --- | --- | --- |
| api (global) | 60 s | 1200 | user or IP | local fallback |
| register | 1 h | 6 | IP | closed |
| login | 15 min | 12 | IP | closed |
| step-up | 10 min | 10 | user | closed |
| mfa-verify | 10 min | 20 | IP | closed |
| mfa-enable | 10 min | 20 | user | local fallback |
| mfa-disable | 10 min | 10 | user | local fallback |
| intel-lookup | 60 s | 30 | user or IP | local fallback |
| phish-scan | 1 h | 40 | user or IP | local fallback |
| website ingest | 60 s | 600 | API key (existing route limiter) | local fallback |

Login and MFA also have an independent per email failure counter in the database, so clearing an IP does not clear the account lockout.

## 4. Failure behaviour

When the store throws a `RateLimitStoreError`:

- `failMode: 'closed'` returns 503 `rate_limit_unavailable` for the sensitive policies listed above. An outage cannot silently remove the login limit.
- `failMode: 'local'` counts in a separate bounded memory store. The limit still applies per instance and the response is marked so an operator can see the degradation.

The default is `local`, configured by `SF_RATE_LIMIT_FAIL_MODE=closed` to make every policy fail closed.

## 5. Trusted proxy

Identity uses `req.ip`. Express only trusts `X-Forwarded-For` when `SF_TRUST_PROXY=true` is set, which production configuration warns about. Without it, a spoofed header cannot create a new bucket.

## 6. Tests executed

`backend/tests/ratelimit.test.mjs`, eight tests, all passing:

- allow up to the limit, refuse the next with a retry hint
- separate buckets per authenticated user behind one IP
- custom API key isolation
- two middleware instances sharing one store enforce one combined limit
- window expiry allows the caller again
- store outage falls back to a bounded local bucket and marks the response
- fail closed returns 503
- reset clears every counter

`backend/tests/ratelimit-redis.test.mjs`, two tests, skipped locally without `SF_REDIS_URL`:

- two limiter instances sharing one Redis counter refuse the fourth request regardless of which instance answers
- the Redis key expires and the counter restarts

CI runs these against a real `redis:7.4-alpine` service in the `redis` job.

## 7. Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SF_REDIS_URL` | unset | enables the Redis store; unset uses memory |
| `SF_RATE_LIMIT_PREFIX` | `sf:ratelimit:` | key namespace |
| `SF_RATE_LIMIT_FAIL_MODE` | `local` | `closed` refuses requests when the store is down |

## 8. Remaining risks

- Redis is not available on this host, so the local run used the memory store. The real server evidence comes from the CI job.
- The memory fallback is per instance. During an outage, the effective global limit is `max × instances`.
- Rate limit counters are not persisted; a Redis restart clears them. This is normal for abuse control and is documented rather than "fixed" with a database counter that would recreate the bottleneck.
- IPv6 addresses are keyed verbatim. A caller with a large IPv6 allocation can rotate addresses; the per account lockout is the control that still applies.
