import { createHmac, randomUUID } from 'node:crypto';

const KEY_PATTERN = /^sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}$/;
const EVENT_TYPES = new Set([
  'auth.login_failed', 'auth.login_succeeded', 'auth.password_reset_requested', 'auth.mfa_failed',
  'auth.signup', 'access.denied', 'request.suspicious', 'request.rate_limited', 'app.error',
  'sdk.connectivity_test', 'sdk.heartbeat',
]);
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const SENSITIVE = new Set([
  'password', 'passwd', 'secret', 'token', 'authorization', 'cookie', 'set-cookie',
  'api_key', 'apikey', 'session', 'card', 'cvv', 'ssn',
]);
const CONTROL = /[\u0000-\u001f\u007f]/g;
const VERSION = '0.1.0';
const MAX_EVENT_BYTES = 16 * 1024;

const sleep = (ms) => new Promise((resolve) => { const timer = setTimeout(resolve, ms); timer.unref?.(); });

const strip = (value, max) => String(value).replace(CONTROL, '').slice(0, max);

/**
 * Explicit, server side event sender. Nothing is captured automatically: the
 * host application calls track() from the paths it wants monitored.
 */
export class SecureFlow {
  #apiKey;
  #endpoint;
  #flushIntervalMs;
  #maxBatchSize;
  #maxQueueSize;
  #requestTimeoutMs;
  #actorIdMode;
  #actorPepper;
  #fetch;
  #onError;
  #retryBaseMs;
  #maxRetryAttempts;
  #queue = [];
  #dropped = 0;
  #inFlight = false;
  #accepting = true;
  #aborted = false;
  #failures = 0;
  #pauseUntil = 0;
  #timer = null;
  #heartbeatTimer = null;

  constructor({
    apiKey,
    endpoint,
    flushIntervalMs = 5000,
    maxBatchSize = 50,
    maxQueueSize = 1000,
    requestTimeoutMs = 5000,
    actorIdMode = 'hash',
    actorPepper,
    heartbeatIntervalMs = 900_000,
    allowInsecureEndpoint = false,
    retryBaseMs = 1000,
    maxRetryAttempts = 5,
    onError,
    fetchImpl,
  } = {}) {
    if (typeof apiKey !== 'string' || !KEY_PATTERN.test(apiKey)) {
      throw new Error('SecureFlow: apiKey must match sfk_<12 base32 characters>_<43 characters>.');
    }
    if (typeof endpoint !== 'string' || !endpoint) {
      throw new Error('SecureFlow: endpoint is required.');
    }
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error('SecureFlow: endpoint must be an absolute URL.');
    }
    const localHttp = url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1', '[::1]'].includes(url.hostname);
    const insecureAllowed = localHttp && process.env.NODE_ENV !== 'production' && allowInsecureEndpoint === true;
    if (url.protocol !== 'https:' && !insecureAllowed) {
      throw new Error('SecureFlow: endpoint must use https. Plain http is only accepted for localhost in development with allowInsecureEndpoint.');
    }
    if (!['hash', 'raw', 'omit'].includes(actorIdMode)) {
      throw new Error('SecureFlow: actorIdMode must be hash, raw or omit.');
    }
    if (actorIdMode === 'hash' && (typeof actorPepper !== 'string' || Buffer.byteLength(actorPepper) < 16)) {
      throw new Error('SecureFlow: actorPepper must be at least 16 bytes when actorIdMode is hash.');
    }
    if (!Number.isFinite(maxBatchSize) || maxBatchSize < 1 || maxBatchSize > 100) {
      throw new Error('SecureFlow: maxBatchSize must be between 1 and 100.');
    }

    this.#apiKey = apiKey;
    this.#endpoint = endpoint;
    this.#flushIntervalMs = flushIntervalMs;
    this.#maxBatchSize = maxBatchSize;
    this.#maxQueueSize = maxQueueSize;
    this.#requestTimeoutMs = requestTimeoutMs;
    this.#actorIdMode = actorIdMode;
    this.#actorPepper = actorPepper;
    this.#fetch = fetchImpl ?? globalThis.fetch;
    this.#onError = typeof onError === 'function' ? onError : () => {};
    this.#retryBaseMs = retryBaseMs;
    this.#maxRetryAttempts = maxRetryAttempts;

    this.#timer = setInterval(() => { void this.flush(); }, flushIntervalMs);
    this.#timer.unref?.();
    this.#heartbeatTimer = setInterval(() => this.#heartbeat(), heartbeatIntervalMs);
    this.#heartbeatTimer.unref?.();
  }

  get dropped() { return this.#dropped; }
  get queued() { return this.#queue.length; }

  /** Synchronous enqueue. Invalid input is dropped and reported, never thrown. */
  track(event) {
    try {
      if (!this.#accepting) return;
      const prepared = this.#prepare(event);
      if (!prepared) return;
      if (this.#queue.length >= this.#maxQueueSize) {
        this.#queue.shift();
        this.#dropped += 1;
      }
      this.#queue.push(prepared);
      if (this.#queue.length >= this.#maxBatchSize) void this.flush();
    } catch (error) {
      this.#report(error);
    }
  }

  /** Send one connectivity test event immediately and report the HTTP result. */
  async testConnection() {
    try {
      const event = this.#prepare({ type: 'sdk.connectivity_test' });
      const response = await this.#post([event]);
      return { ok: response.ok, status: response.status };
    } catch {
      return { ok: false, status: 0 };
    }
  }

  /** Send everything queued, one batch at a time. Never rejects. */
  async flush() {
    if (this.#inFlight || this.#aborted) return;
    if (this.#queue.length === 0) return;
    if (Date.now() < this.#pauseUntil) return;
    this.#inFlight = true;
    try {
      while (this.#queue.length > 0) {
        if (this.#aborted) break;
        const batch = this.#queue.splice(0, this.#maxBatchSize);
        const result = await this.#deliver(batch);
        if (!result.ok && !result.retry) break;
        if (result.ok) this.#failures = 0;
      }
    } catch (error) {
      this.#report(error);
    } finally {
      this.#inFlight = false;
    }
  }

  /** Stop accepting work, flush within the deadline and release timers. */
  async shutdown({ timeoutMs = 5000 } = {}) {
    this.#accepting = false;
    if (this.#timer) clearInterval(this.#timer);
    if (this.#heartbeatTimer) clearInterval(this.#heartbeatTimer);
    this.#timer = null;
    this.#heartbeatTimer = null;
    let timer;
    const deadline = new Promise((resolve) => { timer = setTimeout(resolve, timeoutMs); timer.unref?.(); });
    try {
      await Promise.race([this.flush(), deadline]);
    } finally {
      clearTimeout(timer);
      // Stop any retry that is still sleeping; the deadline is binding.
      this.#aborted = true;
    }
  }

  /** Extract the fields the SDK understands from an Express style request. */
  requestContext(req) {
    if (!req) return {};
    const header = (name) => req.get?.(name) ?? req.headers?.[name.toLowerCase()] ?? null;
    return {
      ip: req.ip ?? req.socket?.remoteAddress ?? null,
      host: req.hostname ?? header('host') ?? null,
      method: req.method ?? null,
      path: req.path ?? req.url ?? null,
      user_agent: header('user-agent'),
    };
  }

  toJSON() {
    return { endpoint: this.#endpoint, queued: this.#queue.length, dropped: this.#dropped };
  }

  toString() { return '[SecureFlow]'; }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return `SecureFlow { endpoint: ${this.#endpoint}, queued: ${this.#queue.length}, dropped: ${this.#dropped} }`;
  }

  #report(error) {
    try {
      this.#onError(error instanceof Error ? error : new Error(String(error)));
    } catch { /* a reporter must never break the host */ }
  }

  #heartbeat() {
    try {
      const dropped = this.#dropped;
      this.#dropped = 0;
      const event = this.#prepare({ type: 'sdk.heartbeat', attributes: { dropped, queued: this.#queue.length } });
      if (!event) return;
      if (this.#queue.length >= this.#maxQueueSize) {
        this.#queue.shift();
        this.#dropped += 1;
      }
      this.#queue.push(event);
    } catch (error) {
      this.#report(error);
    }
  }

  #prepare(raw) {
    try {
      if (!raw || typeof raw !== 'object') throw new Error('SecureFlow: event must be an object.');
      if (!EVENT_TYPES.has(raw.type)) throw new Error(`SecureFlow: unsupported event type ${String(raw.type).slice(0, 40)}.`);
      const event = { event_id: typeof raw.event_id === 'string' ? raw.event_id : randomUUID(), type: raw.type, occurred_at: new Date().toISOString() };

      if (raw.actor && typeof raw.actor === 'object') {
        const id = typeof raw.actor.id === 'string' ? raw.actor.id.slice(0, 128) : null;
        if (id && this.#actorIdMode !== 'omit') {
          event.actor = {
            id: this.#actorIdMode === 'hash' ? this.#hash(id) : id,
            id_mode: this.#actorIdMode,
          };
        }
      }

      if (raw.client && typeof raw.client === 'object') {
        const client = {};
        if (typeof raw.client.ip === 'string') client.ip = raw.client.ip.slice(0, 64);
        if (typeof raw.client.user_agent === 'string') client.user_agent = strip(raw.client.user_agent, 256);
        if (Object.keys(client).length) event.client = client;
      }

      if (raw.request && typeof raw.request === 'object') {
        const request = {};
        if (typeof raw.request.host === 'string') request.host = raw.request.host.toLowerCase().slice(0, 253);
        if (METHODS.has(raw.request.method)) request.method = raw.request.method;
        if (typeof raw.request.path === 'string') {
          const path = strip(raw.request.path.split('?')[0].split('#')[0], 512);
          if (path.startsWith('/')) request.path = path;
        }
        if (Number.isInteger(raw.request.status) && raw.request.status >= 100 && raw.request.status <= 599) request.status = raw.request.status;
        if (Object.keys(request).length) event.request = request;
      }

      if (raw.attributes && typeof raw.attributes === 'object' && !Array.isArray(raw.attributes)) {
        const attributes = {};
        for (const [key, value] of Object.entries(raw.attributes)) {
          if (!/^[a-z][a-z0-9_.]{0,63}$/.test(key)) continue;
          if (SENSITIVE.has(key)) continue;
          if (typeof value === 'string') attributes[key] = strip(value, 512);
          else if (typeof value === 'number' && Number.isFinite(value)) attributes[key] = value;
          else if (typeof value === 'boolean') attributes[key] = value;
        }
        if (Object.keys(attributes).length) event.attributes = attributes;
      }

      const size = Buffer.byteLength(JSON.stringify(event));
      if (size > MAX_EVENT_BYTES) throw new Error('SecureFlow: event is larger than 16 KiB and was dropped.');
      return event;
    } catch (error) {
      this.#report(error);
      return null;
    }
  }

  #hash(value) {
    return createHmac('sha256', this.#actorPepper).update(value).digest('hex');
  }

  #backoff(attempt) {
    const base = Math.min(this.#retryBaseMs * 2 ** (attempt - 1), 60_000);
    const jitter = base * 0.2 * (Math.random() * 2 - 1);
    return Math.max(1, Math.round(base + jitter));
  }

  #envelope(events) {
    return {
      schema_version: 1,
      sdk: { name: 'secureflow-sdk-node', version: VERSION },
      sent_at: new Date().toISOString(),
      events,
    };
  }

  async #post(events) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#requestTimeoutMs);
    timer.unref?.();
    try {
      const response = await this.#fetch(this.#endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${this.#apiKey}`,
          'user-agent': `secureflow-sdk-node/${VERSION}`,
        },
        body: JSON.stringify(this.#envelope(events)),
        signal: controller.signal,
      });
      return { ok: response.ok, status: response.status, retryAfter: response.headers?.get?.('retry-after') ?? null };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Bounded retries with jitter. Permanent client errors drop the batch. */
  async #deliver(batch) {
    const maxAttempts = this.#maxRetryAttempts;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (this.#aborted) return { ok: false, retry: false };
      if (Date.now() < this.#pauseUntil) return { ok: false, retry: true };
      try {
        const response = await this.#post(batch);
        if (response.ok) return { ok: true };
        const retryable = response.status === 429 || response.status >= 500;
        if (!retryable) {
          this.#report(new Error(`SecureFlow: ingestion rejected the batch with status ${response.status}.`));
          return { ok: false, retry: false };
        }
        if (attempt === maxAttempts) {
          this.#failures += 1;
          if (this.#failures >= 5) this.#pauseUntil = Date.now() + 60_000;
          this.#report(new Error(`SecureFlow: ingestion returned status ${response.status} after ${maxAttempts} attempts.`));
          return { ok: false, retry: false };
        }
        const retryAfter = Number(response.retryAfter);
        await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 60_000) : this.#backoff(attempt));
      } catch (error) {
        if (attempt === maxAttempts) {
          this.#failures += 1;
          if (this.#failures >= 5) this.#pauseUntil = Date.now() + 60_000;
          this.#report(error);
          return { ok: false, retry: false };
        }
        await sleep(this.#backoff(attempt));
      }
    }
    return { ok: false, retry: false };
  }
}

export default SecureFlow;
