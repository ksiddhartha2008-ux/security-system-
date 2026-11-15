/**
 * Minimal Wazuh manager API client (API v4).
 *
 * It performs the two calls that prove the manager is real and reachable:
 * authenticate, then read manager info. Agent listing is used for the endpoint
 * view when the API is configured, so the number of online agents comes from the
 * manager rather than from a collector guess.
 *
 * The manager certificate must be trusted by Node. Point NODE_EXTRA_CA_CERTS at
 * the manager CA instead of disabling verification.
 */

const DEFAULT_TIMEOUT = 6000;

function trimBase(value) {
  return String(value ?? '').trim().replace(/\/+$/, '');
}

export function wazuhConfig(env = process.env) {
  const baseUrl = trimBase(env.WAZUH_API_URL);
  const username = env.WAZUH_API_USER || '';
  const password = env.WAZUH_API_PASSWORD || '';
  const token = env.WAZUH_API_TOKEN || '';
  return { baseUrl, username, password, token, configured: Boolean(baseUrl && (token || (username && password))) };
}

export function createWazuhClient({
  baseUrl,
  username,
  password,
  token,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT,
} = {}) {
  const base = trimBase(baseUrl);
  const configured = Boolean(base && (token || (username && password)));

  async function call(path, { method = 'GET', auth, body } = {}) {
    const headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth) headers.authorization = auth;
    const response = await fetchImpl(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = null; }
    if (!response.ok) {
      const message = payload?.detail ?? payload?.message ?? payload?.title ?? text.slice(0, 160) ?? `HTTP ${response.status}`;
      throw new Error(`Wazuh HTTP ${response.status}: ${message}`);
    }
    return payload ?? {};
  }

  async function authenticate() {
    if (token) return { header: `Bearer ${token}`, source: 'static token' };
    const basic = Buffer.from(`${username}:${password}`).toString('base64');
    const payload = await call('/security/user/authenticate', {
      method: 'POST',
      auth: `Basic ${basic}`,
    });
    const issued = payload?.data?.token;
    if (!issued) throw new Error('Wazuh authentication returned no token');
    return { header: `Bearer ${issued}`, source: 'username and password' };
  }

  return {
    configured,
    async health() {
      if (!configured) {
        return { ok: false, detail: 'WAZUH_API_URL and credentials are not configured', latencyMs: null };
      }
      const started = performance.now();
      try {
        const auth = await authenticate();
        const info = await call('/manager/info', { auth: auth.header });
        const latencyMs = Math.round(performance.now() - started);
        const version = info?.data?.affected_items?.[0]?.version ?? info?.data?.version ?? null;
        return {
          ok: true,
          latencyMs,
          version,
          detail: `Manager answered in ${latencyMs} ms using ${auth.source}`,
        };
      } catch (error) {
        return {
          ok: false,
          latencyMs: Math.round(performance.now() - started),
          detail: String(error.message).slice(0, 240),
        };
      }
    },
    async agents({ limit = 100 } = {}) {
      if (!configured) throw new Error('Wazuh API is not configured');
      const auth = await authenticate();
      const payload = await call(`/agents?limit=${Math.min(Math.max(limit, 1), 500)}&select=id,name,ip,status,lastKeepAlive,os.name`, { auth: auth.header });
      const rows = payload?.data?.affected_items ?? [];
      return rows.map((row) => ({
        id: String(row.id ?? ''),
        name: row.name ?? '',
        ip: row.ip ?? null,
        status: row.status ?? 'unknown',
        os: row.os?.name ?? null,
        lastKeepAlive: row.lastKeepAlive ?? null,
      }));
    },
  };
}
