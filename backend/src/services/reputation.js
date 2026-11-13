/**
 * External reputation providers.
 *
 * Both providers are optional. When a key is absent the connector reports
 * UNAVAILABLE and the verdict falls back to workspace indicators only. When a
 * key is present the call is real: bounded timeout, one bounded retry for
 * transient failures, response shape validation, a short cache and a health
 * record per provider. Credentials never leave the backend.
 */
import { z } from 'zod';

const TIMEOUT_MS = 8000;
const RETRY_DELAY_MS = 250;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 500;

const VT_STATS = z.object({
  data: z.object({
    attributes: z.object({
      last_analysis_stats: z.object({
        malicious: z.number().optional(),
        suspicious: z.number().optional(),
        harmless: z.number().optional(),
        undetected: z.number().optional(),
      }).passthrough().optional(),
    }).passthrough(),
  }).passthrough(),
});

const ABUSE_BODY = z.object({
  data: z.object({
    abuseConfidenceScore: z.number(),
    totalReports: z.number().optional(),
    countryCode: z.string().nullable().optional(),
  }).passthrough(),
});

export const PROVIDERS = [
  {
    key: 'virustotal', name: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY',
    kinds: ['domain', 'url', 'hash'], category: 'threat-intel',
    description: 'Reputation lookups for hashes, domains and URLs. Indicators leave the platform.',
  },
  {
    key: 'abuseipdb', name: 'AbuseIPDB', env: 'ABUSEIPDB_API_KEY',
    kinds: ['ip'], category: 'threat-intel',
    description: 'Abuse confidence scores for IP addresses. Addresses leave the platform.',
  },
];

const health = new Map();
const cache = new Map();

function record(key, outcome, detail) {
  const current = health.get(key) ?? { lastOkAt: null, lastErrorAt: null, lastError: null };
  if (outcome === 'ok') health.set(key, { ...current, lastOkAt: new Date().toISOString(), lastError: null });
  else health.set(key, { ...current, lastErrorAt: new Date().toISOString(), lastError: detail ?? 'unknown error' });
}

export function resetProviderState() {
  health.clear();
  cache.clear();
}

export function providerHealth(env = process.env) {
  return PROVIDERS.map((provider) => {
    const configured = Boolean(env[provider.env]);
    const state = health.get(provider.key) ?? {};
    const verified = Boolean(state.lastOkAt);
    const status = !configured
      ? 'UNAVAILABLE'
      : state.lastErrorAt && !state.lastOkAt
        ? 'ERROR'
        : state.lastOkAt && state.lastErrorAt && state.lastErrorAt > state.lastOkAt
          ? 'ERROR'
          : 'REAL';
    return {
      key: provider.key, name: provider.name, category: provider.category, description: provider.description,
      envVar: provider.env, configured, status, verified,
      lastOkAt: state.lastOkAt ?? null, lastErrorAt: state.lastErrorAt ?? null, lastError: state.lastError ?? null,
    };
  });
}

function cached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) { cache.delete(key); return null; }
  return entry.value;
}

function remember(key, value) {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
  cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function requestJson(url, options, { fetchImpl = fetch } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const response = await fetchImpl(url, { ...options, signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (response.status >= 500 && attempt === 1) { lastError = new Error(`HTTP ${response.status}`); await sleep(RETRY_DELAY_MS); continue; }
      return response;
    } catch (err) {
      lastError = err;
      if (attempt === 1) { await sleep(RETRY_DELAY_MS); continue; }
    }
  }
  throw lastError;
}

/** VirusTotal. Returns null when the indicator is not in the dataset. */
export async function virusTotal(type, value, options = {}) {
  const env = options.env ?? process.env;
  const key = env.VIRUSTOTAL_API_KEY;
  if (!key) return { configured: false, check: null };
  const cacheKey = `vt:${type}:${value}`;
  const hit = cached(cacheKey);
  if (hit) return { configured: true, check: hit, cached: true };
  const path = type === 'hash'
    ? `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`
    : type === 'url'
      ? `https://www.virustotal.com/api/v3/urls/${Buffer.from(value).toString('base64url')}`
      : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
  try {
    const response = await requestJson(path, { headers: { 'x-apikey': key } }, options);
    if (response.status === 404) {
      const check = { provider: 'VirusTotal', note: 'No record for this indicator' };
      remember(cacheKey, check);
      record('virustotal', 'ok');
      return { configured: true, check };
    }
    if (!response.ok) {
      record('virustotal', 'error', `HTTP ${response.status}`);
      return { configured: true, check: { provider: 'VirusTotal', error: `HTTP ${response.status}` } };
    }
    const parsed = VT_STATS.safeParse(await response.json());
    if (!parsed.success) {
      record('virustotal', 'error', 'unexpected response shape');
      return { configured: true, check: { provider: 'VirusTotal', error: 'Unexpected response shape' } };
    }
    const stats = parsed.data.data.attributes.last_analysis_stats ?? {};
    const check = {
      provider: 'VirusTotal',
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
    };
    remember(cacheKey, check);
    record('virustotal', 'ok');
    return { configured: true, check };
  } catch (err) {
    record('virustotal', 'error', err.message);
    return { configured: true, check: { provider: 'VirusTotal', error: `Lookup failed: ${err.message}` } };
  }
}

/** AbuseIPDB for one address. */
export async function abuseIp(ip, options = {}) {
  const env = options.env ?? process.env;
  const key = env.ABUSEIPDB_API_KEY;
  if (!key) return { configured: false, check: null };
  const cacheKey = `abuse:${ip}`;
  const hit = cached(cacheKey);
  if (hit) return { configured: true, check: hit, cached: true };
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  try {
    const response = await requestJson(url, { headers: { Key: key, Accept: 'application/json' } }, options);
    if (!response.ok) {
      record('abuseipdb', 'error', `HTTP ${response.status}`);
      return { configured: true, check: { provider: 'AbuseIPDB', error: `HTTP ${response.status}` } };
    }
    const parsed = ABUSE_BODY.safeParse(await response.json());
    if (!parsed.success) {
      record('abuseipdb', 'error', 'unexpected response shape');
      return { configured: true, check: { provider: 'AbuseIPDB', error: 'Unexpected response shape' } };
    }
    const check = {
      provider: 'AbuseIPDB',
      ipAddress: ip,
      abuseConfidenceScore: parsed.data.data.abuseConfidenceScore,
      totalReports: parsed.data.data.totalReports ?? 0,
      countryCode: parsed.data.data.countryCode ?? null,
    };
    remember(cacheKey, check);
    record('abuseipdb', 'ok');
    return { configured: true, check };
  } catch (err) {
    record('abuseipdb', 'error', err.message);
    return { configured: true, check: { provider: 'AbuseIPDB', error: `Lookup failed: ${err.message}` } };
  }
}

/**
 * Run every provider that supports this indicator type. A failing provider
 * returns an error entry and never blocks the local verdict.
 */
export async function enrich({ type, value, ip = null, options = {} }) {
  const checks = [];
  const providers = [];
  if (['domain', 'url', 'hash'].includes(type)) {
    const vt = await virusTotal(type, value, options);
    if (vt.configured) { providers.push('VirusTotal'); checks.push(vt.check); }
  }
  if (type === 'ip' || ip) {
    const abuse = await abuseIp(type === 'ip' ? value : ip, options);
    if (abuse.configured) { providers.push('AbuseIPDB'); checks.push(abuse.check); }
  }
  return { providers, checks };
}

/** Extra score from provider answers, capped so one provider cannot dominate. */
export function reputationScore(checks) {
  let score = 0;
  for (const check of checks) {
    if (check.malicious > 0) score += Math.min(40, check.malicious * 8);
    if (check.abuseConfidenceScore > 25) score += Math.min(25, Math.round(check.abuseConfidenceScore / 4));
  }
  return Math.min(100, score);
}

export const providerNote = 'No reputation provider configured. Set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY to enrich lookups.';
