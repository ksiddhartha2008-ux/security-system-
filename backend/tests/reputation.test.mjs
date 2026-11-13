import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  virusTotal, abuseIp, enrich, providerHealth, resetProviderState, reputationScore,
} from '../src/services/reputation.js';

/** Local stand-in for the provider API. No real credentials or traffic are used. */
async function stub(handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

test('a configured VirusTotal key produces a validated real check', async () => {
  resetProviderState();
  const seen = [];
  const s = await stub((req, res) => {
    seen.push(req.headers['x-apikey']);
    json(res, 200, { data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 4 } } } });
  });
  try {
    const original = globalThis.__sfVtBase;
    process.env.VIRUSTOTAL_API_KEY = 'test-key-not-a-secret';
    const result = await virusTotal('domain', 'example.test', {
      fetchImpl: (url, options) => fetch(`${s.base}/vt`, options),
    });
    assert.equal(result.configured, true);
    assert.equal(result.check.malicious, 3);
    assert.deepEqual(seen, ['test-key-not-a-secret']);
    const health = providerHealth().find((p) => p.key === 'virustotal');
    assert.equal(health.status, 'REAL');
    assert.equal(health.verified, true);
    void original;
  } finally {
    delete process.env.VIRUSTOTAL_API_KEY;
    await s.close();
  }
});

test('a 404 is reported as no record, not as an error', async () => {
  resetProviderState();
  const s = await stub((_req, res) => json(res, 404, { error: { code: 'NotFoundError' } }));
  process.env.VIRUSTOTAL_API_KEY = 'test-key';
  try {
    const result = await virusTotal('hash', 'a'.repeat(64), { fetchImpl: (url, options) => fetch(`${s.base}/vt`, options) });
    assert.equal(result.check.note, 'No record for this indicator');
    assert.equal(providerHealth().find((p) => p.key === 'virustotal').status, 'REAL');
  } finally {
    delete process.env.VIRUSTOTAL_API_KEY;
    await s.close();
  }
});

test('a transient 500 is retried once and the success is used', async () => {
  resetProviderState();
  let calls = 0;
  const s = await stub((_req, res) => {
    calls += 1;
    if (calls === 1) return json(res, 500, { error: 'temporary' });
    return json(res, 200, { data: { abuseConfidenceScore: 88, totalReports: 42, countryCode: 'NL' } });
  });
  process.env.ABUSEIPDB_API_KEY = 'test-key';
  try {
    const result = await abuseIp('203.0.113.9', { fetchImpl: (url, options) => fetch(`${s.base}/abuse`, options) });
    assert.equal(calls, 2);
    assert.equal(result.check.abuseConfidenceScore, 88);
    assert.equal(result.check.countryCode, 'NL');
  } finally {
    delete process.env.ABUSEIPDB_API_KEY;
    await s.close();
  }
});

test('an unexpected response shape is an error, not a silent zero', async () => {
  resetProviderState();
  const s = await stub((_req, res) => json(res, 200, { unexpected: true }));
  process.env.VIRUSTOTAL_API_KEY = 'test-key';
  try {
    const result = await virusTotal('domain', 'shape.test', { fetchImpl: (url, options) => fetch(`${s.base}/vt`, options) });
    assert.match(result.check.error, /Unexpected response shape/i);
    assert.equal(providerHealth().find((p) => p.key === 'virustotal').status, 'ERROR');
  } finally {
    delete process.env.VIRUSTOTAL_API_KEY;
    await s.close();
  }
});

test('provider errors are surfaced without leaking the key', async () => {
  resetProviderState();
  const s = await stub((_req, res) => json(res, 403, { error: 'forbidden' }));
  process.env.VIRUSTOTAL_API_KEY = 'super-secret-key';
  try {
    const result = await virusTotal('url', 'https://example.test/login', { fetchImpl: (url, options) => fetch(`${s.base}/vt`, options) });
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes('super-secret-key'), false);
    assert.match(result.check.error, /HTTP 403/);
  } finally {
    delete process.env.VIRUSTOTAL_API_KEY;
    await s.close();
  }
});

test('a repeated lookup inside the cache window makes one provider call', async () => {
  resetProviderState();
  let calls = 0;
  const s = await stub((_req, res) => {
    calls += 1;
    json(res, 200, { data: { attributes: { last_analysis_stats: { malicious: 1 } } } });
  });
  process.env.VIRUSTOTAL_API_KEY = 'test-key';
  try {
    const options = { fetchImpl: (url, opts) => fetch(`${s.base}/vt`, opts) };
    await virusTotal('domain', 'cache.test', options);
    await virusTotal('domain', 'cache.test', options);
    assert.equal(calls, 1);
  } finally {
    delete process.env.VIRUSTOTAL_API_KEY;
    await s.close();
  }
});

test('without keys every provider reports UNAVAILABLE and enrichment is empty', async () => {
  resetProviderState();
  delete process.env.VIRUSTOTAL_API_KEY;
  delete process.env.ABUSEIPDB_API_KEY;
  const health = providerHealth();
  assert.ok(health.every((p) => p.status === 'UNAVAILABLE' && p.verified === false));
  const enriched = await enrich({ type: 'url', value: 'https://example.test/' });
  assert.deepEqual(enriched.providers, []);
  assert.deepEqual(enriched.checks, []);
});

test('provider scores are capped and additive', () => {
  assert.equal(reputationScore([]), 0);
  assert.equal(reputationScore([{ malicious: 2 }]), 16);
  assert.equal(reputationScore([{ malicious: 99 }]), 40);
  assert.equal(reputationScore([{ abuseConfidenceScore: 100 }]), 25);
  assert.equal(reputationScore([{ malicious: 99 }, { abuseConfidenceScore: 100 }]), 65);
});
