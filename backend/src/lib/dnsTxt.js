import { promises as dns } from 'node:dns';
import { readFileSync } from 'node:fs';

const NOT_FOUND_CODES = new Set(['ENODATA', 'ENOTFOUND', 'ENOENT']);
const MAX_RECORDS = 20;
const MAX_CHARS = 4096;
export const DNS_TIMEOUT_MS = 3000;

/**
 * Compare TXT answers with the expected challenge value.
 * Returns ok, mismatch, not_found or resolver_error. Comparison is exact:
 * no substring, prefix or case folding.
 */
export function evaluateTxtRecords(records, expected) {
  if (!Array.isArray(records)) return 'not_found';
  const limited = records.slice(0, MAX_RECORDS);
  let consumed = 0;
  let sawRecord = false;
  for (const record of limited) {
    if (!Array.isArray(record)) continue;
    const joined = record.join('');
    consumed += joined.length;
    if (consumed > MAX_CHARS) break;
    sawRecord = true;
    if (joined.trim() === expected) return 'ok';
  }
  return sawRecord ? 'mismatch' : 'not_found';
}

export function classifyDnsError(error) {
  const code = error?.code ?? '';
  if (NOT_FOUND_CODES.has(code)) return 'not_found';
  return 'resolver_error';
}

/**
 * Resolution seam. Production uses the system resolver or configured servers.
 * Tests and local demonstrations can point SF_DNS_FAKE_FILE at a JSON map, a
 * seam that is refused in production (see lib/config.js).
 */
export function createTxtResolver({ fakeFile = process.env.SF_DNS_FAKE_FILE, timeoutMs = DNS_TIMEOUT_MS } = {}) {
  if (fakeFile) {
    return {
      kind: 'file',
      async resolveTxt(name) {
        const map = JSON.parse(readFileSync(fakeFile, 'utf8'));
        const records = map?.records?.[name.toLowerCase()];
        const failure = map?.errors?.[name.toLowerCase()];
        if (failure) {
          const error = new Error(`fake resolver error ${failure}`);
          error.code = String(failure);
          throw error;
        }
        if (records === undefined) {
          const error = new Error('fake resolver: no data');
          error.code = 'ENODATA';
          throw error;
        }
        return normalizeFakeRecords(records);
      },
    };
  }

  const servers = String(process.env.SF_DNS_RESOLVERS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 2 });
  if (servers.length) resolver.setServers(servers);

  return {
    kind: 'dns',
    async resolveTxt(name) {
      // `node:dns/promises` Resolver returns a promise. Passing a callback here
      // would leave the returned promise unobserved, so a failed lookup would
      // surface as an unhandled rejection and stop the process.
      return withTimeout(resolver.resolveTxt(name), timeoutMs);
    },
  };
}

/**
 * Race a promise against a timer without leaking the loser.
 *
 * Node treats a rejection that nobody observes as fatal. When the timeout wins,
 * the DNS attempt may reject later; attaching a no-op catch keeps that rejection
 * handled so a slow lookup cannot crash the API process.
 */
export function withTimeout(promise, timeoutMs, message = 'dns lookup timed out') {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(message);
      error.code = 'ETIMEOUT';
      reject(error);
    }, timeoutMs);
    timer.unref?.();
  });
  promise.catch(() => {});
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function normalizeFakeRecords(value) {
  if (!Array.isArray(value)) return [];
  return value.map((record) => (Array.isArray(record) ? record.map(String) : [String(record)]));
}
