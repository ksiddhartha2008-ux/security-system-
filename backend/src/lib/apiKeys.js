import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { get } from '../db.js';

export const KEY_PATTERN = /^sfk_([a-z2-7]{12})_([A-Za-z0-9_-]{43})$/;
const KEY_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** 12 characters from the RFC 4648 base32 alphabet, derived only from CSPRNG bytes. */
export function generateKeyId() {
  const bytes = randomBytes(16);
  let out = '';
  for (const byte of bytes) out += KEY_ID_ALPHABET[byte % 32];
  return out.slice(0, 12);
}

export const hashSecret = (secret) => createHash('sha256').update(secret).digest('hex');

export function generateApiKey() {
  const keyId = generateKeyId();
  const secret = randomBytes(32).toString('base64url');
  return {
    keyId,
    secret,
    apiKey: `sfk_${keyId}_${secret}`,
    last4: secret.slice(-4),
    secretHash: hashSecret(secret),
  };
}

export function parseApiKey(value) {
  if (typeof value !== 'string') return null;
  const match = KEY_PATTERN.exec(value);
  if (!match) return null;
  return { keyId: match[1], secret: match[2] };
}

/** Authorization header only. Keys in a query string or cookie are never read. */
export function readAuthorizationKey(header) {
  if (typeof header !== 'string') return null;
  const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(header.trim());
  if (!match) return null;
  return match[1];
}

const DUMMY = Buffer.alloc(32, 7);
const CACHE_TTL_MS = 10_000;
const cache = new Map();

export function purgeKeyCache(keyId) {
  if (keyId) cache.delete(keyId);
  else cache.clear();
}

function safeEqualHex(a, b) {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== right.length || left.length === 0) return false;
  return timingSafeEqual(left, right);
}

function loadKey(apiKey) {
  const parsed = parseApiKey(apiKey);
  if (!parsed) return { ok: false, code: 'invalid_api_key' };

  const now = Date.now();
  const cached = cache.get(parsed.keyId);
  if (cached && cached.expiresAt > now) {
    if (!safeEqualHex(hashSecret(parsed.secret), cached.row.secret_hash)) return { ok: false, code: 'invalid_api_key' };
    return finish(cached.row, cached.site);
  }

  const row = get('SELECT * FROM site_api_keys WHERE key_id = ?', parsed.keyId);
  if (!row) {
    // Constant work for unknown ids so a response time cannot confirm existence.
    timingSafeEqual(DUMMY, DUMMY);
    return { ok: false, code: 'invalid_api_key' };
  }
  if (!safeEqualHex(hashSecret(parsed.secret), row.secret_hash)) return { ok: false, code: 'invalid_api_key' };
  if (row.revoked_at || (row.expires_at && new Date(row.expires_at).getTime() <= now)) {
    return { ok: false, code: 'invalid_api_key' };
  }

  const site = get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', row.site_id, row.org_id);
  if (!site || site.status === 'deleted') return { ok: false, code: 'invalid_api_key' };

  cache.set(parsed.keyId, { row, site, expiresAt: now + CACHE_TTL_MS });
  return finish(row, site);
}

function finish(row, site) {
  if (site.status !== 'verified') return { ok: false, code: 'site_not_verified' };
  return { ok: true, key: row, site };
}

/** Validate an API key. Returns the key and site rows; never the secret. */
export function verifyApiKey(apiKey) {
  try {
    return loadKey(apiKey);
  } catch {
    // Fail closed on any unexpected storage or parsing error.
    return { ok: false, code: 'invalid_api_key' };
  }
}

/** Write amplification guard: at most one update per minute per key. */
export function touchKey(row, now = Date.now()) {
  const last = row.last_used_at ? new Date(row.last_used_at).getTime() : 0;
  if (now - last < 60_000) return false;
  return true;
}
