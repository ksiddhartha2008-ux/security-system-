import { scryptSync, scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { get, run, all, newId, nowIso } from '../db.js';
import { ApiError, forbidden, unauthorized } from './http.js';

export const SESSION_COOKIE = 'sf_session';
export const CSRF_COOKIE = 'sf_csrf';
export const MFA_COOKIE = 'sf_mfa';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const SCRYPT_KEYLEN = 64;

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const [scheme, salt, digest] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !digest) return false;
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(digest, 'hex');
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(derived, expected);
}

const scryptAsync = promisify(scrypt);

/**
 * Asynchronous variants for request paths. scrypt is deliberately expensive;
 * running it off the event loop keeps one login from stalling every request.
 */
export async function hashPasswordAsync(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scryptAsync(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt}$${derived.toString('hex')}`;
}

export async function verifyPasswordAsync(password, stored) {
  if (typeof stored !== 'string') return false;
  const [scheme, salt, digest] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !digest) return false;
  const derived = await scryptAsync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(digest, 'hex');
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(derived, expected);
}

export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

const secureCookies = () => process.env.NODE_ENV === 'production';

export function setSessionCookie(res, token, { secure = false } = {}) {
  const parts = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (secure) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

export function setCsrfCookie(res, token) {
  // Readable by the client on purpose: the double submit token must be sent
  // back in a header. It is bound to the session hash server side.
  const parts = [
    `${CSRF_COOKIE}=${token}`,
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (secureCookies()) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(res) {
  res.append('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  res.append('Set-Cookie', `${CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0`);
}

export function setMfaCookie(res, token) {
  const parts = [`${MFA_COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=300'];
  if (secureCookies()) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

export function clearMfaCookie(res) {
  res.append('Set-Cookie', `${MFA_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
}

export function createSession(user, req, res) {
  const token = randomBytes(32).toString('base64url');
  const csrfToken = randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  run(
    `INSERT INTO sessions (id, user_id, org_id, expires_at, ip, user_agent, csrf_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    hashToken(token), user.id, user.org_id, expires.toISOString(),
    req.ip ?? null, (req.headers['user-agent'] ?? '').slice(0, 255), hashToken(csrfToken), nowIso(),
  );
  // Keep the session list bounded per user; drop the oldest beyond ten.
  const extra = all(
    'SELECT id FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET 10',
    user.id,
  );
  for (const row of extra) run('DELETE FROM sessions WHERE id = ?', row.id);
  setSessionCookie(res, token, { secure: secureCookies() });
  setCsrfCookie(res, csrfToken);
  return token;
}

export function destroySession(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  if (token) run('DELETE FROM sessions WHERE id = ?', hashToken(token));
  clearSessionCookie(res);
}

/** Resolve the session cookie into req.user; never trusts client supplied org or role. */
export function attachUser(req, _res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  req.user = null;
  if (!token) return next();
  const row = get(
    `SELECT s.id AS session_id, s.expires_at, s.csrf_hash, u.id, u.org_id, u.email, u.name, u.role, u.status
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ?`,
    hashToken(token),
  );
  if (!row) return next();
  if (new Date(row.expires_at).getTime() < Date.now()) {
    run('DELETE FROM sessions WHERE id = ?', row.session_id);
    return next();
  }
  if (row.status !== 'active') return next();
  req.user = {
    id: row.id,
    orgId: row.org_id,
    email: row.email,
    name: row.name,
    role: row.role,
  };
  req.csrfHash = row.csrf_hash;
  return next();
}

export function requireAuth(req, _res, next) {
  if (!req.user) return next(unauthorized());
  return next();
}

const RANK = { viewer: 1, analyst: 2, admin: 3 };

export function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.user) return next(unauthorized());
    const allowed = new Set(roles);
    if (allowed.has(req.user.role)) return next();
    const minRank = Math.min(...[...allowed].map((r) => RANK[r] ?? 99));
    if (RANK[req.user.role] >= minRank) return next();
    return next(forbidden());
  };
}

export const isAdmin = (user) => user?.role === 'admin';
export const canWrite = (user) => RANK[user?.role] >= RANK.analyst;

/** CSRF defense in depth: SameSite=Lax cookie plus Origin/Host comparison on state changes. */
export function checkOrigin(req, _res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next(); // A missing Origin is not sufficient on its own; requireCsrf still applies.
  try {
    const parsed = new URL(origin);
    const host = req.headers.host;
    if (parsed.host === host) return next();
    if (process.env.SF_ALLOW_ORIGIN && parsed.origin === process.env.SF_ALLOW_ORIGIN) return next();
    return next(new ApiError(403, 'origin_rejected', 'Cross-origin request rejected'));
  } catch {
    return next(new ApiError(403, 'origin_rejected', 'Invalid origin header'));
  }
}

/**
 * Session-bound CSRF check for cookie authenticated mutations.
 * Public auth endpoints (login, register, MFA verify) have no session yet and
 * are protected by origin checks plus rate limits instead.
 */
export function requireCsrf(req, _res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!req.user) return next();
  const header = req.headers['x-csrf-token'];
  const cookie = parseCookies(req.headers.cookie)[CSRF_COOKIE];
  if (!header || !cookie || header !== cookie) {
    return next(new ApiError(403, 'csrf_rejected', 'CSRF token missing or invalid'));
  }
  if (!req.csrfHash || hashToken(header) !== req.csrfHash) {
    return next(new ApiError(403, 'csrf_rejected', 'CSRF token does not match this session'));
  }
  return next();
}

export function sessionCountForUser(userId) {
  return get('SELECT COUNT(*) AS c FROM sessions WHERE user_id = ? AND expires_at > ?', userId, nowIso())?.c ?? 0;
}
