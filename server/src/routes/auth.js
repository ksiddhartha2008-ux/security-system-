import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson, transaction } from '../db.js';
import { asyncHandler, badRequest, conflict, created, ok, unauthorized, validate } from '../lib/http.js';
import { hashPassword, verifyPassword, createSession, destroySession, requireAuth, parseCookies, hashToken, SESSION_COOKIE } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { rateLimit } from '../lib/ratelimit.js';
import { DEMO_ACCOUNTS, isDemoMode } from '../lib/demo.js';
import { verifyTotp, generateSecret, otpauthUrl, generateRecoveryCodes, hashRecoveryCode } from '../lib/totp.js';

const router = Router();

const emailSchema = z.string().trim().toLowerCase().email('Enter a valid email address').max(180);
const passwordSchema = z.string().min(10, 'Use at least 10 characters').max(200, 'Password is too long');

const registerSchema = z.object({
  name: z.string().trim().min(2, 'Enter your full name').max(80),
  email: emailSchema,
  password: passwordSchema,
  organizationName: z.string().trim().min(2, 'Enter an organization name').max(80),
});

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Enter your password').max(200),
});

function publicUser(user, orgName) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    orgId: user.org_id,
    orgName,
    mfaEnabled: user.mfa_enabled === 1,
    createdAt: user.created_at,
    lastLoginAt: user.last_login_at,
  };
}

router.get('/demo-accounts', asyncHandler(async (_req, res) => {
  // Returned only when demo mode is on. This keeps credentials out of the built bundle.
  return ok(res, isDemoMode() ? DEMO_ACCOUNTS : []);
}));

router.post('/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 6, keyPrefix: 'register', message: 'Too many accounts created from this address. Try again later.' }), asyncHandler(async (req, res) => {
  const body = validate(registerSchema, req.body);
  if (get('SELECT id FROM users WHERE email = ?', body.email)) {
    throw conflict('An account with this email already exists');
  }
  const slugBase = body.organizationName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'workspace';
  const orgId = newId('org');
  const userId = newId('usr');
  const ts = nowIso();
  transaction(() => {
    let slug = slugBase;
    let n = 1;
    while (get('SELECT id FROM organizations WHERE slug = ?', slug)) { slug = `${slugBase}-${n}`; n += 1; }
    run(
      `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at) VALUES (?, ?, ?, 'team', ?, ?, ?)`,
      orgId, body.organizationName, slug, JSON.stringify({ timezone: 'UTC', retentionDays: 90, demoMode: false }), ts, ts,
    );
    run(
      `INSERT INTO users (id, org_id, email, name, password_hash, role, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'admin', 'active', ?, ?)`,
      userId, orgId, body.email, body.name, hashPassword(body.password), ts, ts,
    );
  });
  const user = get('SELECT * FROM users WHERE id = ?', userId);
  createSession(user, req, res);
  audit(req, 'auth.register', 'user', userId, { orgId });
  return created(res, { user: publicUser(user, body.organizationName) });
}));

router.post('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 12, keyPrefix: 'login' }), asyncHandler(async (req, res) => {
  const body = validate(loginSchema, req.body);
  const user = get('SELECT * FROM users WHERE email = ?', body.email);
  const ip = req.ip ?? null;
  const record = (success) => run(
    `INSERT INTO login_attempts (id, email, ip, success, created_at) VALUES (?, ?, ?, ?, ?)`,
    newId('att'), body.email, ip, success ? 1 : 0, nowIso(),
  );

  if (!user || !verifyPassword(body.password, user.password_hash)) {
    record(0);
    // Same message and status for unknown email and wrong password.
    throw unauthorized('Email or password is incorrect');
  }
  if (user.status !== 'active') {
    record(0);
    throw unauthorized('This account is disabled. Contact an administrator.');
  }
  record(1);
  const org = get('SELECT name FROM organizations WHERE id = ?', user.org_id);
  run('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?', nowIso(), nowIso(), user.id);

  if (user.mfa_enabled === 1) {
    // Do not create a session yet. A short lived challenge cookie proves the
    // password step; the second factor completes the login.
    run('DELETE FROM mfa_challenges WHERE expires_at < ?', nowIso());
    const challenge = randomBytes(24).toString('base64url');
    run(
      `INSERT INTO mfa_challenges (id, user_id, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)`,
      hashToken(challenge), user.id, new Date(Date.now() + 5 * 60_000).toISOString(), nowIso(),
    );
    res.setHeader('Set-Cookie', `sf_mfa=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
    audit(req, 'auth.mfa_challenge', 'user', user.id, {});
    return ok(res, { mfaRequired: true });
  }

  createSession(user, req, res);
  audit(req, 'auth.login', 'user', user.id, { orgId: user.org_id });
  return ok(res, { user: publicUser(user, org?.name) });
}));

router.post('/logout', asyncHandler(async (req, res) => {
  if (req.user) audit(req, 'auth.logout', 'user', req.user.id);
  destroySession(req, res);
  return ok(res, { ok: true });
}));

router.get('/me', requireAuth, asyncHandler(async (req, res) => {
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.user.id, req.user.orgId);
  const org = get('SELECT * FROM organizations WHERE id = ?', req.user.orgId);
  return ok(res, {
    user: publicUser(user, org?.name),
    organization: { id: org.id, name: org.name, slug: org.slug, plan: org.plan, settings: JSON.parse(org.settings || '{}') },
    permissions: {
      canWrite: req.user.role !== 'viewer',
      canAdmin: req.user.role === 'admin',
      canApprove: req.user.role !== 'viewer',
    },
  });
}));

router.patch('/me', requireAuth, asyncHandler(async (req, res) => {
  const body = validate(z.object({
    name: z.string().trim().min(2).max(80).optional(),
    currentPassword: z.string().max(200).optional(),
    newPassword: passwordSchema.optional(),
  }), req.body);
  const user = get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (body.newPassword) {
    if (!body.currentPassword || !verifyPassword(body.currentPassword, user.password_hash)) {
      throw badRequest('Current password is incorrect');
    }
    run('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', hashPassword(body.newPassword), nowIso(), user.id);
    // Rotate every session: a password change must invalidate any stolen cookie.
    run('DELETE FROM sessions WHERE user_id = ?', user.id);
    createSession({ ...user, password_hash: undefined }, req, res);
  }
  if (body.name) run('UPDATE users SET name = ?, updated_at = ? WHERE id = ?', body.name, nowIso(), user.id);
  audit(req, 'auth.profile_updated', 'user', user.id, { passwordChanged: Boolean(body.newPassword) });
  const updated = get('SELECT * FROM users WHERE id = ?', user.id);
  return ok(res, { user: publicUser(updated, null) });
}));

router.get('/sessions', requireAuth, asyncHandler(async (req, res) => {
  const rows = all('SELECT id, ip, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC', req.user.id, nowIso());
  return ok(res, rows.map((r) => ({ id: r.id.slice(0, 8), ip: r.ip, userAgent: r.user_agent, createdAt: r.created_at, expiresAt: r.expires_at })));
}));

/* --------------------------------- MFA --------------------------------- */

function mfaChallenge(req) {
  const token = parseCookies(req.headers.cookie).sf_mfa;
  if (!token) return null;
  return get('SELECT * FROM mfa_challenges WHERE id = ?', hashToken(token));
}

router.post('/mfa/verify', rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: 'mfa-verify' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({ code: z.string().trim().min(6).max(24) }), req.body);
  const challenge = mfaChallenge(req);
  if (!challenge) throw unauthorized('Your verification session expired. Sign in again.');
  if (new Date(challenge.expires_at).getTime() < Date.now()) {
    run('DELETE FROM mfa_challenges WHERE id = ?', challenge.id);
    throw unauthorized('Your verification session expired. Sign in again.');
  }
  if (challenge.attempts >= 5) {
    run('DELETE FROM mfa_challenges WHERE id = ?', challenge.id);
    throw unauthorized('Too many incorrect codes. Sign in again.');
  }
  const user = get('SELECT * FROM users WHERE id = ?', challenge.user_id);
  if (!user || user.status !== 'active') throw unauthorized('This account is not available');

  let accepted = verifyTotp(user.mfa_secret, body.code);
  let usedRecovery = false;
  const recovery = parseJson(user.mfa_recovery, []);
  if (!accepted) {
    const candidate = hashRecoveryCode(body.code);
    if (recovery.includes(candidate)) {
      accepted = true;
      usedRecovery = true;
      run('UPDATE users SET mfa_recovery = ?, updated_at = ? WHERE id = ?',
        JSON.stringify(recovery.filter((hash) => hash !== candidate)), nowIso(), user.id);
    }
  }
  if (!accepted) {
    run('UPDATE mfa_challenges SET attempts = attempts + 1 WHERE id = ?', challenge.id);
    throw unauthorized('That code is not valid');
  }

  run('DELETE FROM mfa_challenges WHERE id = ?', challenge.id);
  res.setHeader('Set-Cookie', 'sf_mfa=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  createSession(user, req, res);
  run('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?', nowIso(), nowIso(), user.id);
  audit(req, 'auth.login_mfa', 'user', user.id, { usedRecoveryCode: usedRecovery });
  const org = get('SELECT name FROM organizations WHERE id = ?', user.org_id);
  return ok(res, { user: publicUser(user, org?.name), usedRecoveryCode: usedRecovery, recoveryCodesRemaining: parseJson(user.mfa_recovery, []).length });
}));

router.post('/mfa/setup', requireAuth, asyncHandler(async (req, res) => {
  const body = validate(z.object({ password: z.string().min(1).max(200) }), req.body);
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.user.id, req.user.orgId);
  if (!user) throw unauthorized();
  if (user.mfa_enabled === 1) throw badRequest('Multi-factor authentication is already enabled');
  if (!verifyPassword(body.password, user.password_hash)) throw badRequest('Password is incorrect');

  const secret = generateSecret();
  const recoveryCodes = generateRecoveryCodes();
  run(
    'UPDATE users SET mfa_secret = ?, mfa_recovery = ?, mfa_enabled = 0, updated_at = ? WHERE id = ?',
    secret, JSON.stringify(recoveryCodes.map(hashRecoveryCode)), nowIso(), user.id,
  );
  audit(req, 'auth.mfa_setup_started', 'user', user.id, {});
  return ok(res, {
    secret,
    otpauth: otpauthUrl(secret, user.email),
    recoveryCodes,
    note: 'Add the secret to an authenticator app, then confirm with a six digit code to enable MFA.',
  });
}));

router.post('/mfa/enable', requireAuth, rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: 'mfa-enable' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({ code: z.string().trim().min(6).max(10) }), req.body);
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.user.id, req.user.orgId);
  if (!user || !user.mfa_secret) throw badRequest('Start MFA setup first');
  if (!verifyTotp(user.mfa_secret, body.code)) throw badRequest('That code is not valid. Check the clock on your device and try again.');
  run('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?', nowIso(), user.id);
  audit(req, 'auth.mfa_enabled', 'user', user.id, {});
  return ok(res, { enabled: true, recoveryCodesRemaining: parseJson(user.mfa_recovery, []).length });
}));

router.post('/mfa/disable', requireAuth, rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: 'mfa-disable' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({ password: z.string().min(1).max(200), code: z.string().trim().min(6).max(10) }), req.body);
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.user.id, req.user.orgId);
  if (!user || user.mfa_enabled !== 1) throw badRequest('Multi-factor authentication is not enabled');
  if (!verifyPassword(body.password, user.password_hash)) throw badRequest('Password is incorrect');
  if (!verifyTotp(user.mfa_secret, body.code)) throw badRequest('That code is not valid');
  run('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_recovery = \'[]\', updated_at = ? WHERE id = ?', nowIso(), user.id);
  audit(req, 'auth.mfa_disabled', 'user', user.id, {});
  return ok(res, { enabled: false });
}));

router.post('/mfa/recovery-codes', requireAuth, asyncHandler(async (req, res) => {
  const body = validate(z.object({ password: z.string().min(1).max(200) }), req.body);
  const user = get('SELECT * FROM users WHERE id = ? AND org_id = ?', req.user.id, req.user.orgId);
  if (!user || user.mfa_enabled !== 1) throw badRequest('Enable multi-factor authentication first');
  if (!verifyPassword(body.password, user.password_hash)) throw badRequest('Password is incorrect');
  const codes = generateRecoveryCodes();
  run('UPDATE users SET mfa_recovery = ?, updated_at = ? WHERE id = ?', JSON.stringify(codes.map(hashRecoveryCode)), nowIso(), user.id);
  audit(req, 'auth.mfa_recovery_regenerated', 'user', user.id, {});
  return ok(res, { recoveryCodes: codes });
}));

router.delete('/sessions', requireAuth, asyncHandler(async (req, res) => {
  destroySession(req, res);
  return ok(res, { ok: true });
}));

router.post('/sessions/revoke-others', requireAuth, asyncHandler(async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const current = cookies[SESSION_COOKIE] ? hashToken(cookies[SESSION_COOKIE]) : null;
  if (current) {
    run('DELETE FROM sessions WHERE user_id = ? AND id != ?', req.user.id, current);
  } else {
    run('DELETE FROM sessions WHERE user_id = ?', req.user.id);
  }
  audit(req, 'auth.sessions_revoked', 'user', req.user.id, {});
  return ok(res, { ok: true });
}));

export default router;
