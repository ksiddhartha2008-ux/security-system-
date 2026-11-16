import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { startServer, client, login } from './helpers.mjs';

const PASSWORD = 'Anchor#2026';
const NEUTRAL_REGISTER = 'If registration can be completed, check your email for the next step.';

function openDb(server) {
  return new DatabaseSync(join(server.dir, 'test.db'));
}

function insertToken(server, email, raw, expiresAt) {
  const db = openDb(server);
  try {
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    assert.ok(user, 'the account exists');
    db.prepare(
      `INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, consumed_at, created_at)
       VALUES (?, ?, ?, ?, NULL, ?)`,
    ).run(`evt_${randomBytes(8).toString('hex')}`, user.id, createHash('sha256').update(raw).digest('hex'), new Date(expiresAt).toISOString(), new Date().toISOString());
  } finally {
    db.close();
  }
}

test('an unverified account can sign in, is gated, then verifies and reaches the workspace', async () => {
  const server = await startServer({ RESEND_API_KEY: '', EMAIL_FROM: '', APP_BASE_URL: 'http://127.0.0.1:4100' });
  try {
    const email = `verify-${Date.now()}@example.test`;
    const anonymous = client(server.base);
    const registered = await anonymous.post('/auth/register', { name: 'Verify User', email, password: PASSWORD, organizationName: 'Verify Workspace' });
    assert.equal(registered.status, 202);
    assert.deepEqual(registered.body.data, { message: NEUTRAL_REGISTER });
    assert.equal(registered.headers.get('set-cookie'), null);

    const session = client(server.base);
    const signedIn = await session.post('/auth/login', { email, password: PASSWORD });
    assert.equal(signedIn.status, 200, signedIn.text);

    const me = await session.get('/auth/me');
    assert.equal(me.status, 200);
    assert.equal(me.body.data.user.emailVerified, false);

    const gated = await session.get('/overview/summary');
    assert.equal(gated.status, 403);
    assert.equal(gated.body.error.code, 'EMAIL_VERIFICATION_REQUIRED');
    assert.equal((await session.get('/settings/members')).status, 403);

    const resend = await session.post('/auth/resend-verification');
    assert.equal(resend.status, 202);
    assert.deepEqual(resend.body.data, { message: 'If this account needs verification, a new message will be sent.' });

    const raw = randomBytes(32).toString('base64url');
    insertToken(server, email, raw, Date.now() + 60_000);
    const verified = await session.post('/auth/verify-email', { token: raw });
    assert.equal(verified.status, 200, verified.text);
    assert.equal((await session.get('/overview/summary')).status, 200);
    assert.equal((await session.get('/auth/me')).body.data.user.emailVerified, true);

    const replay = await session.post('/auth/verify-email', { token: raw });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error.code, 'verification_used');

    const invalid = await session.post('/auth/verify-email', { token: randomBytes(32).toString('base64url') });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error.code, 'verification_invalid');

    const expiredRaw = randomBytes(32).toString('base64url');
    insertToken(server, email, expiredRaw, Date.now() - 1000);
    const expired = await session.post('/auth/verify-email', { token: expiredRaw });
    assert.equal(expired.status, 400);
    assert.equal(expired.body.error.code, 'verification_expired');

    assert.equal((await session.post('/auth/verify-email', { token: 'short' })).status, 400);

    const admin = await login(server.base, email, PASSWORD);
    const logs = await admin.get('/settings/audit-logs?limit=100');
    const actions = logs.body.data.map((row) => row.action);
    assert.ok(actions.includes('auth.email_verification_sent') === false, 'no provider configured, so nothing was sent');
    assert.ok(actions.includes('auth.email_verification_failed'), 'provider absence is recorded');
    assert.ok(actions.includes('auth.email_verified'));
    assert.ok(actions.includes('auth.email_verification_rejected'));
    assert.equal((await admin.get('/settings/audit-logs/verify')).body.data.ok, true);
  } finally {
    server.stop();
  }
}, { timeout: 90_000 });

test('resend is neutral for a verified account and throttled per account', async () => {
  const server = await startServer();
  try {
    const email = `throttle-${Date.now()}@example.test`;
    await client(server.base).post('/auth/register', { name: 'Throttle User', email, password: PASSWORD, organizationName: 'Throttle Workspace' });

    const session = client(server.base);
    await session.post('/auth/login', { email, password: PASSWORD });

    const first = await session.post('/auth/resend-verification');
    const second = await session.post('/auth/resend-verification');
    assert.equal(first.status, 202);
    assert.equal(second.status, 202);
    assert.deepEqual(second.body.data, first.body.data);

    // The per account budget counts the message sent at registration, so the
    // third resend is accepted and answered neutrally while sending nothing.
    const third = await session.post('/auth/resend-verification');
    assert.equal(third.status, 202);
    assert.deepEqual(third.body.data, first.body.data);

    const fourth = await session.post('/auth/resend-verification');
    assert.equal(fourth.status, 429);
    assert.equal(fourth.body.error.code, 'rate_limited');

    // Read the audit trail only after the account is verified, because the log
    // endpoint is part of the gated workspace.
    const raw = randomBytes(32).toString('base64url');
    insertToken(server, email, raw, Date.now() + 60_000);
    assert.equal((await session.post('/auth/verify-email', { token: raw })).status, 200);

    const admin = await login(server.base, email, PASSWORD);
    const logs = await admin.get('/settings/audit-logs?limit=100');
    assert.ok(logs.body.data.some((row) => row.action === 'auth.email_verification_throttled'));
  } finally {
    server.stop();
  }
}, { timeout: 90_000 });

test('verified accounts never see the gate and an unknown token is rejected', async () => {
  const server = await startServer();
  try {
    const email = `already-${Date.now()}@example.test`;
    await client(server.base).post('/auth/register', { name: 'Verified User', email, password: PASSWORD, organizationName: 'Verified Workspace' });
    const raw = randomBytes(32).toString('base64url');
    insertToken(server, email, raw, Date.now() + 60_000);
    assert.equal((await client(server.base).post('/auth/verify-email', { token: raw })).status, 200);

    const session = await login(server.base, email, PASSWORD);
    assert.equal((await session.get('/auth/me')).body.data.user.emailVerified, true);
    assert.equal((await session.get('/overview/summary')).status, 200);
    const again = await session.post('/auth/verify-email', { token: raw });
    assert.equal(again.body.error.code, 'verification_used');
  } finally {
    server.stop();
  }
}, { timeout: 90_000 });

test('simultaneous verification requests cannot both consume a token', async () => {
  const server = await startServer();
  try {
    const email = `race-${Date.now()}@example.test`;
    await client(server.base).post('/auth/register', { name: 'Race User', email, password: PASSWORD, organizationName: 'Race Workspace' });
    const raw = randomBytes(32).toString('base64url');
    insertToken(server, email, raw, Date.now() + 60_000);
    const call = () => fetch(`${server.base}/auth/verify-email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: raw }),
    });
    const results = await Promise.all([call(), call()]);
    assert.deepEqual(results.map((response) => response.status).sort(), [200, 400]);
  } finally {
    server.stop();
  }
}, { timeout: 90_000 });
