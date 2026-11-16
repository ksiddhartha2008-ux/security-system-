import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, markEmailVerified } from './helpers.mjs';
import { totp } from '../src/lib/totp.js';

/**
 * SF-AUTH-01: an administrator without an enrolled second factor cannot change
 * state, even when calling the API directly. Reading and enrolment stay open.
 */
let server;
let admin;
let password;
let secret;

before(async () => {
  server = await startServer();
  password = 'Anchor#2026';
  admin = client(server.base);
  const email = `mfa-gate-${Date.now()}@example.test`;
  const registered = await admin.post('/auth/register', {
    name: 'MFA Gate Admin',
    email,
    password,
    organizationName: `MFA Gate ${Date.now()}`,
  });
  assert.equal(registered.status, 202, registered.text);
  markEmailVerified(server, email);
  const signedIn = await admin.post('/auth/login', { email, password });
  assert.equal(signedIn.status, 200, signedIn.text);
}, { timeout: 60_000 });

after(() => server?.stop());

test('an unenrolled administrator is refused on every privileged mutation', async () => {
  const attempts = [
    ['POST', '/settings/users', { name: 'Blocked User', email: 'blocked@example.test', role: 'viewer', password: 'Blocked#2026' }],
    ['PATCH', '/settings/organization', { name: 'Renamed' }],
    ['POST', '/v1/websites', { url: 'https://blocked.example.test', display_name: 'Blocked' }],
    ['POST', '/trishield/collectors', { kind: 'suricata', name: 'blocked collector' }],
    ['POST', '/trishield/actions/missing/approve', {}],
    ['PATCH', '/trishield/policies/missing', { enabled: true }],
    ['POST', '/demo/reset', {}],
  ];
  for (const [method, path, body] of attempts) {
    const response = await admin.request(method, path, body);
    assert.equal(response.status, 403, `${method} ${path} returned ${response.status} ${response.text}`);
    assert.equal(response.body.error.code, 'ADMIN_MFA_ENROLLMENT_REQUIRED', `${method} ${path}`);
    assert.match(response.body.error.message, /Enrol multi-factor/i);
  }
});

test('reads and the enrolment endpoints remain available', async () => {
  assert.equal((await admin.get('/settings/users')).status, 200);
  assert.equal((await admin.get('/settings/organization')).status, 200);
  assert.equal((await admin.get('/auth/me')).status, 200);

  const setup = await admin.post('/auth/mfa/setup', { password });
  assert.equal(setup.status, 200, setup.text);
  secret = setup.body.data.secret;
  assert.ok(secret.length >= 16);
  assert.equal(setup.body.data.recoveryCodes.length, 8);
});

test('MFA cannot be enabled with a wrong code', async () => {
  const wrong = await admin.post('/auth/mfa/enable', { code: '000000' });
  assert.equal(wrong.status, 400);
  const me = await admin.get('/auth/me');
  assert.equal(me.body.data.user.mfaEnabled, false);
});

test('after a real TOTP enrolment the same mutations succeed', async () => {
  const enabled = await admin.post('/auth/mfa/enable', { code: totp(secret) });
  assert.equal(enabled.status, 200, enabled.text);

  const created = await admin.post('/settings/users', {
    name: 'Allowed Analyst', email: `analyst-${Date.now()}@example.test`, role: 'analyst', password: 'Analyst#2026',
  });
  assert.equal(created.status, 201, created.text);
  assert.equal(created.body.data.role, 'analyst');

  const renamed = await admin.patch('/settings/organization', { name: 'MFA Gate Renamed' });
  assert.equal(renamed.status, 200, renamed.text);
});

test('the denial is written to the audit chain', async () => {
  const logs = await admin.get('/settings/audit-logs?limit=100');
  assert.equal(logs.status, 200);
  assert.ok(logs.body.data.some((row) => row.action === 'auth.admin_mfa_required'));
  const verify = await admin.get('/settings/audit-logs/verify');
  assert.equal(verify.status, 200);
  assert.equal(verify.body.data.ok, true);
});

test('password-only step-up is refused once MFA is active', async () => {
  const passwordOnly = await admin.post('/auth/step-up', { password });
  assert.equal(passwordOnly.status, 400);
  assert.match(passwordOnly.body.error.message, /six digit code/i);

  const withCode = await admin.post('/auth/step-up', { password, code: totp(secret) });
  assert.equal(withCode.status, 200, withCode.text);
});

test('analysts and viewers keep their existing boundaries', async () => {
  const analystEmail = `mfa-analyst-${Date.now()}@example.test`;
  const viewerEmail = `mfa-viewer-${Date.now()}@example.test`;
  assert.equal((await admin.post('/settings/users', { name: 'Analyst Two', email: analystEmail, role: 'analyst', password: 'Analyst#2026' })).status, 201);
  assert.equal((await admin.post('/settings/users', { name: 'Viewer Two', email: viewerEmail, role: 'viewer', password: 'Viewer#2026' })).status, 201);

  markEmailVerified(server, analystEmail);
  markEmailVerified(server, viewerEmail);
  const analyst = await login(server.base, analystEmail, 'Analyst#2026');
  const incident = await analyst.post('/incidents', { title: 'Analyst without MFA opens an incident', severity: 'medium' });
  assert.equal(incident.status, 201, incident.text);

  const viewer = await login(server.base, viewerEmail, 'Viewer#2026');
  const denied = await viewer.patch('/settings/organization', { name: 'Viewer Rename' });
  assert.equal(denied.status, 403);
  assert.notEqual(denied.body.error.code, 'ADMIN_MFA_ENROLLMENT_REQUIRED');
});
