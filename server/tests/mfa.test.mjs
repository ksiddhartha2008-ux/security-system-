import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, DEMO } from './helpers.mjs';
import { totp } from '../src/lib/totp.js';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

test('MFA enrol, login step-up, recovery code and disable', async () => {
  const account = [`mfa-${Date.now()}@example.test`, 'CorrectHorse#1'];
  const owner = client(server.base);
  const registered = await owner.post('/auth/register', {
    name: 'MFA Tester', email: account[0], password: account[1], organizationName: 'MFA Lab',
  });
  assert.equal(registered.status, 201);

  // Setup requires the password and returns a secret plus recovery codes.
  const wrongPassword = await owner.post('/auth/mfa/setup', { password: 'not-it' });
  assert.equal(wrongPassword.status, 400);
  const setup = await owner.post('/auth/mfa/setup', { password: account[1] });
  assert.equal(setup.status, 200);
  assert.ok(setup.body.data.secret.length >= 16);
  assert.equal(setup.body.data.recoveryCodes.length, 8);
  assert.match(setup.body.data.otpauth, /^otpauth:\/\/totp\//);

  const secret = setup.body.data.secret;
  const recovery = setup.body.data.recoveryCodes[0];

  // A wrong code does not enable MFA.
  assert.equal((await owner.post('/auth/mfa/enable', { code: '000000' })).status, 400);
  const enabled = await owner.post('/auth/mfa/enable', { code: totp(secret) });
  assert.equal(enabled.status, 200);
  assert.equal(enabled.body.data.enabled, true);

  const me = await owner.get('/auth/me');
  assert.equal(me.body.data.user.mfaEnabled, true);

  // Password alone no longer creates a session.
  const second = client(server.base);
  const loginResponse = await second.post('/auth/login', { email: account[0], password: account[1] });
  assert.equal(loginResponse.status, 200);
  assert.equal(loginResponse.body.data.mfaRequired, true);
  assert.ok(second.cookies.sf_mfa, 'challenge cookie expected');
  assert.equal((await second.get('/auth/me')).status, 401, 'no session before the second factor');

  const badCode = await second.post('/auth/mfa/verify', { code: '123456' });
  assert.equal(badCode.status, 401);
  assert.equal((await second.get('/auth/me')).status, 401);

  const verified = await second.post('/auth/mfa/verify', { code: totp(secret) });
  assert.equal(verified.status, 200);
  assert.equal((await second.get('/auth/me')).status, 200);

  // Recovery codes are single use.
  const third = client(server.base);
  const thirdLogin = await third.post('/auth/login', { email: account[0], password: account[1] });
  assert.equal(thirdLogin.body.data.mfaRequired, true);
  const recovered = await third.post('/auth/mfa/verify', { code: recovery });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.data.usedRecoveryCode, true);

  const fourth = client(server.base);
  await fourth.post('/auth/login', { email: account[0], password: account[1] });
  const reused = await fourth.post('/auth/mfa/verify', { code: recovery });
  assert.equal(reused.status, 401, 'a recovery code must not work twice');

  // Disabling requires both the password and a live code.
  const disableWrong = await second.post('/auth/mfa/disable', { password: account[1], code: '000000' });
  assert.equal(disableWrong.status, 400);
  const disabled = await second.post('/auth/mfa/disable', { password: account[1], code: totp(secret) });
  assert.equal(disabled.status, 200);
  assert.equal((await second.get('/auth/me')).body.data.user.mfaEnabled, false);
});

test('demo accounts endpoint is gated by demo mode', async () => {
  const anonymous = client(server.base);
  const response = await anonymous.get('/auth/demo-accounts');
  assert.equal(response.status, 200);
  // The test harness runs with NODE_ENV=test, which keeps demo mode on.
  assert.ok(Array.isArray(response.body.data));
});

test('MFA endpoints require a session', async () => {
  const anonymous = client(server.base);
  assert.equal((await anonymous.post('/auth/mfa/setup', { password: 'x' })).status, 401);
  assert.equal((await anonymous.post('/auth/mfa/enable', { code: '123456' })).status, 401);
  assert.equal((await anonymous.post('/auth/mfa/verify', { code: '123456' })).status, 401);
});
