import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, markEmailVerified, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

test('registration returns the same neutral response and does not sign anyone in', async () => {
  const c = client(server.base);
  const email = `founder-${Date.now()}@example.test`;
  const payload = { name: 'Avery Stone', email, password: 'Anchor#2026', organizationName: 'Stone Labs' };
  const response = await c.post('/auth/register', payload);
  assert.equal(response.status, 202);
  assert.deepEqual(response.body.data, { message: 'If registration can be completed, check your email for the next step.' });
  assert.equal(response.headers.get('set-cookie'), null, 'registration must not create a session');
  assert.equal((await c.get('/auth/me')).status, 401);
  markEmailVerified(server, email);

  const signedIn = await login(server.base, email, payload.password);
  const me = await signedIn.get('/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.data.user.email, email);
  assert.equal(me.body.data.permissions.canAdmin, true);
});

test('duplicate registration returns the same neutral response and creates nothing', async () => {
  const email = `dupe-${Date.now()}@example.test`;
  const payload = { name: 'Duplicate User', email, password: 'Anchor#2026', organizationName: 'Dupe Co' };
  const first = await client(server.base).post('/auth/register', payload);
  const second = await client(server.base).post('/auth/register', {
    ...payload, name: 'Someone Else', password: 'Other#2026', organizationName: 'Other Org',
  });
  assert.equal(first.status, 202);
  assert.equal(second.status, 202);
  assert.deepEqual(second.body, first.body);
  markEmailVerified(server, email);

  const signedIn = await login(server.base, email, payload.password);
  const users = await signedIn.get('/settings/users');
  assert.equal(users.status, 200);
  assert.equal(users.body.data.length, 1);
  assert.equal(users.body.data[0].email, email);
  const org = await signedIn.get('/settings/organization');
  assert.equal(org.body.data.name, 'Dupe Co');
});

test('login rejects a wrong password with the same message as an unknown account', async () => {
  const c = client(server.base);
  const wrong = await c.post('/auth/login', { email: DEMO.analyst[0], password: 'not-the-password' });
  assert.equal(wrong.status, 401);
  const unknown = await c.post('/auth/login', { email: 'nobody@example.test', password: 'not-the-password' });
  assert.equal(unknown.status, 401);
  assert.equal(wrong.body.error.message, unknown.body.error.message);
});

test('session is required for protected routes and logout clears it', async () => {
  const anonymous = client(server.base);
  assert.equal((await anonymous.get('/overview/summary')).status, 401);

  const c = await login(server.base, ...DEMO.analyst);
  assert.equal((await c.get('/overview/summary')).status, 200);
  assert.equal((await c.post('/auth/logout')).status, 200);
  assert.equal((await c.get('/overview/summary')).status, 401);
});

test('validation errors return a field level envelope', async () => {
  const c = client(server.base);
  const response = await c.post('/auth/register', { name: 'x', email: 'not-an-email', password: 'short', organizationName: '' });
  assert.equal(response.status, 400);
  assert.equal(response.body.error.code, 'validation_failed');
  assert.ok(response.body.error.details.length >= 3);
});

test('viewer cannot write, analyst can', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const denied = await viewer.post('/assets', { name: 'Viewer asset', hostname: 'viewer-01' });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error.code, 'forbidden');

  const analyst = await login(server.base, ...DEMO.analyst);
  const allowed = await analyst.post('/assets', { name: 'Analyst asset', hostname: `analyst-${Date.now()}`, assetType: 'server', criticality: 'low' });
  assert.equal(allowed.status, 201);
});

test('admin only routes reject analysts', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);
  assert.equal((await analyst.get('/settings/audit-logs')).status, 403);
  assert.equal((await analyst.post('/settings/users', {
    name: 'Nope', email: 'nope@example.test', role: 'viewer', password: 'CorrectHorse#1',
  })).status, 403);
});
