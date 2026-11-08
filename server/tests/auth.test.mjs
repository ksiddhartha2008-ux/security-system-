import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

test('registration creates an organization and signs the admin in', async () => {
  const c = client(server.base);
  const email = `founder-${Date.now()}@example.test`;
  const response = await c.post('/auth/register', {
    name: 'Avery Stone', email, password: 'CorrectHorse#1', organizationName: 'Stone Labs',
  });
  assert.equal(response.status, 201);
  assert.equal(response.body.data.user.role, 'admin');
  assert.equal(response.body.data.user.email, email);
  assert.ok(c.cookie.startsWith('sf_session='));

  const me = await c.get('/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.data.user.email, email);
  assert.equal(me.body.data.permissions.canAdmin, true);
});

test('duplicate registration is rejected with 409', async () => {
  const c = client(server.base);
  const payload = {
    name: 'Duplicate User', email: `dupe-${Date.now()}@example.test`, password: 'CorrectHorse#1', organizationName: 'Dupe Co',
  };
  assert.equal((await c.post('/auth/register', payload)).status, 201);
  const second = await c.post('/auth/register', payload);
  assert.equal(second.status, 409);
  assert.equal(second.body.error.code, 'conflict');
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
