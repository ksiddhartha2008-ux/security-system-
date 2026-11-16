import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { startServer, client, login } from './helpers.mjs';

/**
 * SF-AUTH-06. Registration must not reveal whether an address exists, and must
 * not create a session for either outcome.
 */
let server;
const neutral = { message: 'If registration can be completed, you can continue by signing in.' };
const stamp = `${Date.now()}-${Math.floor(Math.random() * 1000)}`;

before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

function payload(email, suffix = '') {
  return {
    name: `Owner ${suffix || 'One'}`,
    email,
    password: 'Anchor#2026',
    organizationName: `Workspace ${suffix || stamp}`,
  };
}

test('a new and an existing address return the same response and no cookie', async () => {
  const email = `neutral-${stamp}@example.test`;
  const firstClient = client(server.base);
  const first = await firstClient.post('/auth/register', payload(email, 'First'));
  const second = await client(server.base).post('/auth/register', payload(email, 'Second'));

  assert.equal(first.status, 202);
  assert.equal(second.status, 202);
  assert.deepEqual(second.body, first.body);
  assert.deepEqual(first.body.data, neutral);
  assert.equal(first.headers.get('set-cookie'), null);
  assert.equal(second.headers.get('set-cookie'), null);
  assert.equal(first.headers.get('location'), null);
  assert.equal(second.headers.get('location'), null);
  assert.equal((await firstClient.get('/auth/me')).status, 401, 'registration must not create a session');
  assert.equal((await client(server.base).get('/auth/me')).status, 401);
});

test('only the first request created a workspace, and the duplicate is audited', async () => {
  const email = `neutral-${stamp}@example.test`;
  const signedIn = await login(server.base, email, 'Anchor#2026');
  const users = await signedIn.get('/settings/users');
  assert.equal(users.status, 200);
  assert.equal(users.body.data.length, 1);
  assert.equal(users.body.data[0].email, email);

  const org = await signedIn.get('/settings/organization');
  assert.equal(org.body.data.name, `Workspace First`);

  const logs = await signedIn.get('/settings/audit-logs?limit=100');
  assert.ok(logs.body.data.some((row) => row.action === 'auth.register'), 'the new workspace owns its registration audit entry');

  // The duplicate belongs to no tenant, so it is recorded on the system chain.
  const db = new DatabaseSync(join(server.dir, 'test.db'), { readOnly: true });
  const duplicates = db.prepare("SELECT COUNT(*) AS c FROM audit_logs WHERE action = 'auth.register_duplicate'").get().c;
  db.close();
  assert.ok(duplicates >= 1);
});

test('normalisation is shared with login and duplicate checks', async () => {
  const base = `mixed-${stamp}@example.test`;
  const registered = await client(server.base).post('/auth/register', payload(`  ${base.toUpperCase()}  `, 'Mixed'));
  assert.equal(registered.status, 202);

  const duplicate = await client(server.base).post('/auth/register', payload(base.toLowerCase(), 'Mixed Duplicate'));
  assert.equal(duplicate.status, 202);
  assert.deepEqual(duplicate.body, registered.body);

  const signedIn = await login(server.base, base.toLowerCase(), 'Anchor#2026');
  const users = await signedIn.get('/settings/users');
  assert.equal(users.body.data.length, 1);
});

test('invalid input is still a validation error, not a neutral response', async () => {
  const response = await client(server.base).post('/auth/register', { name: 'x', email: 'not-an-email', password: 'short', organizationName: '' });
  assert.equal(response.status, 400);
  assert.equal(response.body.error.code, 'validation_failed');
});

test('the sixth request is accepted and the seventh is limited, whatever the address', async () => {
  const sixth = await client(server.base).post('/auth/register', payload(`sixth-${stamp}@example.test`, 'Sixth'));
  assert.equal(sixth.status, 202);

  const limited = await client(server.base).post('/auth/register', payload(`neutral-${stamp}@example.test`, 'Limited'));
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error.code, 'rate_limited');
});

test('simultaneous requests for one address create exactly one workspace', async () => {
  const isolated = await startServer();
  try {
    const email = `race-${Date.now()}@example.test`;
    const attempts = Array.from({ length: 5 }, (_, index) => (
      fetch(`${isolated.base}/auth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload(email, `Race ${index}`)),
      }).then(async (response) => ({ status: response.status, body: await response.json() }))
    ));
    const results = await Promise.all(attempts);
    assert.ok(results.every((row) => row.status === 202), JSON.stringify(results.map((row) => row.status)));
    assert.ok(results.every((row) => JSON.stringify(row.body) === JSON.stringify(results[0].body)));

    const db = new DatabaseSync(join(isolated.dir, 'test.db'), { readOnly: true });
    const users = db.prepare('SELECT COUNT(*) AS c FROM users WHERE email = ?').get(email).c;
    const orphans = db.prepare(`SELECT COUNT(*) AS c FROM organizations o
      WHERE o.id NOT IN (SELECT org_id FROM users)`).get().c;
    db.close();
    assert.equal(users, 1, 'one user for the address');
    assert.equal(orphans, 0, 'no organisation without a user');

    const signedIn = await login(isolated.base, email, 'Anchor#2026');
    const list = await signedIn.get('/settings/users');
    assert.equal(list.body.data.length, 1);
  } finally {
    isolated.stop();
  }
});
