import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';

/**
 * Feature flags must fail closed at the server, not only in the navigation.
 * With TRISHIELD_ENABLED=false the API is not mounted at all.
 */
let server;
before(async () => { server = await startServer({ TRISHIELD_ENABLED: 'false' }); }, { timeout: 60_000 });
after(() => server?.stop());

test('a disabled feature removes the API surface instead of hiding it in the client', async () => {
  const admin = await login(server.base, ...DEMO.admin);

  const overview = await admin.get('/trishield/overview');
  assert.equal(overview.status, 404);

  const ingest = await fetch(`${server.base}/trishield/ingest/suricata`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer tsk_whatever' },
    body: JSON.stringify([{ event_type: 'alert' }]),
  });
  assert.equal(ingest.status, 404);

  const me = await admin.get('/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.data.features.trishield.enabled, false);
  assert.equal(me.body.data.features.trishield.apply, false);
  assert.equal(me.body.data.features.trishield.autoApply, false);
});

test('the default deployment exposes TriShield with live changes still off', async () => {
  const defaults = await startServer();
  try {
    const admin = await login(defaults.base, ...DEMO.admin);
    const me = await admin.get('/auth/me');
    assert.equal(me.body.data.features.trishield.enabled, true);
    assert.equal(me.body.data.features.trishield.apply, false, 'a default install never applies firewall changes');
    assert.equal(me.body.data.features.trishield.autoApply, false);
    assert.equal((await admin.get('/trishield/overview')).status, 200);
  } finally {
    defaults.stop();
  }
});
