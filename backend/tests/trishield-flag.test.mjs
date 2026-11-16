import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';
import { trishieldFlags } from '../src/lib/config.js';

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

test('the default flags expose TriShield with live changes still off', () => {
  // The default server is already exercised end to end by trishield-api.test.mjs
  // (GET /trishield/overview returns 200). Here only the flag defaults are
  // asserted, so this file boots a single server and cannot race the demo seed.
  const flags = trishieldFlags({});
  assert.equal(flags.enabled, true);
  assert.equal(flags.network, true);
  assert.equal(flags.endpoint, true);
  assert.equal(flags.ipShield, true);
  assert.equal(flags.response, true);
  assert.equal(flags.apply, false, 'a default install never applies firewall changes');
  assert.equal(flags.autoApply, false);
});
