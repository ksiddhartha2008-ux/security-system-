import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

async function waitForCompletion(c, id, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    const response = await c.get(`/simulations/${id}`);
    last = response.body.data;
    if (['completed', 'failed', 'cancelled'].includes(last.status)) return last;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error(`simulation did not settle in time: ${JSON.stringify(last)}`);
}

test('all simulation scenarios are exposed with agent rosters', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const response = await c.get('/simulations/scenarios');
  assert.equal(response.status, 200);
  assert.equal(response.body.data.length, 9);
  const keys = response.body.data.map((row) => row.key).sort();
  assert.deepEqual(keys, [
    'api-abuse', 'brute-force', 'credential-stuffing', 'insider-threat', 'malware',
    'phishing', 'ransomware', 'sql-injection', 'suspicious-admin',
  ]);
  for (const scenario of response.body.data) {
    assert.ok(scenario.agents.length >= 3);
    assert.ok(Object.keys(scenario.defaultConfig).length >= 3);
  }
});

test('an unknown scenario is rejected', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const response = await c.post('/simulations', { scenario: 'not-a-scenario' });
  assert.equal(response.status, 400);
});

test('a run executes rounds, records agents and produces a report', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const created = await c.post('/simulations', {
    scenario: 'ransomware', totalRounds: 4, seed: 424242, name: 'Test ransomware run',
    config: { edrEnabled: true, backupsImmutable: true },
  });
  assert.equal(created.status, 201);
  const id = created.body.data.id;

  const started = await c.post(`/simulations/${id}/start`);
  assert.equal(started.status, 200);

  const finished = await waitForCompletion(c, id);
  assert.equal(finished.status, 'completed');
  assert.equal(finished.progress, 100);
  assert.equal(finished.currentRound, 4);
  assert.ok(finished.events.length > 0);
  assert.ok(finished.agents.some((agent) => agent.activityCount > 0));
  assert.ok(finished.report, 'a completed run must store a report');
  assert.ok(finished.report.findings.length >= 3);
  assert.ok(finished.report.recommendations.length >= 3);
  assert.equal(finished.summary.synthetic, true);
  assert.ok(finished.riskScore >= 1 && finished.riskScore <= 100);
  assert.ok(finished.events.every((event) => event.metadata.synthetic === true));
});

test('a running simulation can be cancelled and keeps its status', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const created = await c.post('/simulations', { scenario: 'phishing', totalRounds: 20, name: 'Cancel me' });
  const id = created.body.data.id;
  assert.equal((await c.post(`/simulations/${id}/start`)).status, 200);
  const cancelled = await c.post(`/simulations/${id}/cancel`);
  assert.equal(cancelled.status, 200);
  const detail = await c.get(`/simulations/${id}`);
  assert.equal(detail.body.data.status, 'cancelled');
});

test('a second start on a completed run is rejected', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const list = await c.get('/simulations?status=completed&limit=1');
  assert.ok(list.body.data.length > 0);
  const response = await c.post(`/simulations/${list.body.data[0].id}/start`);
  assert.equal(response.status, 400);
});

test('MiroFish reports an honest unconfigured state', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const status = await c.get('/simulations/mirofish/status');
  assert.equal(status.status, 200);
  assert.equal(status.body.data.configured, false);
  assert.equal(status.body.data.reachable, false);
  assert.match(status.body.data.reason, /MIROFISH_BASE_URL/);
  assert.equal(status.body.data.license, 'AGPL-3.0');

  const imported = await c.post('/simulations/mirofish/import', { remoteId: 'sim_test123' });
  assert.equal(imported.status, 400);
  assert.match(imported.body.error.message, /not configured/i);
});
