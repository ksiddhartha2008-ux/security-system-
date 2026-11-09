import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

async function newWorkspace(suffix = '') {
  const c = client(server.base);
  const email = `demo-owner-${Date.now()}${suffix}@example.test`;
  const response = await c.post('/auth/register', {
    name: 'Demo Owner', email, password: 'CorrectHorse#1', organizationName: `Demo Workspace ${suffix || Date.now()}`,
  });
  assert.equal(response.status, 201);
  return { c, email };
}

async function waitForSimulation(c, id, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    const response = await c.get(`/simulations/${id}`);
    last = response.body.data;
    if (['completed', 'failed', 'cancelled'].includes(last.status)) return last;
    await new Promise((resolve) => setTimeout(resolve, 350));
  }
  throw new Error(`simulation did not settle: ${JSON.stringify(last)}`);
}

test('demo generation creates a coherent dataset through the real pipeline', async () => {
  const { c } = await newWorkspace('a');

  const empty = await c.get('/demo/status');
  assert.equal(empty.status, 200);
  assert.equal(empty.body.data.hasDemoData, false);
  assert.equal(empty.body.data.counts.events.DEMO ?? 0, 0);

  const generated = await c.post('/demo/generate');
  assert.equal(generated.status, 201);
  const counts = generated.body.data.counts;
  assert.equal(counts.assets, 45);
  assert.ok(counts.events >= 250, `expected about 250 events, got ${counts.events}`);
  assert.ok(counts.detections >= 5, `expected detections, got ${counts.detections}`);
  assert.ok(counts.incidents >= 3, `expected correlated incidents, got ${counts.incidents}`);
  assert.equal(counts.vulnerabilities, 14);
  assert.ok(counts.networkEvents >= 80);

  const status = await c.get('/demo/status');
  assert.equal(status.body.data.hasDemoData, true);
  assert.equal(status.body.data.batchId, generated.body.data.batchId);
  assert.equal(status.body.data.counts.assets.DEMO, 45);

  const summary = await c.get('/overview/summary');
  assert.equal(summary.status, 200);
  assert.equal(summary.body.data.kpis.eventsTotal, counts.events);
  assert.ok(summary.body.data.kpis.incidentsTotal >= counts.incidents);
  assert.ok(summary.body.data.kpis.detectionsOpen > 0);
  assert.ok(summary.body.data.kpis.assetsAtRisk > 0);

  const events = await c.get('/events?limit=5');
  assert.equal(events.body.meta.total, counts.events);
  assert.ok(events.body.data.every((event) => event.dataOrigin === 'DEMO'));

  const incidents = await c.get('/incidents?limit=5');
  assert.ok(incidents.body.data.length > 0);
  assert.ok(incidents.body.data.every((incident) => incident.dataOrigin === 'DEMO'));

  const detail = await c.get(`/incidents/${incidents.body.data[0].id}`);
  assert.equal(detail.status, 200);
  assert.ok(detail.body.data.timeline.length >= 2);

  const duplicate = await c.post('/demo/generate');
  assert.equal(duplicate.status, 409);
});

test('demo data is tenant scoped', async () => {
  const { c: first } = await newWorkspace('b');
  await first.post('/demo/generate');
  const firstCounts = (await first.get('/demo/status')).body.data.counts.events.DEMO;

  const { c: second } = await newWorkspace('c');
  const secondStatus = await second.get('/demo/status');
  assert.equal(secondStatus.body.data.hasDemoData, false);
  assert.equal(secondStatus.body.data.counts.events.DEMO ?? 0, 0);

  const secondEvents = await second.get('/events?limit=5');
  assert.equal(secondEvents.body.meta.total, 0);
  assert.ok(firstCounts > 0);
});

test('reset removes only demo rows and preserves real records', async () => {
  const { c } = await newWorkspace('d');
  await c.post('/demo/generate');

  const realAsset = await c.post('/assets', { name: 'Real production host', hostname: 'real-prod-01', criticality: 'critical' });
  assert.equal(realAsset.status, 201);
  const realIncident = await c.post('/incidents', { title: 'Real incident that must survive reset', severity: 'high' });
  assert.equal(realIncident.status, 201);

  const missingConfirm = await c.post('/demo/reset', {});
  assert.equal(missingConfirm.status, 400);

  const reset = await c.post('/demo/reset', { confirm: 'RESET' });
  assert.equal(reset.status, 200);
  assert.ok(reset.body.data.deleted.events >= 250);

  const status = await c.get('/demo/status');
  assert.equal(status.body.data.hasDemoData, false);
  assert.equal(status.body.data.counts.events.DEMO ?? 0, 0);
  assert.equal(status.body.data.counts.assets.DEMO ?? 0, 0);
  assert.equal(status.body.data.counts.incidents.DEMO ?? 0, 0);

  const assets = await c.get('/assets?limit=100');
  assert.equal(assets.body.meta.total, 1);
  assert.equal(assets.body.data[0].hostname, 'real-prod-01');

  const incidents = await c.get('/incidents?limit=100');
  assert.equal(incidents.body.meta.total, 1);
  assert.equal(incidents.body.data[0].title, 'Real incident that must survive reset');
});

test('simulation output feeds events, detections and dashboard metrics', async () => {
  const { c } = await newWorkspace('e');
  const created = await c.post('/simulations', { scenario: 'brute-force', totalRounds: 4, seed: 424242, name: 'Pipeline check' });
  assert.equal(created.status, 201);
  assert.equal((await c.post(`/simulations/${created.body.data.id}/start`)).status, 200);
  const finished = await waitForSimulation(c, created.body.data.id);
  assert.equal(finished.status, 'completed');

  const events = await c.get('/events?source=simulation&limit=100');
  assert.equal(events.status, 200);
  assert.ok(events.body.meta.total > 0, 'simulation events must reach the security event table');
  assert.ok(events.body.data.every((event) => event.dataOrigin === 'SIMULATED'));

  const detections = await c.get('/detections?limit=100');
  assert.ok(detections.body.data.some((detection) => detection.dataOrigin === 'SIMULATED'), 'detection engine must score simulation events');

  const summary = await c.get('/overview/summary');
  assert.ok(summary.body.data.kpis.eventsTotal > 0);

  // A reset with no demo batch must not touch simulated records.
  const reset = await c.post('/demo/reset', { confirm: 'RESET' });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.data.nothingToDo, true);
  const after = await c.get('/events?source=simulation&limit=100');
  assert.ok(after.body.meta.total > 0);
});

test('only administrators can manage demo data', async () => {
  const viewer = await login(server.base, ...DEMO.viewer);
  const generated = await viewer.post('/demo/generate');
  assert.equal(generated.status, 403);

  const analyst = await login(server.base, ...DEMO.analyst);
  const run = await analyst.post('/demo/scenarios/brute-force/run');
  assert.equal(run.status, 403);
});
