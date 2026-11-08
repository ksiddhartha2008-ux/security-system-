import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, client, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

async function createSecondWorkspace() {
  const c = client(server.base);
  const email = `owner-${Date.now()}-${Math.floor(Math.random() * 1000)}@example.test`;
  const response = await c.post('/auth/register', {
    name: 'Isolation Owner', email, password: 'CorrectHorse#1', organizationName: 'Second Workspace',
  });
  assert.equal(response.status, 201);
  return c;
}

test('records from another organization are invisible and immutable', async () => {
  const other = await createSecondWorkspace();
  const asset = await other.post('/assets', { name: 'Other org secret host', hostname: 'other-secret-01', criticality: 'critical' });
  assert.equal(asset.status, 201);
  const assetId = asset.body.data.id;

  const incident = await other.post('/incidents', { title: 'Other org incident', severity: 'high' });
  assert.equal(incident.status, 201);
  const incidentId = incident.body.data.id;

  const simulation = await other.post('/simulations', { scenario: 'phishing', totalRounds: 3 });
  assert.equal(simulation.status, 201);
  const simulationId = simulation.body.data.id;

  const demo = await login(server.base, ...DEMO.analyst);
  const demoAdmin = await login(server.base, ...DEMO.admin);

  assert.equal((await demo.get(`/assets/${assetId}`)).status, 404);
  assert.equal((await demo.patch(`/assets/${assetId}`, { criticality: 'low' })).status, 404);
  assert.equal((await demo.del(`/assets/${assetId}`)).status, 403, 'viewers and analysts cannot delete assets at all');
  assert.equal((await demoAdmin.del(`/assets/${assetId}`)).status, 404);
  assert.equal((await demo.get(`/incidents/${incidentId}`)).status, 404);
  assert.equal((await demo.get(`/simulations/${simulationId}`)).status, 404);
  assert.equal((await demo.post(`/simulations/${simulationId}/start`)).status, 404);

  const demoAssets = await demo.get('/assets?limit=100');
  const ids = demoAssets.body.data.map((row) => row.id);
  assert.ok(!ids.includes(assetId), 'second workspace asset leaked into the demo list');

  // The other workspace also cannot see demo data.
  const otherAssets = await other.get('/assets?limit=100');
  assert.equal(otherAssets.status, 200);
  assert.equal(otherAssets.body.data.length, 1);
  assert.equal(otherAssets.body.data[0].id, assetId);
});

test('the organization id in the request body is ignored', async () => {
  const demo = await login(server.base, ...DEMO.analyst);
  const before = await demo.get('/assets?limit=100');
  const attempt = await demo.post('/assets', {
    name: 'Tenant override attempt', hostname: 'override-01', orgId: 'org_other', organizationId: 'org_other',
  });
  assert.equal(attempt.status, 201);
  const after = await demo.get('/assets?limit=100');
  assert.equal(after.body.meta.total, before.body.meta.total + 1);
  const created = after.body.data.find((row) => row.hostname === 'override-01');
  assert.ok(created, 'asset should belong to the session organization');
});

test('cross origin writes are rejected by the origin check', async () => {
  const demo = await login(server.base, ...DEMO.analyst);
  const response = await demo.request('POST', '/assets', { name: 'CSRF attempt', hostname: 'csrf-01' }, { origin: 'https://evil.example' });
  assert.equal(response.status, 403);
  assert.equal(response.body.error.code, 'origin_rejected');
});
