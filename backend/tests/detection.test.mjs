import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

const uniqueIp = () => `203.0.113.${Math.floor(Math.random() * 200) + 20}`;

test('repeated authentication failures produce explainable detections', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const ip = uniqueIp();
  const result = await c.post('/events', {
    eventType: 'auth.failure', source: 'identity-provider', severity: 'medium', category: 'identity',
    title: 'Failed sign-in during detection test', srcIp: ip, userEmail: 'victim-one@example.test',
  });
  assert.equal(result.status, 201);
  for (let i = 0; i < 8; i += 1) {
    await c.post('/events', {
      eventType: 'auth.failure', source: 'identity-provider', severity: 'medium', category: 'identity',
      title: `Failed sign-in ${i}`, srcIp: ip, userEmail: `victim-${i % 4}@example.test`,
    });
  }
  const queue = await c.get(`/detections?q=${encodeURIComponent(ip)}&limit=50`);
  assert.equal(queue.status, 200);
  assert.ok(queue.body.data.length >= 1, 'expected at least one detection for the burst');
  const detection = queue.body.data[0];
  assert.ok(detection.riskScore >= 50);
  assert.ok(detection.explanation.factors.length >= 2, 'detection must store its scoring factors');
  assert.equal(detection.explanation.deterministic, true);

  const detail = await c.get(`/detections/${detection.id}`);
  assert.equal(detail.status, 200);
  assert.ok(detail.body.data.explanation.observed);
});

test('the same signal is not duplicated on a second rule pass', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const ip = uniqueIp();
  for (let i = 0; i < 6; i += 1) {
    await c.post('/events', {
      eventType: 'auth.failure', source: 'identity-provider', severity: 'low', category: 'identity',
      title: 'Repeated failure', srcIp: ip, userEmail: 'same@example.test',
    });
  }
  const first = await c.post('/detections/run');
  assert.equal(first.status, 200);
  const second = await c.post('/detections/run');
  assert.equal(second.status, 200);
  assert.equal(second.body.data.produced, 0, 'a repeated pass must not create duplicate detections');
});

test('detection feedback and promotion create a linked incident', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const queue = await c.get('/detections?status=open&limit=5');
  assert.ok(queue.body.data.length > 0);
  const detection = queue.body.data[0];

  const feedback = await c.post(`/detections/${detection.id}/feedback`, { status: 'confirmed', note: 'Verified in test' });
  assert.equal(feedback.status, 200);

  const promoted = await c.post(`/detections/${detection.id}/promote`);
  assert.equal(promoted.status, 201);
  assert.match(promoted.body.data.ref, /^INC-/);

  const incident = await c.get(`/incidents/${promoted.body.data.incidentId}`);
  assert.equal(incident.status, 200);
  assert.ok(incident.body.data.timeline.some((entry) => entry.type === 'created'));
});

test('disabled rules stop producing detections', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const rules = await admin.get('/detections/rules');
  const rule = rules.body.data.find((row) => row.key === 'api-rate-abuse');
  assert.ok(rule);
  assert.equal((await admin.patch(`/detections/rules/${rule.id}`, { enabled: false })).status, 200);
  const after = await admin.get('/detections/rules');
  assert.equal(after.body.data.find((row) => row.id === rule.id).enabled, false);
});
