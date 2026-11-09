import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { startServer, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

test('incident lifecycle enforces allowed transitions', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const created = await c.post('/incidents', {
    title: 'Workflow transition test', description: 'Exercises the lifecycle guard.', severity: 'high', priority: 'P2',
  });
  assert.equal(created.status, 201);
  const id = created.body.data.id;

  const skip = await c.patch(`/incidents/${id}`, { status: 'resolved' });
  assert.equal(skip.status, 400, 'open to resolved must be rejected');

  assert.equal((await c.patch(`/incidents/${id}`, { status: 'investigating' })).status, 200);
  assert.equal((await c.patch(`/incidents/${id}`, { status: 'contained' })).status, 200);
  const resolved = await c.patch(`/incidents/${id}`, { status: 'resolved' });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.body.data.status, 'resolved');

  const detail = await c.get(`/incidents/${id}`);
  assert.ok(detail.body.data.resolvedAt);
  const transitions = detail.body.data.timeline.filter((entry) => entry.type === 'status');
  assert.equal(transitions.length, 3);
});

test('incident notes appear in the timeline', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const created = await c.post('/incidents', { title: 'Note test', severity: 'medium' });
  const id = created.body.data.id;
  const note = await c.post(`/incidents/${id}/notes`, { message: 'Reviewed the endpoint telemetry, nothing else matched.' });
  assert.equal(note.status, 201);
  const detail = await c.get(`/incidents/${id}`);
  assert.ok(detail.body.data.timeline.some((entry) => entry.type === 'note' && entry.message.includes('endpoint telemetry')));
});

test('evidence is hashed on intake, verified, and tampering is detected', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const content = Buffer.from('secureflow evidence integrity test payload', 'utf8');
  const created = await c.post('/forensics', {
    caseRef: 'CASE-TEST-1',
    filename: '../../evil path.txt',
    description: 'Integrity test',
    mimeType: 'text/plain',
    contentBase64: content.toString('base64'),
  });
  assert.equal(created.status, 201);
  const id = created.body.data.id;
  const expected = createHash('sha256').update(content).digest('hex');
  assert.equal(created.body.data.sha256, expected);
  assert.ok(!created.body.data.filename.includes('..'), 'filename must be sanitised');

  const verified = await c.post(`/forensics/${id}/verify`);
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.match, true);

  // Tamper with the stored artefact directly and confirm the check fails.
  const evidenceDir = join(server.dir, 'evidence');
  const stored = readdirSync(evidenceDir).find((name) => name.startsWith(id));
  assert.ok(stored, 'stored evidence file should exist');
  writeFileSync(join(evidenceDir, stored), Buffer.from('tampered content', 'utf8'));
  assert.notEqual(readFileSync(join(evidenceDir, stored)).toString(), content.toString());

  const after = await c.post(`/forensics/${id}/verify`);
  assert.equal(after.status, 200);
  assert.equal(after.body.data.match, false);

  const detail = await c.get(`/forensics/${id}`);
  assert.ok(detail.body.data.custody.length >= 2);
});

test('unsupported evidence types are refused', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const response = await c.post('/forensics', {
    caseRef: 'CASE-TEST-2', filename: 'malware.exe', mimeType: 'application/x-msdownload', contentBase64: 'AAAA',
  });
  assert.equal(response.status, 400);
  assert.match(response.body.error.message, /Unsupported file type/i);
});

test('reports are generated from stored records and export', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const generated = await c.post('/reports/generate', { type: 'executive' });
  assert.equal(generated.status, 201);
  assert.ok(generated.body.data.summary.kpis.length >= 4);
  assert.ok(generated.body.data.bodyMd.includes('Executive security summary'));

  const markdown = await c.request('GET', `/reports/${generated.body.data.id}/download?format=md`);
  assert.equal(markdown.status, 200);
  assert.ok(markdown.text.length > 200);
  assert.match(markdown.headers.get('content-type'), /text\/markdown/);

  const csv = await c.request('GET', `/reports/${generated.body.data.id}/download?format=csv`);
  assert.equal(csv.status, 200);
  assert.ok(csv.text.includes('KPI'));
});

test('workflow approval gate records simulated actions', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const workflows = await c.get('/automation/workflows');
  const gated = workflows.body.data.find((row) => row.requiresApproval);
  assert.ok(gated, 'seed data should include an approval gated workflow');
  const run = await c.post(`/automation/workflows/${gated.id}/run`, {});
  assert.equal(run.status, 201);
  assert.equal(run.body.data.status, 'pending_approval');

  const approved = await c.post(`/automation/executions/${run.body.data.id}/approve`);
  assert.equal(approved.status, 200);
  assert.equal(approved.body.data.status, 'completed');
  assert.ok(approved.body.data.log.every((step) => step.status === 'simulated'));
});
