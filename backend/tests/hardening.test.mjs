import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { startServer, client, login, DEMO } from './helpers.mjs';
import { checkProductionConfig } from '../src/lib/config.js';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

const raw = (path, { method = 'POST', cookie = '', headers = {}, body } = {}) =>
  fetch(`${server.base}${path}`, {
    method,
    headers: { accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });

test('authenticated mutations require a session bound CSRF token', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const cookie = `sf_session=${c.cookies.sf_session}; sf_csrf=${c.cookies.sf_csrf}`;

  const missing = await raw('/assets', { cookie, body: { name: 'No token', hostname: 'no-token-01' } });
  assert.equal(missing.status, 403);
  assert.equal((await missing.json()).error.code, 'csrf_rejected');

  const wrong = await raw('/assets', {
    cookie, headers: { 'x-csrf-token': 'not-the-token' }, body: { name: 'Wrong token', hostname: 'wrong-token-01' },
  });
  assert.equal(wrong.status, 403);

  // A machine client with the token but no Origin header is accepted: the
  // CSRF check, not the Origin header, is the boundary.
  const noOrigin = await raw('/assets', {
    cookie, headers: { 'x-csrf-token': c.cookies.sf_csrf }, body: { name: 'Machine client', hostname: `machine-${Date.now()}` },
  });
  assert.equal(noOrigin.status, 201);

  // Same token with a foreign Origin is still rejected.
  const crossOrigin = await raw('/assets', {
    cookie, headers: { 'x-csrf-token': c.cookies.sf_csrf, origin: 'https://evil.example' },
    body: { name: 'Cross origin', hostname: `cross-${Date.now()}` },
  });
  assert.equal(crossOrigin.status, 403);
  assert.equal((await crossOrigin.json()).error.code, 'origin_rejected');
});

test('audit log is hash chained and tampering is detected', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const created = await admin.post('/incidents', { title: 'Audit chain test incident', severity: 'medium' });
  assert.equal(created.status, 201);

  const initial = await admin.get('/settings/audit-logs/verify');
  assert.equal(initial.status, 200);
  assert.equal(initial.body.data.ok, true);
  assert.ok(initial.body.data.checked > 0);

  const db = new DatabaseSync(join(server.dir, 'test.db'));
  const row = db.prepare("SELECT id FROM audit_logs WHERE org_id = ? AND hash != '' ORDER BY rowid DESC LIMIT 1").get('org_meridian');
  assert.ok(row, 'expected at least one chained audit row');
  db.prepare('UPDATE audit_logs SET action = ? WHERE id = ?').run('audit.action.tampered', row.id);
  db.close();

  const after = await admin.get('/settings/audit-logs/verify');
  assert.equal(after.status, 200);
  assert.equal(after.body.data.ok, false);
  assert.equal(after.body.data.brokenAt, row.id);
});

test('destructive workflows cannot disable approval and approvals expire', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const analyst = await login(server.base, ...DEMO.analyst);

  const bypass = await admin.post('/automation/workflows', {
    name: 'Unsafe isolation', triggerType: 'test', actions: [{ type: 'isolate_host' }], requiresApproval: false,
  });
  assert.equal(bypass.status, 400);
  assert.match(bypass.body.error.message, /always require human approval/i);

  const workflow = await admin.post('/automation/workflows', {
    name: 'Safe isolation', triggerType: 'test', actions: [{ type: 'isolate_host' }], requiresApproval: true,
  });
  assert.equal(workflow.status, 201);
  const workflowId = workflow.body.data.id;

  const disable = await admin.patch(`/automation/workflows/${workflowId}`, { requiresApproval: false });
  assert.equal(disable.status, 400);

  const run = await analyst.post(`/automation/workflows/${workflowId}/run`, { idempotencyKey: `key-${Date.now()}` });
  assert.equal(run.status, 201);
  assert.equal(run.body.data.status, 'pending_approval');

  // A second approval on a completed execution is rejected.
  const approved = await analyst.post(`/automation/executions/${run.body.data.id}/approve`);
  assert.equal(approved.status, 200);
  const again = await analyst.post(`/automation/executions/${run.body.data.id}/approve`);
  assert.equal(again.status, 400);

  // Expired approval windows are rejected.
  const second = await analyst.post(`/automation/workflows/${workflowId}/run`, {});
  const db = new DatabaseSync(join(server.dir, 'test.db'));
  db.prepare('UPDATE workflow_executions SET approval_expires_at = ? WHERE id = ?')
    .run(new Date(Date.now() - 60_000).toISOString(), second.body.data.id);
  db.close();
  const expired = await analyst.post(`/automation/executions/${second.body.data.id}/approve`);
  assert.equal(expired.status, 400);
  assert.match(expired.body.error.message, /expired/i);
});

test('workflow idempotency returns the original execution', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);
  const workflows = await analyst.get('/automation/workflows');
  const workflow = workflows.body.data.find((row) => !row.requiresApproval);
  assert.ok(workflow, 'seed should contain a non destructive workflow');
  const key = `idem-${Date.now()}`;
  const first = await analyst.post(`/automation/workflows/${workflow.id}/run`, { idempotencyKey: key });
  const second = await analyst.post(`/automation/workflows/${workflow.id}/run`, { idempotencyKey: key });
  assert.equal(second.status, 200);
  assert.equal(second.body.data.id, first.body.data.id);
  assert.equal(second.body.data.idempotentReplay, true);
});

test('paused automation refuses new runs', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  await admin.patch('/settings/organization', { settings: { automationPaused: true } });
  const workflows = await admin.get('/automation/workflows');
  const paused = await admin.post(`/automation/workflows/${workflows.body.data[0].id}/run`, {});
  assert.equal(paused.status, 400);
  assert.match(paused.body.error.message, /paused/i);
  await admin.patch('/settings/organization', { settings: { automationPaused: false } });
});

test('evidence rejects declared types that do not match the file signature', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);
  const fakePng = await analyst.post('/forensics', {
    caseRef: 'CASE-SIG-1', filename: 'fake.png', mimeType: 'image/png',
    contentBase64: Buffer.from('this is not a png').toString('base64'),
  });
  assert.equal(fakePng.status, 400);
  assert.match(fakePng.body.error.message, /does not match/i);

  const clean = await analyst.post('/forensics', {
    caseRef: 'CASE-SIG-2', filename: 'note.txt', mimeType: 'text/plain',
    contentBase64: Buffer.from('plain evidence').toString('base64'),
  });
  assert.equal(clean.status, 201);
  assert.equal(clean.body.data.scanStatus, 'not_scanned');
});

test('report CSV neutralises formula injection', async () => {
  const analyst = await login(server.base, ...DEMO.analyst);
  const incident = await analyst.post('/incidents', {
    title: '=cmd|\' /C calc\'!A0', severity: 'low', description: 'Spreadsheet formula probe',
  });
  assert.equal(incident.status, 201);
  const report = await analyst.post('/reports/generate', { type: 'incidents' });
  assert.equal(report.status, 201);
  const csv = await analyst.request('GET', `/reports/${report.body.data.id}/download?format=csv`);
  assert.equal(csv.status, 200);
  assert.ok(csv.text.includes("'=cmd"), 'formula cell must be prefixed with an apostrophe');
  assert.ok(!csv.text.includes('"=cmd'), 'unprefixed formula must not appear');
});

test('production configuration rejects demo mode and insecure origins', () => {
  const demo = checkProductionConfig({ NODE_ENV: 'production', SF_DEMO_MODE: 'true' });
  assert.equal(demo.errors.length, 1);
  const insecureOrigin = checkProductionConfig({ NODE_ENV: 'production', SF_ALLOW_ORIGIN: 'http://example.test' });
  assert.ok(insecureOrigin.errors.some((message) => message.includes('https')));
  const safe = checkProductionConfig({ NODE_ENV: 'production', SF_TRUST_PROXY: 'true' });
  assert.equal(safe.errors.length, 0);
});

test('account based login throttling survives IP rotation', async () => {
  const email = `throttle-${Date.now()}@example.test`;
  const c = client(server.base);
  await c.post('/auth/register', { name: 'Throttle User', email, password: 'CorrectHorse#1', organizationName: 'Throttle Lab' });
  for (let i = 0; i < 10; i += 1) {
    const response = await c.post('/auth/login', { email, password: 'wrong-password' });
    assert.ok([401, 429].includes(response.status));
  }
  const blocked = await c.post('/auth/login', { email, password: 'CorrectHorse#1' });
  assert.equal(blocked.status, 429);
});
