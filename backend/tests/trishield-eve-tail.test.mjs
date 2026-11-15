import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, client, login, DEMO } from './helpers.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const script = join(root, 'scripts', 'trishield-eve-tail.mjs');
let server;
let dir;
before(async () => {
  server = await startServer();
  dir = mkdtempSync(join(tmpdir(), 'sf-eve-'));
}, { timeout: 60_000 });
after(() => {
  server?.stop();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

function runTail(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...args], { timeout: 60_000 }, (error, stdout, stderr) => {
      resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr });
    });
  });
}

test('the tailer sends alerts with a collector token and never replays them', async () => {
  const admin = await login(server.base, ...DEMO.admin);
  const created = await admin.post('/trishield/collectors', { kind: 'suricata', name: 'EVE tail' });
  assert.equal(created.status, 201);
  const token = created.body.data.token;

  const evePath = join(dir, 'eve.json');
  const offsetPath = join(dir, 'offset');
  const records = [
    { timestamp: '2026-11-15T10:00:00Z', event_type: 'alert', src_ip: '198.51.100.61', dest_ip: '10.0.0.5', alert: { signature: 'ET SCAN', signature_id: 2001, severity: 2 } },
    { timestamp: '2026-11-15T10:00:01Z', event_type: 'dns', src_ip: '10.0.0.5', dns: { rrname: 'example.test' } },
    { timestamp: '2026-11-15T10:00:02Z', event_type: 'alert', src_ip: '198.51.100.62', dest_ip: '10.0.0.5', alert: { signature: 'ET POLICY', signature_id: 2002, severity: 3 } },
  ];
  writeFileSync(evePath, `${records.map((row) => JSON.stringify(row)).join('\n')}\n{"broken":`);

  const first = await runTail(['--file', evePath, '--url', server.base.replace(/\/api$/, ''), '--token', token, '--offset-file', offsetPath, '--once']);
  assert.equal(first.code, 0, first.stderr);
  assert.match(first.stdout, /accepted 2/);
  assert.match(first.stdout, /skipped 2/, 'the dns record and the malformed line are skipped');
  assert.equal(existsSync(offsetPath), true);
  assert.ok(Number(readFileSync(offsetPath, 'utf8')) > 0);

  const events = await admin.get('/trishield/network/events?limit=20');
  assert.equal(events.body.data.filter((row) => row.srcIp === '198.51.100.61').length, 1);

  const second = await runTail(['--file', evePath, '--url', server.base.replace(/\/api$/, ''), '--token', token, '--offset-file', offsetPath, '--once']);
  assert.equal(second.code, 0, second.stderr);
  assert.match(second.stdout, /accepted 0/);
  const after = await admin.get('/trishield/network/events?limit=20');
  assert.equal(after.body.data.filter((row) => row.srcIp === '198.51.100.61').length, 1, 'a restart must not duplicate events');
});

test('the tailer refuses a bad token and an insecure URL', async () => {
  const evePath = join(dir, 'one.json');
  writeFileSync(evePath, `${JSON.stringify({ timestamp: '2026-11-15T10:00:00Z', event_type: 'alert', src_ip: '198.51.100.70', alert: { signature: 'x', signature_id: 1 } })}\n`);
  const badToken = await runTail(['--file', evePath, '--url', server.base.replace(/\/api$/, ''), '--token', 'tsk_wrong', '--once']);
  assert.equal(badToken.code, 1);
  assert.match(badToken.stderr, /401/);

  const badUrl = await runTail(['--file', evePath, '--url', 'ftp://example.test', '--token', 'tsk_abc', '--once']);
  assert.equal(badUrl.code, 1);
  assert.match(badUrl.stderr, /http/i);

  const dry = await runTail(['--file', evePath, '--dry-run', '--once']);
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, /dry-run/);
});
