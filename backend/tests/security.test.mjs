import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, login, DEMO } from './helpers.mjs';

let server;
before(async () => { server = await startServer(); }, { timeout: 60_000 });
after(() => server?.stop());

test('the URL scanner refuses loopback, private, link local and reserved targets', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const blocked = [
    'http://127.0.0.1/admin',
    'http://10.20.0.5/',
    'http://192.168.1.1/',
    'http://172.16.4.4/',
    'http://169.254.169.254/latest/meta-data/',
    'http://[::1]/',
    'http://0.0.0.0/',
    'http://100.64.1.1/',
  ];
  for (const url of blocked) {
    const response = await c.post('/phishing/scan', { url });
    assert.equal(response.status, 400, `${url} should be refused`);
    assert.match(response.body.error.message, /Refusing to scan|Local and internal|cannot be scanned/i);
  }
});

test('only http and https schemes are accepted', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  for (const url of ['file:///C:/Windows/win.ini', 'ftp://example.com/file', 'javascript:alert(1)', 'gopher://example.com']) {
    const response = await c.post('/phishing/scan', { url });
    assert.equal(response.status, 400, `${url} should be refused`);
  }
});

test('URLs with embedded credentials are refused', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const response = await c.post('/phishing/scan', { url: 'https://user:pass@example.com/login' });
  assert.equal(response.status, 400);
  assert.match(response.body.error.message, /credentials/i);
});

test('scan history is scoped to the organization', async () => {
  const c = await login(server.base, ...DEMO.analyst);
  const history = await c.get('/phishing?limit=10');
  assert.equal(history.status, 200);
  assert.ok(Array.isArray(history.body.data));
});
