import { mkdtempSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Boot an isolated hardened instance on a temporary database and exercise the
// live HTTP surface. Does not touch the developer's running server or data.
const dir = mkdtempSync(join(tmpdir(), 'secureflow-verify-'));
process.env.PORT = '4011';
process.env.NODE_ENV = 'development';
process.env.SF_DATA_DIR = dir;
process.env.SF_DB_PATH = join(dir, 'verify.db');
process.env.SF_DEMO_MODE = 'true';

await import('../server/src/index.js');

const base = 'http://127.0.0.1:4011/api';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let healthy = false;
for (let i = 0; i < 40; i += 1) {
  try {
    const response = await fetch(`${base}/health`);
    if (response.ok) { healthy = true; break; }
  } catch { /* still starting */ }
  await sleep(250);
}
if (!healthy) {
  console.error('FAIL: server did not start');
  process.exit(1);
}

// Register a throwaway workspace instead of using a seeded credential.
const email = `verify-${Date.now()}@example.test`;
const password = `Verify#${randomBytes(9).toString('base64url')}`;
const register = await fetch(`${base}/auth/register`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name: 'Verify Runner', email, password, organizationName: 'Verification Lab' }),
});
const cookies = register.headers.getSetCookie();
const session = cookies.find((c) => c.startsWith('sf_session='))?.split(';')[0];
const csrf = cookies.find((c) => c.startsWith('sf_csrf='))?.split(';')[0];
const cookieHeader = `${session}; ${csrf}`;
const csrfValue = csrf.split('=')[1];

const noToken = await fetch(`${base}/assets`, {
  method: 'POST',
  headers: { cookie: cookieHeader, 'content-type': 'application/json' },
  body: JSON.stringify({ name: 'No token', hostname: 'no-token-verify' }),
});
const withToken = await fetch(`${base}/assets`, {
  method: 'POST',
  headers: { cookie: cookieHeader, 'content-type': 'application/json', 'x-csrf-token': csrfValue },
  body: JSON.stringify({ name: 'With token', hostname: 'with-token-verify' }),
});
const verify = await fetch(`${base}/settings/audit-logs/verify`, { headers: { cookie: cookieHeader } });
const verifyBody = await verify.json();

console.log(JSON.stringify({
  registerStatus: register.status,
  sessionCookie: Boolean(session),
  csrfCookie: Boolean(csrf),
  postWithoutToken: noToken.status,
  postWithToken: withToken.status,
  auditChain: verifyBody.data?.ok,
  auditChecked: verifyBody.data?.checked,
}, null, 2));

const passed = register.status === 201 && session && csrf && noToken.status === 403 && withToken.status === 201 && verifyBody.data?.ok === true;
process.exit(passed ? 0 : 1);
