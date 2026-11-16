import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

import { totp } from '../src/lib/totp.js';

const serverRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const serverDirs = new Map();

/**
 * Boot an isolated API instance with its own database file.
 * The port is chosen at random, so a busy port is retried instead of failing
 * every test in the file with a startup error.
 */
export async function startServer(extraEnv = {}) {
  let lastOutput = '';
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const dir = mkdtempSync(join(tmpdir(), 'secureflow-test-'));
    const port = 4400 + Math.floor(Math.random() * 400);
    const proc = spawn(process.execPath, ['src/index.js'], {
      cwd: serverRoot,
      env: {
        ...process.env,
        PORT: String(port),
        NODE_ENV: 'test',
        SF_DB_PATH: join(dir, 'test.db'),
        SF_DATA_DIR: dir,
        SF_WEBSITE_SCHEDULER: 'off',
        VIRUSTOTAL_API_KEY: '',
        ABUSEIPDB_API_KEY: '',
        MIROFISH_BASE_URL: '',
        ...extraEnv,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    proc.stdout.on('data', (chunk) => { output += chunk.toString(); });
    proc.stderr.on('data', (chunk) => { output += chunk.toString(); });

    const base = `http://127.0.0.1:${port}/api`;
    const deadline = Date.now() + 15_000;
    let ready = false;
    while (Date.now() < deadline && proc.exitCode === null) {
      try {
        const response = await fetch(`${base}/health`);
        if (response.ok) { ready = true; break; }
      } catch { /* not listening yet */ }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    if (ready) {
      serverDirs.set(base, dir);
      return { base, proc, dir, stop: () => proc.kill(), output: () => output };
    }

    proc.kill();
    lastOutput = output;
    if (!/EADDRINUSE/.test(output)) {
      throw new Error(`Server did not start in time.\n${output}`);
    }
  }
  throw new Error(`Server could not bind a free port after 5 attempts.\n${lastOutput}`);
}

/** Tiny cookie aware client for the test suite. */
export function client(base) {
  const cookies = {};
  async function request(method, path, body, extraHeaders = {}) {
    const headers = { accept: 'application/json', ...extraHeaders };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD' && cookies.sf_csrf) headers['x-csrf-token'] = cookies.sf_csrf;
    const cookieHeader = Object.entries(cookies).map(([name, value]) => `${name}=${value}`).join('; ');
    if (cookieHeader) headers.cookie = cookieHeader;
    const response = await fetch(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookies = response.headers.getSetCookie?.() ?? [];
    for (const entry of setCookies) {
      const [pair, ...attributes] = entry.split(';');
      const index = pair.indexOf('=');
      if (index < 0) continue;
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const maxAge = attributes.map((a) => a.trim().toLowerCase()).find((a) => a.startsWith('max-age='));
      if (!value || (maxAge && Number(maxAge.split('=')[1]) === 0)) delete cookies[name];
      else cookies[name] = value;
    }
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: response.status, body: json, text, headers: response.headers };
  }
  return {
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body ?? {}),
    patch: (path, body) => request('PATCH', path, body ?? {}),
    del: (path) => request('DELETE', path),
    request,
    get cookie() { return cookies.sf_session ? `sf_session=${cookies.sf_session}` : ''; },
    cookies,
  };
}

const mfaSecrets = new Map();
const mfaKey = (base, email) => `${base}|${email.toLowerCase()}`;

/**
 * Registration returns a neutral 202 and never creates a session. Tests that
 * need the new workspace sign in afterwards, exactly like a person would.
 */
export function markEmailVerified(target, email) {
  const dir = typeof target === 'string' ? serverDirs.get(target) : target?.dir;
  if (!dir) throw new Error('unknown test server for email verification');
  const db = new DatabaseSync(join(dir, 'test.db'));
  try {
    db.prepare('UPDATE users SET email_verified = 1, email_verified_at = COALESCE(email_verified_at, ?) WHERE email = ?')
      .run(new Date().toISOString(), String(email).toLowerCase());
  } finally {
    db.close();
  }
}

export async function registerWorkspace(base, { name, email, password, organizationName }) {
  const anonymous = client(base);
  const response = await anonymous.post('/auth/register', { name, email, password, organizationName });
  if (response.status !== 202) {
    throw new Error(`registration failed: ${response.status} ${response.text}`);
  }
  markEmailVerified(base, email);
  const session = await login(base, email, password);
  const me = await session.get('/auth/me');
  if (me.status !== 200) throw new Error(`new workspace could not sign in: ${me.status} ${me.text}`);
  return {
    client: session,
    response,
    user: me.body.data.user,
    organization: me.body.data.organization,
  };
}

/** Register on an existing client, then sign in and enrol administrator MFA. */
export async function registerInto(c, base, payload) {
  const response = await c.post('/auth/register', payload);
  if (response.status !== 202) throw new Error(`registration failed: ${response.status} ${response.text}`);
  markEmailVerified(base, payload.email);
  const loginResponse = await c.post('/auth/login', { email: payload.email, password: payload.password });
  if (loginResponse.status !== 200) throw new Error(`new workspace could not sign in: ${loginResponse.status} ${loginResponse.text}`);
  if (loginResponse.body?.data?.mfaRequired) throw new Error('registerInto expects an account without MFA');
  await enrollAdminMfa(c, payload.password);
  return response;
}

export async function login(base, email, password) {
  const c = client(base);
  const response = await c.post('/auth/login', { email, password });
  if (response.status !== 200) throw new Error(`login failed for ${email}: ${response.status} ${response.text}`);
  if (response.body?.data?.mfaRequired) {
    const secret = mfaSecrets.get(mfaKey(base, email));
    if (!secret) throw new Error(`login for ${email} requires an MFA code and no enrolled secret is known`);
    const verified = await c.post('/auth/mfa/verify', { code: totp(secret) });
    if (verified.status !== 200) throw new Error(`MFA verification failed for ${email}: ${verified.status} ${verified.text}`);
    c.mfaSecret = secret;
    c.stepUp = () => c.post('/auth/step-up', { password, code: totp(secret) });
    return c;
  }
  const secret = await enrollAdminMfa(c, password);
  if (secret) {
    mfaSecrets.set(mfaKey(base, email), secret);
    c.stepUp = () => c.post('/auth/step-up', { password, code: totp(secret) });
  }
  return c;
}

/**
 * Administrator-only mutations require an enrolled second factor. Test suites
 * that act as an administrator enrol it here with the real TOTP flow, so tests
 * exercise the same path a person does.
 */
export async function enrollAdminMfa(c, password) {
  const me = await c.get('/auth/me');
  const user = me.body?.data?.user;
  if (!user || user.role !== 'admin' || user.mfaEnabled) return null;
  const setup = await c.post('/auth/mfa/setup', { password });
  if (setup.status !== 200) return null;
  const secret = setup.body.data.secret;
  const enabled = await c.post('/auth/mfa/enable', { code: totp(secret) });
  if (enabled.status !== 200) throw new Error(`could not enrol administrator MFA: ${enabled.status} ${enabled.text}`);
  c.mfaSecret = secret;
  c.stepUp = () => c.post('/auth/step-up', { password, code: totp(secret) });
  return secret;
}

export const DEMO = {
  admin: ['admin@secureflow.dev', 'Admin#2026'],
  analyst: ['analyst@secureflow.dev', 'Analyst#2026'],
  viewer: ['viewer@secureflow.dev', 'Viewer#2026'],
};
