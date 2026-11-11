import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const serverRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Boot an isolated API instance with its own database file. */
export async function startServer(extraEnv = {}) {
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
  const deadline = Date.now() + 40_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
      if (response.ok) return { base, proc, dir, stop: () => proc.kill(), output: () => output };
    } catch { /* not listening yet */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  proc.kill();
  throw new Error(`Server did not start in time.\n${output}`);
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

export async function login(base, email, password) {
  const c = client(base);
  const response = await c.post('/auth/login', { email, password });
  if (response.status !== 200) throw new Error(`login failed for ${email}: ${response.status} ${response.text}`);
  return c;
}

export const DEMO = {
  admin: ['admin@secureflow.dev', 'Admin#2026'],
  analyst: ['analyst@secureflow.dev', 'Analyst#2026'],
  viewer: ['viewer@secureflow.dev', 'Viewer#2026'],
};
