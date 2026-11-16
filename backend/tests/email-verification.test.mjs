import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

/** Token lifecycle, provider boundary and template rendering, in process. */
const dir = mkdtempSync(join(tmpdir(), 'sf-email-unit-'));
process.env.SF_DB_PATH = join(dir, 'unit.db');
process.env.SF_DATA_DIR = dir;

const db = await import('../src/db.js');
db.migrate();
const tokens = await import('../src/services/emailVerification.js');
const templates = await import('../src/services/email/templates.js');
const { createEmailService } = await import('../src/services/email/service.js');

const ts = db.nowIso();
db.run(`INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at) VALUES ('org_email_unit', 'Email Unit', 'email-unit', 'team', '{}', ?, ?)`, ts, ts);
db.run(`INSERT INTO users (id, org_id, email, name, password_hash, role, status, created_at, updated_at) VALUES ('usr_email_unit', 'org_email_unit', 'unit@example.test', 'Unit', 'x', 'admin', 'active', ?, ?)`, ts, ts);

after(() => {
  try { db.db.close(); } catch { /* already closed */ }
  rmSync(dir, { recursive: true, force: true });
});

test('only the token hash is stored and issuing revokes the previous link', () => {
  const first = tokens.issueVerificationToken('usr_email_unit');
  const row = db.get('SELECT * FROM email_verification_tokens ORDER BY created_at DESC, rowid DESC LIMIT 1');
  assert.equal(row.token_hash, createHash('sha256').update(first.token).digest('hex'));
  assert.notEqual(row.token_hash, first.token);
  assert.equal(db.all('SELECT id FROM email_verification_tokens WHERE user_id = ? AND consumed_at IS NULL', 'usr_email_unit').length, 1);

  const second = tokens.issueVerificationToken('usr_email_unit');
  assert.equal(tokens.consumeVerificationToken(first.token).code, 'used');
  assert.equal(tokens.consumeVerificationToken(second.token).ok, true);
  assert.equal(db.get('SELECT email_verified FROM users WHERE id = ?', 'usr_email_unit').email_verified, 1);
});

test('a token cannot be replayed and an expired token is refused', () => {
  const used = tokens.issueVerificationToken('usr_email_unit');
  assert.equal(tokens.consumeVerificationToken(used.token).ok, true);
  assert.equal(tokens.consumeVerificationToken(used.token).code, 'used');

  const expired = tokens.issueVerificationToken('usr_email_unit', { now: Date.now() - 25 * 3600_000 });
  assert.equal(tokens.consumeVerificationToken(expired.token).code, 'expired');
});

test('the email body escapes dynamic values and carries the link', () => {
  const message = templates.verificationEmail({
    link: 'https://app.example/verify-email?token=abc',
    email: 'user+<b>@example.test',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  });
  assert.match(message.subject, /Verify your SecureFlow AI email/);
  assert.ok(message.html.includes('&lt;b&gt;'));
  assert.ok(!message.html.includes('<b>@example.test'));
  assert.ok(message.text.includes('https://app.example/verify-email?token=abc'));
  assert.match(message.text, /24 hours|expires/i);
});

test('the service never reports delivery without a provider', async () => {
  const sent = [];
  const working = createEmailService(
    { APP_BASE_URL: 'https://app.example', EMAIL_FROM: 'SecureFlow <no-reply@example.test>', RESEND_API_KEY: 'test' },
    { provider: { configured: true, send: async (message) => { sent.push(message); return { ok: true, id: 'email_1' }; } } },
  );
  const result = await working.sendVerification({ to: 'a@example.test', token: 'raw-token', expiresAt: ts });
  assert.equal(result.ok, true);
  assert.match(sent[0].html, /https:\/\/app\.example\/verify-email\?token=raw-token/);

  const absent = createEmailService({ APP_BASE_URL: 'https://app.example' }, { provider: { configured: false, send: async () => ({ ok: true }) } });
  assert.equal((await absent.sendVerification({ to: 'a@example.test', token: 't', expiresAt: ts })).code, 'not_configured');

  const failing = createEmailService(
    { APP_BASE_URL: 'https://app.example', EMAIL_FROM: 'x', RESEND_API_KEY: 'k' },
    { provider: { configured: true, send: async () => ({ ok: false, code: 'provider_error' }) } },
  );
  assert.equal((await failing.sendVerification({ to: 'a@example.test', token: 't', expiresAt: ts })).ok, false);
});
