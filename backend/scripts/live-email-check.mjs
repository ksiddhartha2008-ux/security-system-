/**
 * One-off live delivery check for Phase 1.3. Applies pending migrations to the
 * local development database, then sends a real message through the production
 * email service to the configured test recipient. The token is bound to the demo
 * administrator so the link still resolves while `npm run dev:api` is running.
 *
 * Run: node scripts/live-email-check.mjs <recipient>
 * It never prints the token or the API key.
 */
import { createHash, randomBytes } from 'node:crypto';
import '../src/lib/loadEnv.js';
import { migrate, get, run, nowIso } from '../src/db.js';
import { createEmailService } from '../src/services/email/service.js';

const recipient = process.argv[2];
if (!recipient) {
  console.error('usage: node scripts/live-email-check.mjs <recipient>');
  process.exit(2);
}

migrate();

const user = get("SELECT id, email FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1");
if (!user) {
  console.error('no admin account in the development database');
  process.exit(2);
}

const token = randomBytes(32).toString('base64url');
const hash = createHash('sha256').update(token).digest('hex');
const ts = nowIso();
const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
run('UPDATE email_verification_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL', ts, user.id);
run(
  `INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, consumed_at, created_at)
   VALUES (?, ?, ?, ?, NULL, ?)`,
  `evt_live_${randomBytes(6).toString('hex')}`, user.id, hash, expiresAt, ts,
);

const service = createEmailService();
if (!service.available) {
  console.error('email provider is not configured; set RESEND_API_KEY and EMAIL_FROM');
  process.exit(3);
}

const result = await service.sendVerification({ to: recipient, token, expiresAt });
if (result.ok) {
  console.log(`provider accepted the message, id=${result.id}`);
  console.log(`link host: ${service.baseUrl}/verify-email`);
  console.log(`bound account: ${user.email}`);
} else {
  console.log(`provider did not accept the message: code=${result.code} status=${result.status ?? 'n/a'}`);
  process.exit(1);
}
