import { createHash, randomBytes } from 'node:crypto';
import { get, run, newId, nowIso, transaction } from '../db.js';

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const hashToken = (token) => createHash('sha256').update(String(token)).digest('hex');

/** Issue a single active token. Previous unconsumed tokens are revoked first. */
export function issueVerificationToken(userId, { now = Date.now() } = {}) {
  const token = randomBytes(32).toString('base64url');
  const ts = nowIso();
  const expiresAt = new Date(now + TOKEN_TTL_MS).toISOString();
  transaction(() => {
    run('UPDATE email_verification_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL', ts, userId);
    run(
      `INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, consumed_at, created_at)
       VALUES (?, ?, ?, ?, NULL, ?)`,
      newId('evt'), userId, hashToken(token), expiresAt, ts,
    );
  });
  return { token, expiresAt };
}

/**
 * Consume a token atomically. The BEGIN IMMEDIATE transaction serialises
 * callers, and the conditional UPDATE makes a second consumer lose the race.
 */
export function consumeVerificationToken(token, { now = Date.now() } = {}) {
  const hash = hashToken(token);
  return transaction(() => {
    const row = get('SELECT * FROM email_verification_tokens WHERE token_hash = ?', hash);
    if (!row) return { ok: false, code: 'invalid' };
    if (row.consumed_at) return { ok: false, code: 'used' };
    const user = get('SELECT id, org_id, email, email_verified FROM users WHERE id = ?', row.user_id);
    if (!user) return { ok: false, code: 'invalid' };
    if (new Date(row.expires_at).getTime() <= now) return { ok: false, code: 'expired', orgId: user.org_id, userId: user.id };

    const ts = nowIso();
    const consumed = run(
      'UPDATE email_verification_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL',
      ts, row.id,
    );
    if (!consumed.changes) return { ok: false, code: 'used', orgId: user.org_id, userId: user.id };

    if (user.email_verified !== 1) {
      run('UPDATE users SET email_verified = 1, email_verified_at = ?, updated_at = ? WHERE id = ?', ts, ts, user.id);
    }
    return { ok: true, orgId: user.org_id, userId: user.id, alreadyVerified: user.email_verified === 1 };
  });
}

export function activeTokenCount(userId, { since } = {}) {
  if (since) return get('SELECT COUNT(*) AS c FROM email_verification_tokens WHERE user_id = ? AND created_at >= ?', userId, since).c;
  return get('SELECT COUNT(*) AS c FROM email_verification_tokens WHERE user_id = ? AND consumed_at IS NULL', userId).c;
}
