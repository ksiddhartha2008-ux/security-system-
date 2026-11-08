import { get, run, newId, nowIso } from '../db.js';
import { hashPassword } from './auth.js';

const slugify = (value) =>
  value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'workspace';

/**
 * Create the first organization and admin from environment variables when demo
 * mode is off. Without this, a production deployment either has no account or,
 * worse, would be seeded with the public demo credentials.
 */
export function createBootstrapAdmin({ email, password, name = 'Workspace owner', organizationName = 'SecureFlow Workspace' }) {
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error('SF_BOOTSTRAP_EMAIL must be a valid email address');
  }
  if (!password || password.length < 12) {
    throw new Error('SF_BOOTSTRAP_PASSWORD must be at least 12 characters in production');
  }
  if (get('SELECT id FROM users WHERE email = ?', email.toLowerCase())) {
    throw new Error('A user with SF_BOOTSTRAP_EMAIL already exists');
  }
  const orgId = newId('org');
  const userId = newId('usr');
  const ts = nowIso();
  let slug = slugify(organizationName);
  let suffix = 1;
  while (get('SELECT id FROM organizations WHERE slug = ?', slug)) {
    slug = `${slugify(organizationName)}-${suffix}`;
    suffix += 1;
  }
  run(
    `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at)
     VALUES (?, ?, ?, 'team', ?, ?, ?)`,
    orgId, organizationName, slug, JSON.stringify({ timezone: 'UTC', retentionDays: 90, demoMode: false }), ts, ts,
  );
  run(
    `INSERT INTO users (id, org_id, email, name, password_hash, role, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'admin', 'active', ?, ?)`,
    userId, orgId, email.toLowerCase(), name, hashPassword(password), ts, ts,
  );
  console.log(`[startup] bootstrap admin created for ${email} in organization "${organizationName}"`);
  return { orgId, userId, email: email.toLowerCase() };
}
