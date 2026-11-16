-- Phase 1.3: email ownership verification
-- Existing accounts are grandfathered as verified during this migration. They
-- were created before verification existed and there is no evidence either way;
-- the one-time migration policy is documented in PHASE-1.3-EMAIL-VERIFICATION.md.
-- Every account created after this migration starts unverified.

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1));
ALTER TABLE users ADD COLUMN email_verified_at TEXT;

UPDATE users SET email_verified = 1, email_verified_at = created_at WHERE email_verified = 0;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_verification_user
  ON email_verification_tokens(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_verification_expiry
  ON email_verification_tokens(expires_at);
