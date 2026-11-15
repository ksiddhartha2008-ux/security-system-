-- TriShield schema v7
-- Recorded integration health checks so a dashboard can show the last real
-- result, its latency and its version instead of guessing from environment
-- variables.

CREATE TABLE IF NOT EXISTS trishield_health_checks (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  integration TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('NOT CONFIGURED','CONFIGURED','CONNECTED','VERIFIED','DEGRADED','ERROR','UNAVAILABLE')),
  ok          INTEGER NOT NULL DEFAULT 0 CHECK (ok IN (0,1)),
  latency_ms  INTEGER,
  detail      TEXT NOT NULL DEFAULT '',
  version     TEXT,
  checked_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trishield_health_org
  ON trishield_health_checks(org_id, integration, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_trishield_health_recent
  ON trishield_health_checks(org_id, checked_at DESC);
