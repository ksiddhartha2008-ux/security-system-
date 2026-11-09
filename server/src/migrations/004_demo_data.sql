-- Migration v4: data origin classification, demo batches, simulation event mirroring.
ALTER TABLE assets ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE assets ADD COLUMN demo_batch_id TEXT;

ALTER TABLE security_events ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE security_events ADD COLUMN demo_batch_id TEXT;
ALTER TABLE security_events ADD COLUMN dedupe_key TEXT;
ALTER TABLE security_events ADD COLUMN simulation_id TEXT;

ALTER TABLE detections ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE detections ADD COLUMN demo_batch_id TEXT;

ALTER TABLE incidents ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE incidents ADD COLUMN demo_batch_id TEXT;

ALTER TABLE vulnerabilities ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE vulnerabilities ADD COLUMN demo_batch_id TEXT;

ALTER TABLE network_events ADD COLUMN data_origin TEXT NOT NULL DEFAULT 'REAL';
ALTER TABLE network_events ADD COLUMN demo_batch_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedupe
  ON security_events(org_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_origin ON security_events(org_id, data_origin);
CREATE INDEX IF NOT EXISTS idx_detections_origin ON detections(org_id, data_origin);
CREATE INDEX IF NOT EXISTS idx_incidents_origin ON incidents(org_id, data_origin);
CREATE INDEX IF NOT EXISTS idx_assets_origin ON assets(org_id, data_origin);

CREATE TABLE IF NOT EXISTS demo_runs (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL,
  action     TEXT NOT NULL,
  batch_id   TEXT,
  counts     TEXT NOT NULL DEFAULT '{}',
  actor_id   TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_demo_runs_org ON demo_runs(org_id, created_at DESC);

-- Existing workspace seeded by the demo seeder is demo data, not real telemetry.
UPDATE assets SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
UPDATE security_events SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
UPDATE detections SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
UPDATE incidents SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
UPDATE vulnerabilities SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
UPDATE network_events SET data_origin = 'DEMO', demo_batch_id = 'seed-v1' WHERE org_id = 'org_meridian';
