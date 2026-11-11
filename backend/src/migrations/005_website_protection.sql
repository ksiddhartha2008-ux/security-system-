-- Migration v5: website protection.
-- Website onboarding, DNS ownership verification, scoped API keys, event
-- idempotency, derived health counters, notification throttling and a durable
-- job table used by the website scheduler.

ALTER TABLE sessions ADD COLUMN reauthenticated_at TEXT;

ALTER TABLE security_events ADD COLUMN trust_level TEXT NOT NULL DEFAULT 'internal';
ALTER TABLE security_events ADD COLUMN website_site_id TEXT;

CREATE TABLE IF NOT EXISTS website_sites (
  id                        TEXT PRIMARY KEY,
  org_id                    TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id                  TEXT REFERENCES assets(id) ON DELETE SET NULL,
  display_name              TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
  input_url                 TEXT NOT NULL,
  hostname                  TEXT NOT NULL CHECK (hostname = lower(hostname)),
  hostname_unicode          TEXT NOT NULL,
  scheme                    TEXT NOT NULL CHECK (scheme IN ('https','http')),
  scope                     TEXT NOT NULL CHECK (scope IN ('host','domain')),
  registrable_domain        TEXT NOT NULL,
  criticality               INTEGER NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
  status                    TEXT NOT NULL
                              CHECK (status IN ('pending_verification','verified','lapsed','expired','deleted')),
  status_changed_at         TEXT NOT NULL,
  verified_at               TEXT,
  last_verification_ok_at   TEXT,
  verification_failing_since TEXT,
  last_event_at             TEXT,
  last_heartbeat_at         TEXT,
  connected_at              TEXT,
  host_mismatch_count       INTEGER NOT NULL DEFAULT 0,
  host_mismatch_last_at     TEXT,
  private_ip_count          INTEGER NOT NULL DEFAULT 0,
  ip_event_count            INTEGER NOT NULL DEFAULT 0,
  sensitive_paths           TEXT NOT NULL DEFAULT '["/.env","/.git/","/wp-login.php","/wp-admin","/phpmyadmin","/server-status"]',
  created_by                TEXT,
  deleted_at                TEXT,
  created_at                TEXT NOT NULL,
  updated_at                TEXT NOT NULL,
  UNIQUE (org_id, id)
);

-- One verified owner per hostname across every organization. The index, not
-- application logic, is what makes concurrent verification races deterministic.
CREATE UNIQUE INDEX IF NOT EXISTS idx_website_sites_verified_host
  ON website_sites(hostname) WHERE status = 'verified';
CREATE INDEX IF NOT EXISTS idx_website_sites_org ON website_sites(org_id, status);
CREATE INDEX IF NOT EXISTS idx_website_sites_host ON website_sites(hostname);

CREATE TABLE IF NOT EXISTS domain_verifications (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  site_id         TEXT NOT NULL,
  method          TEXT NOT NULL DEFAULT 'dns_txt' CHECK (method = 'dns_txt'),
  record_name     TEXT NOT NULL,
  token           TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('pending','verified','expired','superseded','conflict')),
  expires_at      TEXT NOT NULL,
  attempt_count   INTEGER NOT NULL DEFAULT 0,
  last_checked_at TEXT,
  last_result     TEXT CHECK (last_result IS NULL OR last_result IN ('ok','not_found','mismatch','resolver_error')),
  verified_at     TEXT,
  created_at      TEXT NOT NULL,
  UNIQUE (org_id, id),
  UNIQUE (site_id, token),
  FOREIGN KEY (org_id, site_id) REFERENCES website_sites(org_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_verifications_pending
  ON domain_verifications(site_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_domain_verifications_org ON domain_verifications(org_id, site_id);

CREATE TABLE IF NOT EXISTS site_api_keys (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  site_id       TEXT NOT NULL,
  key_id        TEXT NOT NULL UNIQUE,
  secret_hash   TEXT NOT NULL,
  last4         TEXT NOT NULL,
  label         TEXT NOT NULL DEFAULT 'default' CHECK (length(label) <= 60),
  scopes        TEXT NOT NULL DEFAULT 'events:write',
  created_by    TEXT,
  expires_at    TEXT,
  last_used_at  TEXT,
  revoked_at    TEXT,
  revoked_by    TEXT,
  revoke_reason TEXT,
  created_at    TEXT NOT NULL,
  UNIQUE (org_id, id),
  FOREIGN KEY (org_id, site_id) REFERENCES website_sites(org_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_site_api_keys_site ON site_api_keys(org_id, site_id);

CREATE TABLE IF NOT EXISTS website_event_ids (
  site_id     TEXT NOT NULL,
  event_id    TEXT NOT NULL,
  org_id      TEXT NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY (site_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_website_event_ids_received ON website_event_ids(received_at);

CREATE TABLE IF NOT EXISTS website_verification_attempts (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL,
  site_id    TEXT NOT NULL,
  source     TEXT NOT NULL CHECK (source IN ('manual','scheduled')),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_website_attempts_site ON website_verification_attempts(site_id, created_at);
CREATE INDEX IF NOT EXISTS idx_website_attempts_org ON website_verification_attempts(org_id, created_at);

-- Fixed window counters for ingestion limits. Durable, so limits survive a
-- restart and work across more than one process.
CREATE TABLE IF NOT EXISTS website_usage (
  site_id    TEXT NOT NULL,
  bucket     TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (site_id, bucket)
);
CREATE INDEX IF NOT EXISTS idx_website_usage_updated ON website_usage(updated_at);

CREATE TABLE IF NOT EXISTS website_jobs (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  kind            TEXT NOT NULL,
  site_id         TEXT,
  verification_id TEXT,
  next_run_at     TEXT NOT NULL,
  lease_until     TEXT,
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  payload         TEXT NOT NULL DEFAULT '{}',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_website_jobs_due ON website_jobs(next_run_at, lease_until);

CREATE TABLE IF NOT EXISTS notifications (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL,
  incident_id        TEXT REFERENCES incidents(id) ON DELETE CASCADE,
  site_id            TEXT,
  kind               TEXT NOT NULL CHECK (kind IN ('incident','integration_health')),
  priority           TEXT NOT NULL,
  channel            TEXT NOT NULL DEFAULT 'in_app',
  status             TEXT NOT NULL CHECK (status IN ('sent','suppressed','failed')),
  suppression_reason TEXT,
  title              TEXT NOT NULL,
  body               TEXT NOT NULL,
  dedupe_key         TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  UNIQUE (org_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_incident ON notifications(incident_id, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_entities (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  entity_type  TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE (incident_id, entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_incident_entities_lookup
  ON incident_entities(org_id, entity_type, entity_value);

-- One row per detection, so two concurrent workers cannot attach the same
-- detection twice or create twin incidents for it.
CREATE TABLE IF NOT EXISTS incident_detections (
  detection_id TEXT PRIMARY KEY,
  incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  org_id       TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_detections_incident ON incident_detections(incident_id);

CREATE TABLE IF NOT EXISTS website_deletion_requests (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  site_id        TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('pending','completed','failed')),
  deleted_counts TEXT NOT NULL DEFAULT '{}',
  requested_by   TEXT,
  created_at     TEXT NOT NULL,
  completed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_website_deletions_org ON website_deletion_requests(org_id, created_at DESC);
