-- SecureFlow AI – schema v1 (SQLite)
-- Every tenant-owned table carries org_id and is filtered server-side from the session.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  slug          TEXT NOT NULL UNIQUE,
  plan          TEXT NOT NULL DEFAULT 'team',
  settings      TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  last_login_at TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id      TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  ip          TEXT,
  user_agent  TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS assets (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  hostname      TEXT NOT NULL,
  ip_address    TEXT,
  mac_address   TEXT,
  os            TEXT,
  asset_type    TEXT NOT NULL DEFAULT 'server',
  criticality   TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low','medium','high','critical')),
  owner         TEXT,
  risk_score    INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online','offline','quarantined','decommissioned')),
  tags          TEXT NOT NULL DEFAULT '[]',
  last_seen_at  TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id, risk_score DESC);

CREATE TABLE IF NOT EXISTS security_events (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_type   TEXT NOT NULL,
  source       TEXT NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  category     TEXT NOT NULL DEFAULT 'endpoint',
  title        TEXT NOT NULL,
  description  TEXT,
  src_ip       TEXT,
  dest_ip      TEXT,
  user_email   TEXT,
  asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
  raw          TEXT NOT NULL DEFAULT '{}',
  status       TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','triaged','closed')),
  occurred_at  TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_org_time ON security_events(org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_org_sev ON security_events(org_id, severity);
CREATE INDEX IF NOT EXISTS idx_events_src ON security_events(org_id, src_ip, occurred_at);

CREATE TABLE IF NOT EXISTS detection_rules (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key            TEXT NOT NULL,
  name           TEXT NOT NULL,
  category       TEXT NOT NULL,
  severity       TEXT NOT NULL,
  description    TEXT NOT NULL,
  threshold      INTEGER NOT NULL DEFAULT 1,
  window_minutes INTEGER NOT NULL DEFAULT 10,
  enabled        INTEGER NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  UNIQUE (org_id, key)
);

CREATE TABLE IF NOT EXISTS detections (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id      TEXT REFERENCES detection_rules(id) ON DELETE SET NULL,
  event_id     TEXT REFERENCES security_events(id) ON DELETE SET NULL,
  asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL,
  severity     TEXT NOT NULL,
  risk_score   INTEGER NOT NULL,
  confidence   INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','confirmed','false_positive','closed')),
  explanation  TEXT NOT NULL DEFAULT '{}',
  detected_at  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_org ON detections(org_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ref          TEXT NOT NULL,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  severity     TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  priority     TEXT NOT NULL DEFAULT 'P3',
  status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','contained','resolved','closed')),
  assignee_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
  detected_at  TEXT NOT NULL,
  due_at       TEXT,
  resolved_at  TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (org_id, ref)
);
CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS incident_events (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,
  message     TEXT NOT NULL,
  actor_id    TEXT,
  metadata    TEXT NOT NULL DEFAULT '{}',
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_events ON incident_events(incident_id, created_at);

CREATE TABLE IF NOT EXISTS investigations (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ref         TEXT NOT NULL,
  title       TEXT NOT NULL,
  hypothesis  TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','concluded')),
  severity    TEXT NOT NULL DEFAULT 'medium',
  owner_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
  incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
  findings    TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (org_id, ref)
);

CREATE TABLE IF NOT EXISTS investigation_notes (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  author_id        TEXT,
  body             TEXT NOT NULL,
  created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  type         TEXT NOT NULL CHECK (type IN ('ip','domain','url','sha256','md5','email')),
  value        TEXT NOT NULL,
  threat_type  TEXT NOT NULL DEFAULT 'unknown',
  confidence   INTEGER NOT NULL DEFAULT 50,
  source       TEXT NOT NULL DEFAULT 'manual',
  description  TEXT,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','monitoring','retired')),
  last_seen_at TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (org_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_org ON iocs(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS intel_lookups (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL,
  ioc_type   TEXT NOT NULL,
  value      TEXT NOT NULL,
  verdict    TEXT NOT NULL,
  score      INTEGER NOT NULL,
  source     TEXT NOT NULL,
  details    TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS phishing_scans (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  url            TEXT NOT NULL,
  domain         TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  risk_score     INTEGER NOT NULL,
  indicators     TEXT NOT NULL DEFAULT '[]',
  redirect_chain TEXT NOT NULL DEFAULT '[]',
  reachable      INTEGER NOT NULL DEFAULT 0,
  status         TEXT NOT NULL DEFAULT 'completed',
  error          TEXT,
  reputation     TEXT NOT NULL DEFAULT '{}',
  scanned_by     TEXT,
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_phishing_org ON phishing_scans(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  cve_id       TEXT,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  severity     TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  cvss         REAL NOT NULL DEFAULT 0,
  asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
  status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','remediated','accepted','false_positive')),
  remediation  TEXT,
  due_at       TEXT,
  discovered_at TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulns_org ON vulnerabilities(org_id, cvss DESC);

CREATE TABLE IF NOT EXISTS response_workflows (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL,
  name             TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  trigger_type     TEXT NOT NULL,
  trigger_config   TEXT NOT NULL DEFAULT '{}',
  actions          TEXT NOT NULL DEFAULT '[]',
  requires_approval INTEGER NOT NULL DEFAULT 1,
  enabled          INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_executions (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  workflow_id TEXT NOT NULL REFERENCES response_workflows(id) ON DELETE CASCADE,
  incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
  status      TEXT NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval','running','completed','failed','cancelled')),
  current_step INTEGER NOT NULL DEFAULT 0,
  log         TEXT NOT NULL DEFAULT '[]',
  started_by  TEXT,
  approved_by TEXT,
  started_at  TEXT,
  finished_at TEXT,
  error       TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forensic_evidence (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  case_ref       TEXT NOT NULL,
  filename       TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  mime_type      TEXT NOT NULL,
  size_bytes     INTEGER NOT NULL,
  sha256         TEXT NOT NULL,
  storage_path   TEXT NOT NULL,
  collected_from TEXT,
  collected_by   TEXT,
  status         TEXT NOT NULL DEFAULT 'sealed' CHECK (status IN ('sealed','in_review','released')),
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_org ON forensic_evidence(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS custody_records (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  evidence_id   TEXT NOT NULL REFERENCES forensic_evidence(id) ON DELETE CASCADE,
  action        TEXT NOT NULL,
  actor_id      TEXT,
  note          TEXT,
  hash_at_action TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_events (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  src_ip      TEXT NOT NULL,
  src_port    INTEGER,
  dest_ip     TEXT NOT NULL,
  dest_port   INTEGER,
  protocol    TEXT NOT NULL,
  bytes_out   INTEGER NOT NULL DEFAULT 0,
  bytes_in    INTEGER NOT NULL DEFAULT 0,
  direction   TEXT NOT NULL DEFAULT 'outbound',
  verdict     TEXT NOT NULL DEFAULT 'allowed' CHECK (verdict IN ('allowed','suspicious','blocked')),
  asset_id    TEXT REFERENCES assets(id) ON DELETE SET NULL,
  occurred_at TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_org ON network_events(org_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS reports (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  type         TEXT NOT NULL,
  title        TEXT NOT NULL,
  params       TEXT NOT NULL DEFAULT '{}',
  status       TEXT NOT NULL DEFAULT 'ready',
  summary      TEXT NOT NULL DEFAULT '{}',
  body_md      TEXT NOT NULL DEFAULT '',
  generated_by TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulations (
  id                    TEXT PRIMARY KEY,
  org_id                TEXT NOT NULL,
  ref                   TEXT NOT NULL,
  name                  TEXT NOT NULL,
  scenario              TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft','queued','running','completed','failed','cancelled')),
  engine                TEXT NOT NULL DEFAULT 'secureflow-native',
  config                TEXT NOT NULL DEFAULT '{}',
  progress              INTEGER NOT NULL DEFAULT 0,
  current_round         INTEGER NOT NULL DEFAULT 0,
  total_rounds          INTEGER NOT NULL DEFAULT 8,
  risk_score            INTEGER,
  summary               TEXT NOT NULL DEFAULT '{}',
  error                 TEXT,
  mirofish_simulation_id TEXT,
  created_by            TEXT,
  started_at            TEXT,
  finished_at           TEXT,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  UNIQUE (org_id, ref)
);
CREATE INDEX IF NOT EXISTS idx_simulations_org ON simulations(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS simulation_agents (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  simulation_id  TEXT NOT NULL REFERENCES simulations(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  role           TEXT NOT NULL,
  persona        TEXT NOT NULL DEFAULT '',
  status         TEXT NOT NULL DEFAULT 'idle',
  risk_score     INTEGER NOT NULL DEFAULT 0,
  activity_count INTEGER NOT NULL DEFAULT 0,
  last_action    TEXT,
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sim_agents ON simulation_agents(simulation_id);

CREATE TABLE IF NOT EXISTS simulation_events (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  simulation_id TEXT NOT NULL REFERENCES simulations(id) ON DELETE CASCADE,
  round         INTEGER NOT NULL,
  agent_id      TEXT,
  event_type    TEXT NOT NULL,
  severity      TEXT NOT NULL,
  message       TEXT NOT NULL,
  metadata      TEXT NOT NULL DEFAULT '{}',
  occurred_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sim_events ON simulation_events(simulation_id, round);

CREATE TABLE IF NOT EXISTS simulation_reports (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  simulation_id   TEXT NOT NULL UNIQUE REFERENCES simulations(id) ON DELETE CASCADE,
  risk_score      INTEGER NOT NULL,
  findings        TEXT NOT NULL DEFAULT '[]',
  recommendations TEXT NOT NULL DEFAULT '[]',
  narrative       TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_configs (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  key         TEXT NOT NULL,
  name        TEXT NOT NULL,
  category    TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'unconfigured'
                CHECK (status IN ('unconfigured','configured','connected','error','disabled')),
  config      TEXT NOT NULL DEFAULT '{}',
  last_sync_at TEXT,
  last_error  TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (org_id, key)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  actor_id      TEXT,
  actor_email   TEXT,
  action        TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   TEXT,
  ip            TEXT,
  metadata      TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS login_attempts (
  id         TEXT PRIMARY KEY,
  email      TEXT NOT NULL,
  ip         TEXT,
  success    INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(email, created_at);
