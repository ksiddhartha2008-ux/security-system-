-- TriShield schema v6
-- Infrastructure addresses, firewall connectors, approved actions, endpoint agents,
-- collector credentials and the IP privacy vault.

CREATE TABLE IF NOT EXISTS infra_addresses (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  address           TEXT NOT NULL,
  family            TEXT NOT NULL CHECK (family IN ('ipv4','ipv6')),
  scope             TEXT NOT NULL CHECK (scope IN ('public','private','loopback','link_local','multicast','reserved','unknown')),
  interface         TEXT NOT NULL DEFAULT '',
  hostname          TEXT NOT NULL DEFAULT '',
  provider          TEXT NOT NULL DEFAULT 'local',
  discovery_source  TEXT NOT NULL,
  verified          INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0,1)),
  is_management     INTEGER NOT NULL DEFAULT 0 CHECK (is_management IN (0,1)),
  asset_id          TEXT REFERENCES assets(id) ON DELETE SET NULL,
  first_seen_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL,
  metadata          TEXT NOT NULL DEFAULT '{}',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE (org_id, address, interface)
);
CREATE INDEX IF NOT EXISTS idx_infra_addresses_org ON infra_addresses(org_id, scope);
CREATE INDEX IF NOT EXISTS idx_infra_addresses_mgmt ON infra_addresses(org_id, is_management);

CREATE TABLE IF NOT EXISTS trishield_allowlist (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  address     TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  created_by  TEXT,
  created_at  TEXT NOT NULL,
  UNIQUE (org_id, address)
);

CREATE TABLE IF NOT EXISTS firewall_rules (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_key TEXT NOT NULL,
  external_id  TEXT,
  direction    TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
  action       TEXT NOT NULL CHECK (action IN ('block','allow')),
  family       TEXT NOT NULL CHECK (family IN ('ipv4','ipv6')),
  cidr         TEXT NOT NULL,
  protocol     TEXT NOT NULL DEFAULT 'any',
  port         TEXT,
  comment      TEXT NOT NULL DEFAULT '',
  state        TEXT NOT NULL CHECK (state IN ('active','expired','removed','error')),
  expires_at   TEXT,
  created_by   TEXT,
  created_at   TEXT NOT NULL,
  verified_at  TEXT,
  metadata     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_org ON firewall_rules(org_id, provider_key, state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_rules_active
  ON firewall_rules(org_id, provider_key, cidr, action)
  WHERE state = 'active';

CREATE TABLE IF NOT EXISTS firewall_actions (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_key       TEXT NOT NULL,
  type               TEXT NOT NULL CHECK (type IN ('block_ip','unblock_ip','allow_ip','list_rules','health_check')),
  target_ip          TEXT,
  cidr               TEXT,
  reason             TEXT NOT NULL,
  risk_class         TEXT NOT NULL CHECK (risk_class IN ('low','restricted','high')),
  status             TEXT NOT NULL CHECK (status IN ('proposed','awaiting_approval','approved','executing','verifying','succeeded','failed','rejected','expired','rolled_back')),
  approval_required  INTEGER NOT NULL DEFAULT 1 CHECK (approval_required IN (0,1)),
  requested_by       TEXT,
  approved_by        TEXT,
  approved_at        TEXT,
  idempotency_key    TEXT NOT NULL,
  expires_at         TEXT,
  permanent          INTEGER NOT NULL DEFAULT 0 CHECK (permanent IN (0,1)),
  provider_ref       TEXT,
  verification       TEXT NOT NULL DEFAULT '{}',
  error              TEXT,
  metadata           TEXT NOT NULL DEFAULT '{}',
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  UNIQUE (org_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_firewall_actions_org ON firewall_actions(org_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS ip_vault (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  address_id  TEXT NOT NULL REFERENCES infra_addresses(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  key_version TEXT NOT NULL,
  nonce       TEXT NOT NULL,
  ciphertext  TEXT NOT NULL,
  tag         TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  UNIQUE (org_id, address_id, key_version)
);
CREATE INDEX IF NOT EXISTS idx_ip_vault_fingerprint ON ip_vault(org_id, fingerprint);

CREATE TABLE IF NOT EXISTS trishield_policies (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key         TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  mode        TEXT NOT NULL DEFAULT 'monitor' CHECK (mode IN ('monitor','approval','auto')),
  config      TEXT NOT NULL DEFAULT '{}',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (org_id, key)
);

CREATE TABLE IF NOT EXISTS endpoint_agents (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider     TEXT NOT NULL DEFAULT 'wazuh',
  agent_id     TEXT NOT NULL,
  hostname     TEXT NOT NULL DEFAULT '',
  os           TEXT,
  ip_address   TEXT,
  status       TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online','stale','offline')),
  last_seen_at TEXT,
  asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
  metadata     TEXT NOT NULL DEFAULT '{}',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (org_id, provider, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_org ON endpoint_agents(org_id, status);

CREATE TABLE IF NOT EXISTS trishield_collectors (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL CHECK (kind IN ('suricata','wazuh','waf')),
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  last_seen_at TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (org_id, kind, name)
);
