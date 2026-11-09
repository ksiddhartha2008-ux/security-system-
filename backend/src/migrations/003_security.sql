-- Migration v3: CSRF binding, tamper-evident audit chain, evidence scanning, approval expiry.
ALTER TABLE sessions ADD COLUMN csrf_hash TEXT;

ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN result TEXT NOT NULL DEFAULT 'success';
ALTER TABLE audit_logs ADD COLUMN request_id TEXT;

ALTER TABLE forensic_evidence ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'not_scanned';
ALTER TABLE forensic_evidence ADD COLUMN scan_detail TEXT;

ALTER TABLE workflow_executions ADD COLUMN approval_expires_at TEXT;
ALTER TABLE workflow_executions ADD COLUMN idempotency_key TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_logs(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_workflow_idempotency ON workflow_executions(workflow_id, idempotency_key);

-- Sessions created before CSRF binding have no token hash. Invalidate them so
-- every client signs in again and receives a bound token.
DELETE FROM sessions;
