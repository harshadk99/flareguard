-- Allow ERROR finding status for unevaluable checks (API / permission failures).
-- ERROR is excluded from scoring the same way NA is.

-- SQLite cannot ALTER a CHECK constraint in place; recreate findings table.
CREATE TABLE findings_v2 (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id),
  check_id TEXT NOT NULL,
  check_name TEXT NOT NULL,
  category TEXT NOT NULL,
  service TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  status TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL', 'WARNING', 'NA', 'ERROR')),
  message TEXT,
  remediation TEXT,
  nist_controls TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO findings_v2
  SELECT id, audit_id, check_id, check_name, category, service, severity, status, message, remediation, nist_controls, created_at
  FROM findings;

DROP TABLE findings;
ALTER TABLE findings_v2 RENAME TO findings;

CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(audit_id, status);
