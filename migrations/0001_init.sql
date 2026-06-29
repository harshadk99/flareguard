-- FlareGuard D1 Schema
-- Privacy: raw zone/account IDs are NEVER stored. Only short SHA-256 hashes.
-- API tokens are NEVER stored under any circumstances.

CREATE TABLE IF NOT EXISTS audits (
  id TEXT PRIMARY KEY,
  zone_id_hash TEXT,           -- SHA-256(zone_id)[0:16] — not reversible
  account_id_hash TEXT,        -- SHA-256(account_id)[0:16] — not reversible
  scan_type TEXT NOT NULL CHECK (scan_type IN ('zone', 'account', 'worker')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  score INTEGER,
  total_checks INTEGER DEFAULT 0,
  passed INTEGER DEFAULT 0,
  failed INTEGER DEFAULT 0,
  warnings INTEGER DEFAULT 0,
  report_r2_key TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id),
  check_id TEXT NOT NULL,
  check_name TEXT NOT NULL,
  category TEXT NOT NULL,
  service TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  status TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL', 'WARNING', 'NA')),
  message TEXT,
  remediation TEXT,
  nist_controls TEXT,           -- JSON array as text
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY,          -- script name (not sensitive)
  account_id_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  last_deployed_at TEXT,
  routes TEXT,                  -- JSON array
  is_zombie INTEGER DEFAULT 0,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audits_zone    ON audits(zone_id_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_account ON audits(account_id_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(audit_id, status);
CREATE INDEX IF NOT EXISTS idx_workers_account ON workers(account_id_hash);
