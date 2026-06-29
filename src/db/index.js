/**
 * D1 persistence layer — all functions are no-ops when env.DB is not bound.
 *
 * Privacy guarantees:
 *   - API tokens are NEVER stored.
 *   - Raw zone/account IDs are NEVER stored — only a short SHA-256 hash is used as the key.
 *   - Callers must pre-hash IDs with hashId() before passing them here.
 */
import { uuid } from '../utils/uuid.js';

/** Returns true when D1 is available (opt-in storage mode). */
export function hasDB(env) {
  return !!env?.DB;
}

/**
 * Persist an audit report. Returns the audit ID, or null if DB not bound.
 * @param {object} env  - Worker env bindings
 * @param {object} report  - Audit report (must already have zone_id_hash / account_id_hash set)
 * @param {string} scanType
 */
export async function saveAudit(env, report, scanType = 'zone') {
  if (!hasDB(env)) return null;

  const auditId = uuid();
  await env.DB.prepare(`
    INSERT INTO audits (id, zone_id_hash, account_id_hash, scan_type, status, score, total_checks, passed, failed, warnings, completed_at)
    VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, datetime('now'))
  `).bind(
    auditId,
    report.zone_id_hash ?? null,
    report.account_id_hash ?? null,
    scanType,
    report.summary.score,
    report.summary.total_checks,
    report.summary.passed,
    report.summary.failed,
    report.summary.warnings,
  ).run();

  if (report.findings?.length) {
    const stmt = env.DB.prepare(`
      INSERT INTO findings (id, audit_id, check_id, check_name, category, service, severity, status, message, remediation, nist_controls)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await env.DB.batch(
      report.findings.map(f =>
        stmt.bind(
          uuid(), auditId, f.id, f.name, f.category, f.service,
          f.severity, f.status, f.message, f.remediation ?? null,
          JSON.stringify(f.nist_controls ?? []),
        )
      )
    );
  }

  return auditId;
}

export async function setReportKey(env, auditId, r2Key) {
  if (!hasDB(env)) return;
  await env.DB.prepare(`UPDATE audits SET report_r2_key = ? WHERE id = ?`).bind(r2Key, auditId).run();
}

/** Look up history by hashed zone ID. */
export async function getAuditHistory(env, zoneIdHash, limit = 20) {
  if (!hasDB(env)) return [];
  const { results } = await env.DB.prepare(`
    SELECT id, scan_type, score, total_checks, passed, failed, warnings, created_at, completed_at, report_r2_key
    FROM audits WHERE zone_id_hash = ? ORDER BY created_at DESC LIMIT ?
  `).bind(zoneIdHash, limit).all();
  return results;
}

export async function getFindings(env, auditId) {
  if (!hasDB(env)) return [];
  const { results } = await env.DB.prepare(`
    SELECT * FROM findings WHERE audit_id = ? ORDER BY
      CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
      CASE status WHEN 'FAIL' THEN 1 WHEN 'WARNING' THEN 2 WHEN 'PASS' THEN 3 ELSE 4 END
  `).bind(auditId).all();
  return results.map(r => ({ ...r, nist_controls: JSON.parse(r.nist_controls ?? '[]') }));
}

/** Drift: compare two most recent audits for a hashed zone ID. */
export async function getDrift(env, zoneIdHash) {
  if (!hasDB(env)) return null;
  const { results } = await env.DB.prepare(`
    SELECT id FROM audits WHERE zone_id_hash = ? AND status = 'completed'
    ORDER BY created_at DESC LIMIT 2
  `).bind(zoneIdHash).all();

  if (results.length < 2) return null;

  const [latest, previous] = await Promise.all([
    getFindings(env, results[0].id),
    getFindings(env, results[1].id),
  ]);

  const prevMap = Object.fromEntries(previous.map(f => [f.check_id, f.status]));
  const changes = latest
    .filter(f => prevMap[f.check_id] && prevMap[f.check_id] !== f.status)
    .map(f => ({ check_id: f.check_id, check_name: f.check_name, from: prevMap[f.check_id], to: f.status }));

  return { audit_id_latest: results[0].id, audit_id_previous: results[1].id, changes };
}

export async function upsertWorker(env, accountIdHash, worker) {
  if (!hasDB(env)) return;
  await env.DB.prepare(`
    INSERT INTO workers (id, account_id_hash, name, last_deployed_at, routes, is_zombie, last_seen_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      last_deployed_at = excluded.last_deployed_at,
      routes = excluded.routes,
      is_zombie = excluded.is_zombie,
      last_seen_at = excluded.last_seen_at
  `).bind(
    worker.id,
    accountIdHash,
    worker.name ?? worker.id,
    worker.modified_on ?? null,
    JSON.stringify(worker.routes ?? []),
    worker.is_zombie ? 1 : 0,
  ).run();
}
