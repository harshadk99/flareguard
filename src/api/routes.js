/**
 * API route handlers.
 *
 * Privacy contract (enforced here):
 *   - api_token is NEVER passed to any storage layer.
 *   - zone_id / account_id are hashed before any DB/R2/KV write.
 *   - All storage calls are guarded: if the binding is absent, the code path is skipped.
 *     The audit still runs and returns results — storage is purely opt-in.
 */
import { runZoneAudit, runAccountAudit } from '../audit/engine.js';
import { saveAudit, setReportKey, getAuditHistory, getFindings, getDrift, hasDB } from '../db/index.js';
import { ReportStorage } from '../storage/index.js';
import { Cache } from '../cache/index.js';
import { enqueueZoneScan } from '../queue/index.js';
import { hashId } from '../utils/privacy.js';

const JSON_HEADERS = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const err  = (msg, status = 400) => json({ error: msg }, status);

// ── Input validation ───────────────────────────────────────────────────────────
const ZONE_ID_RE    = /^[a-f0-9]{32}$/i;
const ACCOUNT_ID_RE = /^[a-f0-9]{32}$/i;
const TOKEN_RE      = /^[a-zA-Z0-9_\-]{20,}$/;

function validateInputs(body) {
  const errors = [];
  if (body.zone_id    && !ZONE_ID_RE.test(body.zone_id))    errors.push('zone_id must be a 32-character hex string.');
  if (body.account_id && !ACCOUNT_ID_RE.test(body.account_id)) errors.push('account_id must be a 32-character hex string.');
  if (!TOKEN_RE.test(body.api_token ?? '')) errors.push('api_token is missing or has an invalid format.');
  return errors;
}

// ── Route handlers ─────────────────────────────────────────────────────────────

/**
 * POST /api/audit/zone
 * Body: { zone_id, api_token, account_id? }
 */
export async function handleZoneAudit(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return err('Request body must be JSON.');
  if (!body.zone_id) return err('zone_id is required.');

  const errors = validateInputs(body);
  if (errors.length) return err(errors.join(' '));

  const cache = new Cache(env.CACHE, Number(env.CACHE_TTL_SECONDS ?? 300));

  let report;
  try {
    report = await runZoneAudit(body.zone_id, body.api_token, body.account_id ?? null, env, cache);
  } catch (e) {
    return err(e.message, 400);
  }

  // ── Opt-in persistence (only when bindings are present) ───────────────────
  // Credentials are NOT passed to any storage function.
  let auditId = null;
  if (hasDB(env)) {
    try {
      const zoneHash    = await hashId(body.zone_id);
      const accountHash = body.account_id ? await hashId(body.account_id) : null;
      const storableReport = { ...report, zone_id_hash: zoneHash, account_id_hash: accountHash };

      auditId = await saveAudit(env, storableReport, 'zone');

      if (env.REPORTS) {
        const storage = new ReportStorage(env.REPORTS);
        // Store report keyed by hash, not raw zone_id
        const r2Key = await storage.saveReport(auditId, { ...storableReport, zone_id: zoneHash });
        if (r2Key) await setReportKey(env, auditId, r2Key);
      }
    } catch (e) {
      console.error('Persistence failed (non-fatal):', e.message);
    }
  }

  return json({ ...report, audit_id: auditId, storage_enabled: !!auditId });
}

/**
 * POST /api/audit/account
 * Body: { account_id, api_token }
 */
export async function handleAccountAudit(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return err('Request body must be JSON.');
  if (!body.account_id) return err('account_id is required for account-level scans.');

  const errors = validateInputs(body);
  if (errors.length) return err(errors.join(' '));

  // Enqueue if Queue is bound
  if (env.SCAN_QUEUE) {
    try {
      const { CloudflareAPI } = await import('../utils/cf-api.js');
      const api = new CloudflareAPI(body.api_token);
      const zones = await api.listZones(body.account_id);
      // Enqueue: api_token goes into the queue message (in-flight, not stored in D1)
      await Promise.all(zones.map(z =>
        enqueueZoneScan(env.SCAN_QUEUE, z.id, body.api_token, body.account_id)
      ));
      return json({ queued: true, zone_count: zones.length, message: `${zones.length} zone scan(s) enqueued.` });
    } catch (e) {
      return err(`Failed to enqueue scans: ${e.message}`, 500);
    }
  }

  // Synchronous fallback
  try {
    const result = await runAccountAudit(body.account_id, body.api_token, env);
    return json(result);
  } catch (e) {
    return err(e.message, 400);
  }
}

/**
 * POST /api/test-connection
 * Actually calls the Cloudflare API — does NOT store anything.
 */
export async function handleTestConnection(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return err('Request body must be JSON.');

  const errors = validateInputs(body);
  if (errors.length) return err(errors.join(' '));

  const { CloudflareAPI } = await import('../utils/cf-api.js');
  const api = new CloudflareAPI(body.api_token);

  try {
    if (body.zone_id) {
      const zone = await api.getZone(body.zone_id);
      return json({ success: true, message: `Connected. Zone: ${zone.name} (${zone.status})` });
    }
    if (body.account_id) {
      const zones = await api.listZones(body.account_id);
      return json({ success: true, message: `Connected. Found ${zones.length} zone(s) in account.` });
    }
    return err('Provide either zone_id or account_id.');
  } catch (e) {
    return json({ success: false, error: e.message }, 200);
  }
}

/**
 * GET /api/history/:zoneId
 * Hashes the zone_id before querying — never looks up by raw ID.
 */
export async function handleHistory(zoneId, env) {
  if (!ZONE_ID_RE.test(zoneId)) return err('Invalid zone_id.');
  if (!hasDB(env)) return json({ zone_id: '[hashed]', history: [], storage_enabled: false, message: 'Storage not enabled. Add D1 binding to activate audit history.' });

  try {
    const hash = await hashId(zoneId);
    const history = await getAuditHistory(env, hash);
    return json({ storage_enabled: true, history });
  } catch (e) {
    return err(`DB error: ${e.message}`, 500);
  }
}

/**
 * GET /api/audit/:auditId/findings
 */
export async function handleAuditFindings(auditId, env) {
  if (!hasDB(env)) return json({ findings: [], storage_enabled: false });
  try {
    const findings = await getFindings(env, auditId);
    return json({ audit_id: auditId, findings });
  } catch (e) {
    return err(`DB error: ${e.message}`, 500);
  }
}

/**
 * GET /api/drift/:zoneId
 */
export async function handleDrift(zoneId, env) {
  if (!ZONE_ID_RE.test(zoneId)) return err('Invalid zone_id.');
  if (!hasDB(env)) return json({ storage_enabled: false, message: 'Drift detection requires D1 storage binding.' });

  try {
    const hash = await hashId(zoneId);
    const drift = await getDrift(env, hash);
    if (!drift) return json({ message: 'Need at least 2 audits to detect drift.', changes: [] });
    return json(drift);
  } catch (e) {
    return err(`DB error: ${e.message}`, 500);
  }
}

/**
 * GET /api/report/:key
 */
export async function handleReportDownload(key, env) {
  if (!env.REPORTS) return err('Report storage not enabled.', 404);
  const storage = new ReportStorage(env.REPORTS);
  const report = await storage.getReport(decodeURIComponent(key));
  if (!report) return err('Report not found.', 404);
  return json(report);
}

/**
 * GET /api/status
 * Returns which optional features are active.
 */
export function handleStatus(env) {
  return json({
    mode: hasDB(env) ? 'storage' : 'stateless',
    features: {
      audit_history:    hasDB(env),
      drift_detection:  hasDB(env),
      report_storage:   !!env.REPORTS,
      api_cache:        !!env.CACHE,
      async_scanning:   !!env.SCAN_QUEUE,
    },
    privacy: {
      credentials_stored: false,
      zone_ids_stored:    false,
      stored_identifiers: hasDB(env) ? 'hashed (SHA-256, non-reversible)' : 'none',
    },
  });
}
