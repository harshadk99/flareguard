import yaml from 'js-yaml';
import { CloudflareAPI } from '../utils/cf-api.js';
import { hashId } from '../utils/privacy.js';
import { resolveControls, FRAMEWORK_VERSIONS } from '../utils/mappings.js';
import { na as naFinding, error as errorFinding, isUnscored, computeScore } from './finding.js';
import { BUNDLED_BASELINE } from './bundled-baseline.js';
import { evaluateZoneSetting } from './evaluators/zone-setting.js';
import { evaluateWAF } from './evaluators/waf.js';
import { evaluateDNSSEC } from './evaluators/dnssec.js';
import { evaluateBot } from './evaluators/bot.js';
import { evaluateRateLimit } from './evaluators/rate-limit.js';
import { evaluateAccess } from './evaluators/access.js';
import { evaluateWorkers } from './evaluators/workers.js';
import { evaluatePageShield } from './evaluators/page-shield.js';
import { evaluateLogpush } from './evaluators/logpush.js';

// Baseline is bundled at deploy time — loaded once per isolate lifetime.
// Override with env.BASELINE_YAML (tests / local experiments) — never cached into _baseline.
let _baseline = null;

async function getBaseline(env) {
  if (env?.BASELINE_YAML) return yaml.load(env.BASELINE_YAML);
  if (_baseline) return _baseline;
  _baseline = yaml.load(BUNDLED_BASELINE);
  return _baseline;
}

/**
 * Run a zone audit.
 * @param {string} zoneId
 * @param {string} apiToken
 * @param {string|null} accountId  – optional, enables ZT + Worker checks
 * @param {object} env             – Cloudflare Worker env bindings
 * @param {object} [cache]         – optional KV cache helper
 * @param {{ includeRawIds?: boolean }} [opts]
 */
export async function runZoneAudit(zoneId, apiToken, accountId, env, cache, opts = {}) {
  const api = new CloudflareAPI(apiToken);

  let zone;
  try {
    zone = await api.getZone(zoneId);
  } catch (err) {
    throw new Error(`Invalid zone ID or API token: ${err.message}`);
  }

  const baseline = await getBaseline(env);
  const findings = await Promise.all(
    baseline.map(check => dispatch(check, api, zoneId, accountId, zone))
  );

  return buildReport(zone, findings, accountId, opts);
}

/**
 * Run an account-wide scan across all zones.
 * @param {{ includeRawIds?: boolean }} [opts]
 */
export async function runAccountAudit(accountId, apiToken, env, cache, opts = {}) {
  const api = new CloudflareAPI(apiToken);

  let zones;
  try {
    zones = await api.listZones(accountId);
  } catch (err) {
    throw new Error(`Could not list zones: ${err.message}`);
  }

  const results = await Promise.all(
    zones.map(async z => {
      try {
        return await runZoneAudit(z.id, apiToken, accountId, env, cache, opts);
      } catch (err) {
        const entry = { zone_name: z.name, error: err.message };
        if (opts.includeRawIds) entry.zone_id = z.id;
        else entry.zone_id_hash = await hashId(z.id);
        return entry;
      }
    })
  );

  const out = { zones: results };
  if (opts.includeRawIds) out.account_id = accountId;
  else out.account_id_hash = await hashId(accountId);
  return out;
}

// ── Dispatcher ─────────────────────────────────────────────────────────────────

async function dispatch(check, api, zoneId, accountId, zone) {
  let finding;
  try {
    switch (check.service) {
      case 'zone-setting': finding = await evaluateZoneSetting(check, api, zoneId); break;
      case 'waf':          finding = await evaluateWAF(check, api, zoneId); break;
      case 'dnssec':       finding = await evaluateDNSSEC(check, api, zoneId); break;
      case 'bot':          finding = await evaluateBot(check, api, zoneId); break;
      case 'rate-limit':   finding = await evaluateRateLimit(check, api, zoneId); break;
      case 'access':       finding = await evaluateAccess(check, api, zoneId, accountId); break;
      case 'workers':      finding = await evaluateWorkers(check, api, zoneId, accountId); break;
      case 'page-shield':  finding = await evaluatePageShield(check, api, zoneId); break;
      case 'logpush':      finding = await evaluateLogpush(check, api, zoneId, accountId); break;
      default:
        finding = naFinding(check, `Service "${check.service}" not implemented.`);
    }
  } catch (err) {
    finding = errorFinding(check, `Evaluator threw an unexpected error: ${err.message}`);
  }

  finding.resolved_controls = resolveControls(check.nist_controls, check.cis_controls);

  // Attach dashboard deep-link path from baseline when present
  if (check.dashboard_path) {
    finding.dashboard_path = check.dashboard_path;
    // Cloudflare ?to= deep links resolve account/zone from session context
    finding.dashboard_hint = `Cloudflare dashboard → ${check.dashboard_path}` +
      (zone?.name ? ` (zone: ${zone.name})` : '');
  }

  return finding;
}

// ── Report builder ─────────────────────────────────────────────────────────────

/**
 * Build the audit report.
 * By default zone_id / account_id are omitted and only SHA-256 hashes are included.
 * Pass { includeRawIds: true } to opt into plaintext IDs.
 */
async function buildReport(zone, findings, accountId, opts = {}) {
  const passed   = findings.filter(f => f.status === 'PASS').length;
  const failed   = findings.filter(f => f.status === 'FAIL').length;
  const warnings = findings.filter(f => f.status === 'WARNING').length;
  const na       = findings.filter(f => f.status === 'NA').length;
  const errors   = findings.filter(f => f.status === 'ERROR').length;
  const scored   = findings.filter(f => !isUnscored(f.status)).length;
  const { score, open_critical, open_high, scoring, weights } = computeScore(findings);

  const rawZoneId = zone.id;
  const rawAccountId = accountId ?? zone.account?.id ?? null;

  const report = {
    timestamp: new Date().toISOString(),
    zone_name: zone.name,
    zone_id_hash: await hashId(rawZoneId),
    account_id_hash: rawAccountId ? await hashId(rawAccountId) : null,
    framework_versions: FRAMEWORK_VERSIONS,
    summary: {
      total_checks: findings.length,
      passed,
      failed,
      warnings,
      na,
      errors,
      scored,
      score,
      open_critical,
      open_high,
      scoring,
      weights,
    },
    findings,
  };

  if (opts.includeRawIds) {
    report.zone_id = rawZoneId;
    report.account_id = rawAccountId;
  }

  return report;
}
