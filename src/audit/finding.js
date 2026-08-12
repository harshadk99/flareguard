/**
 * Shared finding constructors and unevaluable-check routing.
 *
 * API / evaluation failures always produce status ERROR (excluded from scoring).
 * NA is reserved for checks that do not apply (missing inputs, not implemented).
 */
import { CloudflareAPIError, permissionHintForPath } from '../utils/cf-api.js';

export function pass(check, message) {
  return result(check, 'PASS', message);
}

export function fail(check, message, remediation) {
  return result(check, 'FAIL', message, remediation ?? check.remediation);
}

export function warn(check, message, remediation) {
  return result(check, 'WARNING', message, remediation ?? check.remediation);
}

export function na(check, message) {
  return result(check, 'NA', message);
}

/** Could not evaluate the control — never evidence of a config failure. */
export function error(check, message) {
  return result(check, 'ERROR', message);
}

/**
 * Map a thrown Cloudflare/API/unexpected error onto the single ERROR path.
 * Distinguishes auth failure from insufficient token scope.
 */
export function unevaluable(check, err) {
  if (err instanceof CloudflareAPIError) {
    if (err.kind === 'permission') {
      const hint = permissionHintForPath(err.path);
      return error(
        check,
        `Token lacks permission for this check. Required: ${hint}. Cloudflare: ${err.apiMessage}`
      );
    }
    if (err.kind === 'auth') {
      return error(
        check,
        `Authentication failed — the API token is invalid, expired, or revoked. Cloudflare: ${err.apiMessage}`
      );
    }
    return error(check, `Could not evaluate: ${err.message}`);
  }
  const msg = err?.message ?? String(err);
  return error(check, `Could not evaluate: ${msg}`);
}

export function result(check, status, message, remediation) {
  return {
    id: check.id,
    name: check.name,
    category: check.category,
    service: check.service,
    severity: check.severity,
    nist_controls: check.nist_controls ?? [],
    cis_controls: check.cis_controls ?? [],
    status,
    message,
    remediation: ['FAIL', 'WARNING'].includes(status) ? (remediation ?? check.remediation ?? null) : null,
  };
}

/** Statuses that never contribute to the posture score. */
export function isUnscored(status) {
  return status === 'NA' || status === 'ERROR';
}

/** Severity weights — CRITICAL findings dominate the score. */
export const SEVERITY_WEIGHT = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0,
};

/**
 * Severity-weighted posture score.
 * PASS earns full weight, WARNING earns half, FAIL earns none.
 * ERROR/NA are excluded (same as before).
 */
export function computeScore(findings) {
  let earned = 0;
  let possible = 0;
  let open_critical = 0;
  let open_high = 0;

  for (const f of findings) {
    if (isUnscored(f.status)) continue;
    const w = SEVERITY_WEIGHT[f.severity] ?? 1;
    possible += w;
    if (f.status === 'PASS') earned += w;
    else if (f.status === 'WARNING') earned += w * 0.5;

    if (f.status === 'FAIL' || f.status === 'WARNING') {
      if (f.severity === 'CRITICAL') open_critical += 1;
      else if (f.severity === 'HIGH') open_high += 1;
    }
  }

  return {
    score: possible > 0 ? Math.round((earned / possible) * 100) : 0,
    open_critical,
    open_high,
    scoring: 'severity_weighted',
    weights: SEVERITY_WEIGHT,
  };
}
