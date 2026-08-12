import { pass, fail, unevaluable } from '../finding.js';

/**
 * CF-RL-001 — at least one enabled rate limiting rule in the
 * http_ratelimit phase entrypoint ruleset (current Rulesets API).
 *
 * A 404 on the entrypoint means no ruleset exists yet → FAIL (no rules).
 * Auth / permission / other API errors → ERROR (unevaluable).
 */
export async function evaluateRateLimit(check, api, zoneId) {
  let ruleset;
  try {
    ruleset = await api.getRateLimitEntrypoint(zoneId);
  } catch (err) {
    // No entrypoint ruleset yet → zone has zero rate limiting rules configured
    if (err?.kind === 'not_found' || err?.status === 404) {
      return fail(check, 'No rate limiting rules are configured for this zone (http_ratelimit entrypoint missing).');
    }
    return unevaluable(check, err);
  }

  const rules = Array.isArray(ruleset?.rules) ? ruleset.rules : [];
  if (rules.length === 0) {
    return fail(check, 'No rate limiting rules are configured for this zone.');
  }

  // Rulesets API uses `enabled` (default true when omitted). Ignore purely disabled rules.
  const enabled = rules.filter(r => r.enabled !== false);
  if (enabled.length === 0) {
    return fail(check, `${rules.length} rate limit rule(s) exist but all are disabled.`);
  }
  return pass(check, `${enabled.length} active rate limiting rule(s) configured in http_ratelimit phase.`);
}
