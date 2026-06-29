export async function evaluateRateLimit(check, api, zoneId) {
  let rules;
  try {
    rules = await api.getRateLimitRules(zoneId);
  } catch (err) {
    return na(check, `Rate limit rules not available: ${err.message}`);
  }

  if (!Array.isArray(rules) || rules.length === 0) {
    return fail(check, 'No rate limiting rules are configured for this zone.');
  }

  const enabled = rules.filter(r => r.disabled !== true);
  if (enabled.length === 0) return fail(check, `${rules.length} rate limit rule(s) exist but all are disabled.`);
  return pass_(check, `${enabled.length} active rate limiting rule(s) configured.`);
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function na(check, message) { return r(check, 'NA', message); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: status === 'FAIL' ? remediation : null };
}
