/**
 * Evaluates a single Cloudflare zone setting against a baseline check.
 * Supports: expect, expect_one_of, expect_min_tls
 */
export async function evaluateZoneSetting(check, api, zoneId) {
  let value;
  try {
    const result = await api.getZoneSetting(zoneId, check.setting);
    value = result.value;
  } catch (err) {
    return fail(check, `Could not fetch setting "${check.setting}": ${err.message}`);
  }

  // Exact match
  if (check.expect !== undefined) {
    const pass = String(value) === String(check.expect);
    return pass
      ? pass_(check, `${check.setting} is "${value}"`)
      : fail(check, `${check.setting} is "${value}", expected "${check.expect}"`, check.remediation);
  }

  // One-of match
  if (check.expect_one_of) {
    const pass = check.expect_one_of.includes(String(value));
    return pass
      ? pass_(check, `${check.setting} is "${value}"`)
      : fail(check, `${check.setting} is "${value}", expected one of: ${check.expect_one_of.join(', ')}`, check.remediation);
  }

  // Minimum TLS version comparison
  if (check.expect_min_tls) {
    const actual = parseFloat(value);
    const min = parseFloat(check.expect_min_tls);
    const pass = actual >= min;
    return pass
      ? pass_(check, `Minimum TLS version is ${value}`)
      : fail(check, `Minimum TLS version is ${value}, expected >= ${check.expect_min_tls}`, check.remediation);
  }

  return na(check, `No evaluation rule matched for check ${check.id}`);
}

function pass_(check, message) {
  return result(check, 'PASS', message);
}
function fail(check, message, remediation) {
  return result(check, 'FAIL', message, remediation ?? check.remediation);
}
function na(check, message) {
  return result(check, 'NA', message);
}
function result(check, status, message, remediation) {
  return {
    id: check.id,
    name: check.name,
    category: check.category,
    service: check.service,
    severity: check.severity,
    nist_controls: check.nist_controls ?? [],
    status,
    message,
    remediation: status === 'FAIL' ? (remediation ?? check.remediation) : null,
  };
}
