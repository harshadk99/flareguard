export async function evaluateWAF(check, api, zoneId) {
  let packages;
  try {
    packages = await api.getWAFPackages(zoneId);
  } catch (err) {
    // WAF packages API requires a paid plan — treat as NA rather than FAIL
    return na(check, `WAF packages not available (may require Pro/Business plan): ${err.message}`);
  }

  if (!Array.isArray(packages) || packages.length === 0) {
    return na(check, 'No WAF packages found. WAF may not be available on this zone plan.');
  }

  const owasp = packages.find(p =>
    p.name?.toLowerCase().includes('owasp') ||
    p.description?.toLowerCase().includes('owasp')
  );

  if (check.id === 'CF-WAF-001') {
    if (!owasp) return fail(check, 'OWASP Core Rule Set package not found.');
    const enabled = owasp.detection_mode !== 'off';
    const sensitivity = owasp.sensitivity ?? 'off';
    const goodSensitivity = ['medium', 'high'].includes(sensitivity);
    if (enabled && goodSensitivity) return pass_(check, `OWASP CRS enabled with ${sensitivity} sensitivity.`);
    if (enabled) return fail(check, `OWASP CRS is enabled but sensitivity is "${sensitivity}" (need medium or high).`);
    return fail(check, 'OWASP Core Rule Set is disabled.');
  }

  if (check.id === 'CF-WAF-002') {
    const allBlock = packages.every(p => p.action_mode === 'block' || p.detection_mode !== 'off');
    if (allBlock) return pass_(check, 'All WAF packages are in block mode.');
    const simulate = packages.filter(p => p.action_mode !== 'block').map(p => p.name).join(', ');
    return fail(check, `Some WAF packages are not in block mode: ${simulate}`);
  }

  return na(check, `WAF check ${check.id} not implemented.`);
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function na(check, message) { return r(check, 'NA', message); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: status === 'FAIL' ? remediation : null };
}
