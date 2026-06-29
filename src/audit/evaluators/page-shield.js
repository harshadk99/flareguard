export async function evaluatePageShield(check, api, zoneId) {
  let ps;
  try {
    ps = await api.getPageShield(zoneId);
  } catch (e) {
    return result(check, 'NA', `Could not fetch Page Shield status: ${e.message}`);
  }

  if (check.id === 'CF-PS-001') {
    return ps?.enabled
      ? result(check, 'PASS', 'Page Shield is enabled — scripts and connections are monitored.')
      : result(check, 'FAIL', 'Page Shield is disabled — client-side scripts are unmonitored.', check.remediation);
  }

  if (check.id === 'CF-PS-002') {
    const policy = ps?.policy_enabled ?? false;
    return policy
      ? result(check, 'PASS', 'Page Shield policy enforcement is active.')
      : result(check, 'WARNING', 'Page Shield is in monitor-only mode — enable policy enforcement to block malicious scripts.', check.remediation);
  }

  return result(check, 'NA', `Page Shield check ${check.id} not implemented.`);
}

function result(check, status, message, remediation) {
  return {
    id: check.id, name: check.name, category: check.category,
    service: check.service, severity: check.severity,
    nist_controls: check.nist_controls ?? [],
    cis_controls: check.cis_controls ?? [],
    status, message,
    remediation: status === 'FAIL' || status === 'WARNING' ? (remediation ?? check.remediation) : null,
  };
}
