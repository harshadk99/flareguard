export async function evaluateDNSSEC(check, api, zoneId) {
  let dnssec;
  try {
    dnssec = await api.getDNSSEC(zoneId);
  } catch (err) {
    return fail(check, `Could not fetch DNSSEC status: ${err.message}`);
  }

  const status = dnssec?.status ?? 'unknown';
  if (status === 'active') return pass_(check, 'DNSSEC is active and validated.');
  if (status === 'pending') return warn(check, 'DNSSEC is pending — DS record may not yet be added at registrar.');
  return fail(check, `DNSSEC is not enabled (status: ${status}).`);
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function warn(check, message) { return r(check, 'WARNING', message, check.remediation); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: ['FAIL','WARNING'].includes(status) ? remediation : null };
}
