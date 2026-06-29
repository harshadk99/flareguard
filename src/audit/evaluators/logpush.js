export async function evaluateLogpush(check, api, zoneId, accountId) {
  if (check.id === 'CF-LOG-001') {
    // Try zone-level jobs first, fall back to account-level
    let jobs = [];
    try {
      jobs = await api.getLogpushJobs(zoneId);
    } catch {
      if (accountId) {
        try { jobs = await api.getAccountLogpushJobs(accountId); }
        catch (e) { return result(check, 'NA', `Could not fetch Logpush jobs: ${e.message}`); }
      } else {
        return result(check, 'NA', 'Could not fetch Logpush jobs and no account ID provided.');
      }
    }

    const enabled = (jobs ?? []).filter(j => j.enabled);
    if (enabled.length === 0) {
      return result(check, 'FAIL',
        jobs.length > 0
          ? `${jobs.length} Logpush job(s) configured but none are enabled.`
          : 'No Logpush jobs configured — HTTP traffic logs are not being exported.',
        check.remediation);
    }
    return result(check, 'PASS', `${enabled.length} active Logpush job(s) found — logs are being exported.`);
  }

  return result(check, 'NA', `Logpush check ${check.id} not implemented.`);
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
