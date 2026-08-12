import { pass, fail, na, unevaluable } from '../finding.js';

export async function evaluateLogpush(check, api, zoneId, accountId) {
  if (check.id !== 'CF-LOG-001') {
    return na(check, `Logpush check ${check.id} not implemented.`);
  }

  let jobs = [];
  let lastErr = null;
  try {
    jobs = await api.getLogpushJobs(zoneId);
  } catch (err) {
    lastErr = err;
    if (accountId) {
      try {
        jobs = await api.getAccountLogpushJobs(accountId);
        lastErr = null;
      } catch (e) {
        lastErr = e;
      }
    }
  }

  if (lastErr) return unevaluable(check, lastErr);

  const enabled = (jobs ?? []).filter(j => j.enabled);
  if (enabled.length === 0) {
    return fail(
      check,
      jobs.length > 0
        ? `${jobs.length} Logpush job(s) configured but none are enabled.`
        : 'No Logpush jobs configured — HTTP traffic logs are not being exported.'
    );
  }
  return pass(check, `${enabled.length} active Logpush job(s) found — logs are being exported.`);
}
