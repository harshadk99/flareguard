import { pass, fail, warn, na, unevaluable } from '../finding.js';

export async function evaluatePageShield(check, api, zoneId) {
  let ps;
  try {
    ps = await api.getPageShield(zoneId);
  } catch (err) {
    return unevaluable(check, err);
  }

  if (check.id === 'CF-PS-001') {
    return ps?.enabled
      ? pass(check, 'Page Shield is enabled — scripts and connections are monitored.')
      : fail(check, 'Page Shield is disabled — client-side scripts are unmonitored.');
  }

  if (check.id === 'CF-PS-002') {
    const policy = ps?.policy_enabled ?? false;
    return policy
      ? pass(check, 'Page Shield policy enforcement is active.')
      : warn(check, 'Page Shield is in monitor-only mode — enable policy enforcement to block malicious scripts.');
  }

  return na(check, `Page Shield check ${check.id} not implemented.`);
}
