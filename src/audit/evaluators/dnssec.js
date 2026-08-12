import { pass, fail, warn, unevaluable } from '../finding.js';

export async function evaluateDNSSEC(check, api, zoneId) {
  let dnssec;
  try {
    dnssec = await api.getDNSSEC(zoneId);
  } catch (err) {
    return unevaluable(check, err);
  }

  const status = dnssec?.status ?? 'unknown';
  if (status === 'active') return pass(check, 'DNSSEC is active and validated.');
  if (status === 'pending') return warn(check, 'DNSSEC is pending — DS record may not yet be added at registrar.');
  return fail(check, `DNSSEC is not enabled (status: ${status}).`);
}
