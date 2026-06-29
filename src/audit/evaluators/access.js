/**
 * Zero Trust / Cloudflare Access evaluator.
 * Requires an account_id to be passed alongside zone_id.
 */
export async function evaluateAccess(check, api, _zoneId, accountId) {
  if (!accountId) {
    return na(check, 'Account ID is required for Zero Trust checks. Provide account_id in your request.');
  }

  if (check.id === 'ZT-001') return checkMFA(check, api, accountId);
  if (check.id === 'ZT-002') return checkIdP(check, api, accountId);
  return na(check, `Access check ${check.id} not implemented.`);
}

async function checkMFA(check, api, accountId) {
  let apps;
  try {
    apps = await api.listAccessApps(accountId);
  } catch (err) {
    return na(check, `Could not fetch Access apps: ${err.message}`);
  }

  if (!Array.isArray(apps) || apps.length === 0) {
    return na(check, 'No Cloudflare Access applications found for this account.');
  }

  const results = await Promise.allSettled(
    apps.map(app => api.getAccessAppPolicy(accountId, app.id))
  );

  const appsWithoutMFA = [];
  apps.forEach((app, i) => {
    const outcome = results[i];
    if (outcome.status === 'rejected') return; // skip if policy fetch fails
    const policies = outcome.value ?? [];
    const hasMFA = policies.some(p =>
      p.require?.some(r => r.auth_method?.auth_method === 'mfa' || r.mfa)
    );
    if (!hasMFA) appsWithoutMFA.push(app.name ?? app.id);
  });

  if (appsWithoutMFA.length === 0) {
    return pass_(check, `MFA is enforced on all ${apps.length} Access application(s).`);
  }
  return fail(check, `MFA not enforced on: ${appsWithoutMFA.join(', ')}`);
}

async function checkIdP(check, api, accountId) {
  let idps;
  try {
    idps = await api.listIdentityProviders(accountId);
  } catch (err) {
    return na(check, `Could not fetch identity providers: ${err.message}`);
  }

  if (!Array.isArray(idps) || idps.length === 0) {
    return fail(check, 'No identity providers configured for Zero Trust.');
  }

  const nonDefault = idps.filter(p => p.type !== 'onetimepin');
  if (nonDefault.length > 0) {
    return pass_(check, `${nonDefault.length} identity provider(s) configured: ${nonDefault.map(p => p.name).join(', ')}`);
  }
  return warn(check, 'Only One-Time PIN (OTP) is configured — consider adding a proper IdP (Okta, Azure AD, Google, etc.)');
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function warn(check, message) { return r(check, 'WARNING', message, check.remediation); }
function na(check, message) { return r(check, 'NA', message); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: ['FAIL','WARNING'].includes(status) ? remediation : null };
}
