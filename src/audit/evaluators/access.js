/**
 * Zero Trust / Cloudflare Access evaluator.
 * Requires an account_id to be passed alongside zone_id.
 */
import { pass, fail, warn, na, unevaluable } from '../finding.js';

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
    return unevaluable(check, err);
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
    return pass(check, `MFA is enforced on all ${apps.length} Access application(s).`);
  }
  return fail(check, `MFA not enforced on: ${appsWithoutMFA.join(', ')}`);
}

async function checkIdP(check, api, accountId) {
  let idps;
  try {
    idps = await api.listIdentityProviders(accountId);
  } catch (err) {
    return unevaluable(check, err);
  }

  if (!Array.isArray(idps) || idps.length === 0) {
    return fail(check, 'No identity providers configured for Zero Trust.');
  }

  const nonDefault = idps.filter(p => p.type !== 'onetimepin');
  if (nonDefault.length > 0) {
    return pass(check, `${nonDefault.length} identity provider(s) configured: ${nonDefault.map(p => p.name).join(', ')}`);
  }
  return warn(check, 'Only One-Time PIN (OTP) is configured — consider adding a proper IdP (Okta, Azure AD, Google, etc.)');
}
