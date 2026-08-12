/**
 * WAF evaluator — uses the current Rulesets API
 * (http_request_firewall_managed phase), not the retired WAF packages API.
 *
 * Cloudflare published managed ruleset IDs (stable, documented):
 *   OWASP Core Ruleset:           4814384a9e5d4991b9815dcfc25d2f1f
 *   Cloudflare Managed Ruleset:   efb7b8c949ac4650a09736fc376e9aee
 *   Free Managed Ruleset:         4efc408615d14a388ebe1937d91b69fb
 */
import { pass, fail, na, unevaluable } from '../finding.js';

export const OWASP_MANAGED_RULESET_ID = '4814384a9e5d4991b9815dcfc25d2f1f';
export const CF_MANAGED_RULESET_ID = 'efb7b8c949ac4650a09736fc376e9aee';
export const CF_FREE_MANAGED_RULESET_ID = '4efc408615d14a388ebe1937d91b69fb';

const DETECT_ONLY_ACTIONS = new Set(['log', 'simulate', 'ddos_dynamic']);

function executeRules(ruleset) {
  return (ruleset?.rules ?? []).filter(r =>
    r.action === 'execute' && r.enabled !== false && r.action_parameters?.id
  );
}

function rulesetId(rule) {
  return rule.action_parameters?.id;
}

function isOwasp(rule) {
  const id = rulesetId(rule);
  if (id === OWASP_MANAGED_RULESET_ID) return true;
  return /owasp/i.test(rule.description ?? '') || /owasp/i.test(rule.action_parameters?.ref ?? '');
}

function isManagedWaf(rule) {
  const id = rulesetId(rule);
  return (
    id === OWASP_MANAGED_RULESET_ID ||
    id === CF_MANAGED_RULESET_ID ||
    id === CF_FREE_MANAGED_RULESET_ID ||
    isOwasp(rule) ||
    /managed ruleset/i.test(rule.description ?? '')
  );
}

function isDetectOnly(rule) {
  const overrides = rule.action_parameters?.overrides ?? {};
  // Ruleset-level override forces every rule into log/simulate
  if (DETECT_ONLY_ACTIONS.has(overrides.action)) return true;
  // Tag/category overrides that force log
  if (Array.isArray(overrides.categories) &&
      overrides.categories.some(c => DETECT_ONLY_ACTIONS.has(c.action))) {
    return true;
  }
  return false;
}

export async function evaluateWAF(check, api, zoneId) {
  let ruleset;
  try {
    ruleset = await api.getManagedWAFEntrypoint(zoneId);
  } catch (err) {
    if (err?.kind === 'not_found' || err?.status === 404) {
      if (check.id === 'CF-WAF-001') {
        return fail(check, 'No managed WAF rulesets deployed (http_request_firewall_managed entrypoint missing). Enable OWASP CRS in Security > WAF.');
      }
      if (check.id === 'CF-WAF-002') {
        return fail(check, 'No managed WAF rulesets deployed — cannot verify block mode.');
      }
      return na(check, 'Managed WAF entrypoint not found for this zone.');
    }
    return unevaluable(check, err);
  }

  const deployed = executeRules(ruleset);

  if (check.id === 'CF-WAF-001') {
    const owasp = deployed.filter(isOwasp);
    if (owasp.length === 0) {
      const hasOther = deployed.some(isManagedWaf);
      return fail(
        check,
        hasOther
          ? 'Cloudflare Managed Ruleset is deployed, but OWASP Core Ruleset is not. Enable OWASP CRS in Security > WAF > Managed rules.'
          : 'OWASP Core Rule Set is not deployed on this zone.'
      );
    }
    return pass(check, `OWASP Core Ruleset is deployed (${owasp.length} execute rule(s) in http_request_firewall_managed).`);
  }

  if (check.id === 'CF-WAF-002') {
    const managed = deployed.filter(isManagedWaf);
    if (managed.length === 0) {
      return fail(check, 'No managed WAF rulesets are deployed — WAF is not actively protecting this zone.');
    }
    const detectOnly = managed.filter(isDetectOnly);
    if (detectOnly.length === managed.length) {
      return fail(
        check,
        `All ${managed.length} managed WAF ruleset(s) are overridden to log/simulate (detect-only). Set action to Block/Managed Default.`
      );
    }
    if (detectOnly.length > 0) {
      return fail(
        check,
        `${detectOnly.length} of ${managed.length} managed WAF ruleset(s) are in detect-only (log/simulate) mode.`
      );
    }
    return pass(check, `${managed.length} managed WAF ruleset(s) deployed without detect-only overrides.`);
  }

  return na(check, `WAF check ${check.id} not implemented.`);
}
