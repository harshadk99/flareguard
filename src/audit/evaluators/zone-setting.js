/**
 * Evaluates a single Cloudflare zone setting against a baseline check.
 * Supports: expect, expect_one_of, expect_min_tls, expect_nested (value | min)
 */
import { pass, fail, na, unevaluable } from '../finding.js';

export async function evaluateZoneSetting(check, api, zoneId) {
  let value;
  try {
    const result = await api.getZoneSetting(zoneId, check.setting);
    value = result.value;
  } catch (err) {
    // Failed fetch / undefined setting / permission — not evidence the control failed
    return unevaluable(check, err);
  }

  // Exact match
  if (check.expect !== undefined) {
    const ok = String(value) === String(check.expect);
    return ok
      ? pass(check, `${check.setting} is "${value}"`)
      : fail(check, `${check.setting} is "${value}", expected "${check.expect}"`);
  }

  // One-of match
  if (check.expect_one_of) {
    const ok = check.expect_one_of.includes(String(value));
    return ok
      ? pass(check, `${check.setting} is "${value}"`)
      : fail(check, `${check.setting} is "${value}", expected one of: ${check.expect_one_of.join(', ')}`);
  }

  // Minimum TLS version comparison
  if (check.expect_min_tls) {
    const actual = parseFloat(value);
    const min = parseFloat(check.expect_min_tls);
    const ok = actual >= min;
    return ok
      ? pass(check, `Minimum TLS version is ${value}`)
      : fail(check, `Minimum TLS version is ${value}, expected >= ${check.expect_min_tls}`);
  }

  // Nested object path check — e.g. HSTS: { strict_transport_security: { enabled: true, max_age: N } }
  if (check.expect_nested) {
    const { path, value: expected, min } = check.expect_nested;
    const actual = path.split('.').reduce((obj, key) => obj?.[key], value);

    if (min !== undefined) {
      const n = Number(actual);
      if (Number.isNaN(n)) {
        return fail(check, `${check.setting}.${path} is ${actual ?? 'not set'}, expected >= ${min}`);
      }
      return n >= Number(min)
        ? pass(check, `${check.setting}.${path} is ${n} (>= ${min})`)
        : fail(check, `${check.setting}.${path} is ${n}, expected >= ${min}`);
    }

    const ok = String(actual) === String(expected);
    return ok
      ? pass(check, `${check.setting}.${path} is ${actual}`)
      : fail(check, `${check.setting}.${path} is ${actual ?? 'not set'}, expected ${expected}`);
  }

  return na(check, `No evaluation rule matched for check ${check.id}`);
}
