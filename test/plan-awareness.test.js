/**
 * Plan-aware gating: checks that are impossible below a given Cloudflare plan
 * become NA (excluded from scoring) instead of FAIL, so the score reflects
 * what's achievable on the zone's actual plan.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { planGate } from '../src/audit/engine.js';
import { computeScore } from '../src/audit/finding.js';

const WAF1 = {
  id: 'CF-WAF-001', name: 'OWASP CRS', category: 'WAF', service: 'waf',
  severity: 'CRITICAL', min_plan: 'pro', nist_controls: ['SI-3'],
};
const PS2 = {
  id: 'CF-PS-002', name: 'Page Shield enforcement', category: 'Observability',
  service: 'page-shield', severity: 'MEDIUM', min_plan: 'business', nist_controls: ['SI-3'],
};

const FREE = { plan: { legacy_id: 'free', name: 'Free Website' } };
const PRO = { plan: { legacy_id: 'pro', name: 'Pro Website' } };
const ENT = { plan: { legacy_id: 'enterprise', name: 'Enterprise Website' } };
const NAME_ONLY_BIZ = { plan: { name: 'Business' } }; // no legacy_id → parse name
const UNKNOWN = { plan: {} };

describe('plan-aware gating', () => {
  it('gates a Pro-only check to NA on a Free zone, with a plain-English reason', () => {
    const f = planGate(WAF1, FREE);
    assert.ok(f, 'expected a finding');
    assert.equal(f.status, 'NA');
    assert.match(f.message, /Free plan/);
    assert.match(f.message, /requires Pro/i);
  });

  it('does not gate when the plan meets or exceeds the requirement', () => {
    assert.equal(planGate(WAF1, PRO), null);
    assert.equal(planGate(WAF1, ENT), null);
  });

  it('resolves plan tier from the plan name when legacy_id is absent', () => {
    assert.equal(planGate(PS2, NAME_ONLY_BIZ), null); // Business meets business requirement
    assert.ok(planGate(PS2, FREE));                    // Free does not
  });

  it('never gates a check without min_plan', () => {
    assert.equal(planGate({ id: 'X', severity: 'LOW' }, FREE), null);
  });

  it('does not gate when the plan is unknown (fail open to normal evaluation)', () => {
    assert.equal(planGate(WAF1, UNKNOWN), null);
  });

  it('excludes a gated NA finding from the score', () => {
    const gated = planGate(WAF1, FREE); // NA, CRITICAL
    const onePass = { status: 'PASS', severity: 'HIGH' };
    const { score, open_critical } = computeScore([gated, onePass]);
    assert.equal(score, 100, 'NA must not drag the score');
    assert.equal(open_critical, 0, 'a gated check is not an open critical');
  });
});
