/**
 * Scoring + modern WAF/Workers evaluator tests.
 */
import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { computeScore, isUnscored } from '../src/audit/finding.js';
import { evaluateWAF, OWASP_MANAGED_RULESET_ID, CF_MANAGED_RULESET_ID } from '../src/audit/evaluators/waf.js';
import { evaluateWorkers } from '../src/audit/evaluators/workers.js';
import { CloudflareAPI } from '../src/utils/cf-api.js';

const WAF1 = {
  id: 'CF-WAF-001', name: 'OWASP CRS', category: 'WAF', service: 'waf',
  severity: 'CRITICAL', nist_controls: ['SI-3'], remediation: 'Enable OWASP.',
};
const WAF2 = {
  id: 'CF-WAF-002', name: 'WAF block mode', category: 'WAF', service: 'waf',
  severity: 'HIGH', nist_controls: ['SI-3'], remediation: 'Use block mode.',
};
const WRK1 = {
  id: 'WRK-001', name: 'No zombies', category: 'Workers', service: 'workers',
  severity: 'HIGH', nist_controls: ['CM-8'], remediation: 'Remove zombies.',
};
const WRK2 = {
  id: 'WRK-002', name: 'No plaintext secrets', category: 'Workers', service: 'workers',
  severity: 'CRITICAL', nist_controls: ['IA-5'], remediation: 'Use secrets.',
};

function mockFetchSequence(responses) {
  let i = 0;
  return mock.method(globalThis, 'fetch', async () => {
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return { ok: r.ok, status: r.status, json: async () => r.body };
  });
}

describe('severity-weighted scoring', () => {
  it('weights CRITICAL failures much heavier than LOW failures', () => {
    const lowFail = computeScore([
      { status: 'PASS', severity: 'CRITICAL' },
      { status: 'FAIL', severity: 'LOW' },
    ]);
    const critFail = computeScore([
      { status: 'FAIL', severity: 'CRITICAL' },
      { status: 'PASS', severity: 'LOW' },
    ]);
    // low fail: earned 10/11 ≈ 91; crit fail: earned 1/11 ≈ 9
    assert.ok(lowFail.score > 80, `expected high score, got ${lowFail.score}`);
    assert.ok(critFail.score < 20, `expected low score, got ${critFail.score}`);
  });

  it('excludes ERROR and NA from the denominator', () => {
    const s = computeScore([
      { status: 'PASS', severity: 'HIGH' },
      { status: 'ERROR', severity: 'CRITICAL' },
      { status: 'NA', severity: 'HIGH' },
    ]);
    assert.equal(s.score, 100);
    assert.equal(isUnscored('ERROR'), true);
  });

  it('WARNING earns half credit and counts toward open_high', () => {
    const s = computeScore([{ status: 'WARNING', severity: 'HIGH' }]);
    assert.equal(s.score, 50);
    assert.equal(s.open_high, 1);
    assert.equal(s.scoring, 'severity_weighted');
  });
});

describe('WAF rulesets evaluator', () => {
  afterEach(() => mock.restoreAll());

  it('PASSes CF-WAF-001 when OWASP ruleset is executed', async () => {
    mockFetchSequence([{
      ok: true, status: 200,
      body: {
        success: true,
        result: {
          rules: [{
            action: 'execute', enabled: true,
            action_parameters: { id: OWASP_MANAGED_RULESET_ID },
            description: 'Execute OWASP',
          }],
        },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const f = await evaluateWAF(WAF1, api, 'a'.repeat(32));
    assert.equal(f.status, 'PASS');
  });

  it('FAILs CF-WAF-002 when managed ruleset is detect-only', async () => {
    mockFetchSequence([{
      ok: true, status: 200,
      body: {
        success: true,
        result: {
          rules: [{
            action: 'execute', enabled: true,
            action_parameters: {
              id: CF_MANAGED_RULESET_ID,
              overrides: { action: 'log' },
            },
          }],
        },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const f = await evaluateWAF(WAF2, api, 'a'.repeat(32));
    assert.equal(f.status, 'FAIL');
    assert.match(f.message, /detect-only|log/i);
  });

  it('FAILs CF-WAF-001 when entrypoint is missing (404)', async () => {
    mockFetchSequence([{
      ok: false, status: 404,
      body: { success: false, errors: [{ message: 'not found' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const f = await evaluateWAF(WAF1, api, 'a'.repeat(32));
    assert.equal(f.status, 'FAIL');
  });
});

describe('Workers evaluator', () => {
  afterEach(() => mock.restoreAll());

  it('FAILs WRK-002 when plain_text binding looks like a secret', async () => {
    const old = new Date();
    old.setDate(old.getDate() - 10);
    mock.method(globalThis, 'fetch', async (url) => {
      const u = String(url);
      if (u.endsWith('/workers/scripts')) {
        return {
          ok: true, status: 200,
          json: async () => ({
            success: true,
            result: [{ id: 'api-worker', modified_on: old.toISOString() }],
          }),
        };
      }
      if (u.includes('/settings')) {
        return {
          ok: true, status: 200,
          json: async () => ({
            success: true,
            result: {
              bindings: [
                { type: 'plain_text', name: 'API_TOKEN', text: 'x' },
                { type: 'plain_text', name: 'PUBLIC_URL', text: 'https://x' },
              ],
            },
          }),
        };
      }
      return { ok: false, status: 404, json: async () => ({ success: false, errors: [] }) };
    });

    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const f = await evaluateWorkers(WRK2, api, 'a'.repeat(32), 'b'.repeat(32));
    assert.equal(f.status, 'FAIL');
    assert.match(f.message, /API_TOKEN/);
  });

  it('PASSes WRK-001 when stale script still has a zone route', async () => {
    const old = new Date();
    old.setDate(old.getDate() - 120);
    mock.method(globalThis, 'fetch', async (url) => {
      const u = String(url);
      if (u.endsWith('/workers/scripts') && u.includes('/accounts/')) {
        return {
          ok: true, status: 200,
          json: async () => ({
            success: true,
            result: [{ id: 'legacy-worker', modified_on: old.toISOString() }],
          }),
        };
      }
      if (u.includes('/workers/routes')) {
        return {
          ok: true, status: 200,
          json: async () => ({
            success: true,
            result: [{ pattern: 'example.com/*', script: 'legacy-worker' }],
          }),
        };
      }
      return { ok: false, status: 404, json: async () => ({ success: false, errors: [] }) };
    });

    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const f = await evaluateWorkers(WRK1, api, 'a'.repeat(32), 'b'.repeat(32));
    assert.equal(f.status, 'PASS');
  });
});
