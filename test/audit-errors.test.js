/**
 * Tests for unevaluable API-error routing, permission vs auth messaging,
 * rate-limit rulesets port, HSTS min comparison, and export privacy.
 *
 * Run: npm test
 */
import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { CloudflareAPI, CloudflareAPIError, permissionHintForPath } from '../src/utils/cf-api.js';
import { unevaluable, isUnscored, pass, fail } from '../src/audit/finding.js';
import { evaluateZoneSetting } from '../src/audit/evaluators/zone-setting.js';
import { evaluateRateLimit } from '../src/audit/evaluators/rate-limit.js';
import { evaluateDNSSEC } from '../src/audit/evaluators/dnssec.js';
import { evaluateLogpush } from '../src/audit/evaluators/logpush.js';
import { hashId } from '../src/utils/privacy.js';

const CHECK = {
  id: 'CF-CERT-001',
  name: 'Certificate Transparency Monitoring is enabled',
  category: 'Transport Security',
  service: 'zone-setting',
  setting: 'certificate_transparency_monitoring',
  expect: 'on',
  severity: 'MEDIUM',
  nist_controls: ['SC-17'],
  cis_controls: ['3.10'],
  remediation: 'Enable CT monitoring.',
};

const HSTS_CHECK = {
  id: 'CF-HSTS-002',
  name: 'HSTS max-age is at least 6 months (15552000 seconds)',
  category: 'Transport Security',
  service: 'zone-setting',
  setting: 'security_header',
  expect_nested: { path: 'strict_transport_security.max_age', min: 15552000 },
  severity: 'MEDIUM',
  nist_controls: ['SC-8'],
  remediation: 'Set HSTS max-age to at least 15552000 seconds (180 days / 6 months).',
};

const RL_CHECK = {
  id: 'CF-RL-001',
  name: 'At least one rate limiting rule is configured',
  category: 'Rate Limiting',
  service: 'rate-limit',
  severity: 'MEDIUM',
  nist_controls: ['SC-5'],
  remediation: 'Configure rate limiting rules.',
};

const LOG_CHECK = {
  id: 'CF-LOG-001',
  name: 'At least one active Logpush job is configured',
  category: 'Observability',
  service: 'logpush',
  severity: 'HIGH',
  nist_controls: ['AU-2'],
  remediation: 'Configure Logpush.',
};

const DNS_CHECK = {
  id: 'CF-DNS-001',
  name: 'DNSSEC is enabled and active',
  category: 'DNS',
  service: 'dnssec',
  severity: 'HIGH',
  nist_controls: ['SC-8'],
  remediation: 'Enable DNSSEC.',
};

function mockFetchSequence(responses) {
  let i = 0;
  return mock.method(globalThis, 'fetch', async () => {
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return {
      ok: r.ok,
      status: r.status,
      json: async () => r.body,
    };
  });
}

describe('CloudflareAPIError classification', () => {
  it('classifies 401 / Authentication error as auth', () => {
    const err = new CloudflareAPIError({
      path: '/zones/x/logpush/jobs',
      status: 401,
      code: 10000,
      apiMessage: 'Authentication error',
    });
    assert.equal(err.kind, 'auth');
  });

  it('classifies 403 as permission', () => {
    const err = new CloudflareAPIError({
      path: '/zones/x/logpush/jobs',
      status: 403,
      code: 9109,
      apiMessage: 'Unauthorized to access requested resource',
    });
    assert.equal(err.kind, 'permission');
  });

  it('classifies 410 as gone', () => {
    const err = new CloudflareAPIError({
      path: '/zones/x/rate_limits',
      status: 410,
      apiMessage: 'Gone',
    });
    assert.equal(err.kind, 'gone');
  });

  it('maps logpush path to Logs Read hint', () => {
    assert.match(permissionHintForPath('/zones/abc/logpush/jobs'), /Logs Read/);
  });
});

describe('unevaluable — single ERROR path', () => {
  it('permission errors name the missing token permission', () => {
    const err = new CloudflareAPIError({
      path: '/zones/abc/logpush/jobs',
      status: 403,
      code: 9109,
      apiMessage: 'Unauthorized to access requested resource',
    });
    const finding = unevaluable(LOG_CHECK, err);
    assert.equal(finding.status, 'ERROR');
    assert.match(finding.message, /Token lacks permission/);
    assert.match(finding.message, /Logs Read/);
    assert.equal(isUnscored(finding.status), true);
  });

  it('auth errors do not claim a missing permission', () => {
    const err = new CloudflareAPIError({
      path: '/zones/abc/logpush/jobs',
      status: 401,
      code: 10000,
      apiMessage: 'Authentication error',
    });
    const finding = unevaluable(LOG_CHECK, err);
    assert.equal(finding.status, 'ERROR');
    assert.match(finding.message, /Authentication failed/);
    assert.doesNotMatch(finding.message, /Token lacks permission/);
  });

  it('generic API failures still return ERROR (not FAIL)', () => {
    const err = new CloudflareAPIError({
      path: '/zones/abc/settings/certificate_transparency_monitoring',
      status: 400,
      apiMessage: 'Undefined zone setting: certificate_transparency_monitoring',
    });
    const finding = unevaluable(CHECK, err);
    assert.equal(finding.status, 'ERROR');
    assert.equal(finding.remediation, null);
  });
});

describe('CF-CERT-001 / zone-setting error path', () => {
  afterEach(() => mock.restoreAll());

  it('returns ERROR (not FAIL) when setting cannot be read', async () => {
    mockFetchSequence([{
      ok: false,
      status: 400,
      body: { success: false, errors: [{ message: 'Undefined zone setting: certificate_transparency_monitoring' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'ERROR');
    assert.doesNotMatch(finding.status, /FAIL/);
  });

  it('still FAILs when the setting is readable but wrong', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: { success: true, result: { value: 'off' } },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'FAIL');
  });

  it('PASSes when the setting matches', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: { success: true, result: { value: 'on' } },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'PASS');
  });
});

describe('CF-DNS-001 error path', () => {
  afterEach(() => mock.restoreAll());

  it('returns ERROR (not FAIL) on API failure', async () => {
    mockFetchSequence([{
      ok: false,
      status: 403,
      body: { success: false, errors: [{ code: 9109, message: 'Unauthorized to access requested resource' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateDNSSEC(DNS_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'ERROR');
    assert.match(finding.message, /Token lacks permission|DNS Read/);
  });
});

describe('CF-LOG-001 permission vs auth', () => {
  afterEach(() => mock.restoreAll());

  it('surfaces missing Logs Read on 403', async () => {
    mockFetchSequence([{
      ok: false,
      status: 403,
      body: { success: false, errors: [{ code: 9109, message: 'Unauthorized to access requested resource' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateLogpush(LOG_CHECK, api, 'a'.repeat(32), null);
    assert.equal(finding.status, 'ERROR');
    assert.match(finding.message, /Token lacks permission/);
    assert.match(finding.message, /Logs Read/);
  });

  it('surfaces authentication failure on 401', async () => {
    mockFetchSequence([{
      ok: false,
      status: 401,
      body: { success: false, errors: [{ code: 10000, message: 'Authentication error' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateLogpush(LOG_CHECK, api, 'a'.repeat(32), null);
    assert.equal(finding.status, 'ERROR');
    assert.match(finding.message, /Authentication failed/);
  });
});

describe('CF-RL-001 rulesets API', () => {
  afterEach(() => mock.restoreAll());

  it('PASSes when http_ratelimit entrypoint has enabled rules', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: {
        success: true,
        result: {
          id: 'rs1',
          rules: [
            { id: 'r1', enabled: true, action: 'block', ratelimit: { period: 60, requests_per_period: 100 } },
          ],
        },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateRateLimit(RL_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'PASS');
    assert.match(finding.message, /http_ratelimit/);
  });

  it('FAILs when entrypoint is missing (404) — no rules configured', async () => {
    mockFetchSequence([{
      ok: false,
      status: 404,
      body: { success: false, errors: [{ message: 'Could not find ruleset entrypoint' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateRateLimit(RL_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'FAIL');
  });

  it('returns ERROR (not FAIL) on permission errors', async () => {
    mockFetchSequence([{
      ok: false,
      status: 403,
      body: { success: false, errors: [{ code: 9109, message: 'Unauthorized to access requested resource' }] },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateRateLimit(RL_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'ERROR');
  });
});

describe('CF-HSTS-002 six-month floor', () => {
  afterEach(() => mock.restoreAll());

  it('FAILs when max_age is below 6 months (e.g. 90 days)', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: {
        success: true,
        result: { value: { strict_transport_security: { enabled: true, max_age: 7776000 } } },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(HSTS_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'FAIL');
    assert.match(finding.message, /7776000/);
  });

  it('PASSes when max_age is exactly 6 months (15552000)', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: {
        success: true,
        result: { value: { strict_transport_security: { enabled: true, max_age: 15552000 } } },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(HSTS_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'PASS');
  });

  it('PASSes values above the six-month floor (e.g. 1 year)', async () => {
    mockFetchSequence([{
      ok: true,
      status: 200,
      body: {
        success: true,
        result: { value: { strict_transport_security: { enabled: true, max_age: 31536000 } } },
      },
    }]);
    const api = new CloudflareAPI('test-token-abcdefghijklmnopqrstuvwxyz');
    const finding = await evaluateZoneSetting(HSTS_CHECK, api, 'a'.repeat(32));
    assert.equal(finding.status, 'PASS');
  });
});

describe('scoring exclusion + export privacy helpers', () => {
  it('ERROR and NA are unscored; PASS/FAIL/WARNING are scored', () => {
    assert.equal(isUnscored('ERROR'), true);
    assert.equal(isUnscored('NA'), true);
    assert.equal(isUnscored('PASS'), false);
    assert.equal(isUnscored('FAIL'), false);
    assert.equal(isUnscored('WARNING'), false);
  });

  it('hashId is deterministic and 32 hex chars', async () => {
    const zoneId = 'a'.repeat(32);
    const h1 = await hashId(zoneId);
    const h2 = await hashId(zoneId);
    assert.equal(h1, h2);
    assert.match(h1, /^[a-f0-9]{32}$/);
    assert.notEqual(h1, zoneId);
  });

  it('pass/fail helpers preserve genuine scoring semantics', () => {
    assert.equal(pass(CHECK, 'ok').status, 'PASS');
    assert.equal(fail(CHECK, 'bad').status, 'FAIL');
    assert.ok(fail(CHECK, 'bad').remediation);
  });
});

describe('report privacy defaults (buildReport via dynamic import)', () => {
  let fetchMock;

  beforeEach(() => {
    // Minimal zone + one setting that PASSes so buildReport runs end-to-end
    fetchMock = mock.method(globalThis, 'fetch', async (url) => {
      const u = String(url);
      if (/\/zones\/[a-f0-9]{32}$/.test(u)) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result: { id: 'a'.repeat(32), name: 'example.com', account: { id: 'b'.repeat(32) } },
          }),
        };
      }
      // All other baseline API calls fail → ERROR (unscored)
      return {
        ok: false,
        status: 403,
        json: async () => ({
          success: false,
          errors: [{ code: 9109, message: 'Unauthorized to access requested resource' }],
        }),
      };
    });
  });

  afterEach(() => {
    fetchMock?.mock?.restore?.();
    mock.restoreAll();
  });

  it('omits plaintext zone_id/account_id by default and includes hashes', async () => {
    const { runZoneAudit } = await import('../src/audit/engine.js');
    const report = await runZoneAudit(
      'a'.repeat(32),
      'test-token-abcdefghijklmnopqrstuvwxyz',
      'b'.repeat(32),
      { BASELINE_YAML: `- id: CF-CERT-001
  name: Certificate Transparency Monitoring is enabled
  category: Transport Security
  service: zone-setting
  setting: certificate_transparency_monitoring
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-17]
  remediation: Enable CT.
` },
      null,
      {}
    );

    assert.equal(report.zone_id, undefined);
    assert.equal(report.account_id, undefined);
    assert.match(report.zone_id_hash, /^[a-f0-9]{32}$/);
    assert.match(report.account_id_hash, /^[a-f0-9]{32}$/);
    assert.equal(report.zone_name, 'example.com');
    // CERT-001 is ERROR (403) — must not count as FAIL
    assert.equal(report.findings[0].status, 'ERROR');
    assert.equal(report.summary.errors, 1);
    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.score, 0); // no scored checks
  });

  it('includes plaintext IDs when includeRawIds is true', async () => {
    // Reset module-level baseline cache by importing fresh via cache-bust is hard;
    // engine caches baseline in _baseline — clear by reusing same tiny baseline.
    const { runZoneAudit } = await import('../src/audit/engine.js');
    const report = await runZoneAudit(
      'a'.repeat(32),
      'test-token-abcdefghijklmnopqrstuvwxyz',
      'b'.repeat(32),
      { BASELINE_YAML: `- id: CF-CERT-001
  name: Certificate Transparency Monitoring is enabled
  category: Transport Security
  service: zone-setting
  setting: certificate_transparency_monitoring
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-17]
  remediation: Enable CT.
` },
      null,
      { includeRawIds: true }
    );

    assert.equal(report.zone_id, 'a'.repeat(32));
    assert.equal(report.account_id, 'b'.repeat(32));
    assert.ok(report.zone_id_hash);
  });
});
