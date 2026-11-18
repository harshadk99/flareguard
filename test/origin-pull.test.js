/**
 * CF-ORIGIN-001 context-aware Authenticated Origin Pulls evaluator.
 * It may only downgrade to NA on positive proof of a Cloudflare-only origin;
 * every uncertain case must stay a FAIL so a real missing-AOP finding is kept.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { evaluateOriginPull } from '../src/audit/evaluators/origin-pull.js';

const CHECK = { id: 'CF-ORIGIN-001', name: 'AOP', setting: 'tls_client_auth', severity: 'HIGH' };

function fakeApi({ setting = 'off', records = [], settingThrows = false, dnsThrows = false } = {}) {
  return {
    async getZoneSetting() { if (settingThrows) throw new Error('boom'); return { value: setting }; },
    async listDNSRecords() { if (dnsThrows) throw new Error('permission'); return records; },
  };
}
const rec = (type, content, proxied = true) => ({ type, content, proxied });

describe('origin-pull (CF-ORIGIN-001)', () => {
  it('PASSes when AOP is on', async () => {
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'on' }), 'z');
    assert.equal(f.status, 'PASS');
  });

  it('is NA when off and every proxied record is a Cloudflare-owned CNAME', async () => {
    const records = [rec('CNAME', 'my-site.pages.dev'), rec('CNAME', 'www.my-site.pages.dev')];
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', records }), 'z');
    assert.equal(f.status, 'NA');
    assert.match(f.message, /No customer origin/);
  });

  it('FAILs when off and a real routable origin IP is present', async () => {
    const records = [rec('CNAME', 'my-site.pages.dev'), rec('A', '93.184.216.34')];
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', records }), 'z');
    assert.equal(f.status, 'FAIL');
  });

  it('is NA for Cloudflare infra CNAMEs and non-routable placeholders (real zone shape)', async () => {
    const records = [
      rec('CNAME', 'personal-site.pages.dev'),
      rec('CNAME', 'gateway.agents.cloudflare.com'),
      rec('AAAA', '100::'),            // Worker-served, RFC 6666 discard
      rec('A', '192.0.2.1'),           // RFC 5737 TEST-NET placeholder
    ];
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', records }), 'z');
    assert.equal(f.status, 'NA');
  });

  it('FAILs when off and a CNAME points to a non-Cloudflare host', async () => {
    const records = [rec('CNAME', 'origin.example.com')];
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', records }), 'z');
    assert.equal(f.status, 'FAIL');
  });

  it('FAILs when off and there are no proxied content records to prove Pages-only', async () => {
    const records = [rec('CNAME', 'my-site.pages.dev', false)]; // unproxied
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', records }), 'z');
    assert.equal(f.status, 'FAIL');
  });

  it('FAILs (never hides) when DNS cannot be read', async () => {
    const f = await evaluateOriginPull(CHECK, fakeApi({ setting: 'off', dnsThrows: true }), 'z');
    assert.equal(f.status, 'FAIL');
  });

  it('is unevaluable (ERROR) when the setting itself cannot be read', async () => {
    const f = await evaluateOriginPull(CHECK, fakeApi({ settingThrows: true }), 'z');
    assert.equal(f.status, 'ERROR');
  });
});
