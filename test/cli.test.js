/**
 * CLI gating logic: the pure helpers that decide the process exit code so
 * `flareguard audit` can act as a CI gate. No network — exercises the
 * severity filter and the exit-code decision directly.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { openAtOrAbove, decideExit } from '../bin/flareguard.js';

const F = (status, severity) => ({ status, severity, id: `${status}-${severity}` });
const zoneReport = (score, findings) => ({ summary: { score }, findings });

describe('openAtOrAbove', () => {
  const findings = [
    F('FAIL', 'CRITICAL'), F('FAIL', 'LOW'), F('WARNING', 'MEDIUM'),
    F('PASS', 'HIGH'), F('NA', 'CRITICAL'), F('ERROR', 'HIGH'),
  ];

  it('counts only open FAIL/WARNING at or above the threshold', () => {
    assert.equal(openAtOrAbove(findings, 'MEDIUM').length, 2); // CRITICAL fail + MEDIUM warn
    assert.equal(openAtOrAbove(findings, 'CRITICAL').length, 1); // only the CRITICAL fail
    assert.equal(openAtOrAbove(findings, 'LOW').length, 3); // + the LOW fail
  });

  it('never counts PASS, NA, or ERROR as open', () => {
    const only = [F('PASS', 'CRITICAL'), F('NA', 'CRITICAL'), F('ERROR', 'CRITICAL')];
    assert.equal(openAtOrAbove(only, 'LOW').length, 0);
  });

  it('is safe on missing findings', () => {
    assert.equal(openAtOrAbove(undefined, 'LOW').length, 0);
  });
});

describe('decideExit (zone report)', () => {
  const report = zoneReport(85, [F('FAIL', 'HIGH'), F('FAIL', 'MEDIUM'), F('PASS', 'HIGH')]);

  it('returns 0 with no gates', () => {
    assert.equal(decideExit(report, {}), 0);
  });

  it('fails the --fail-on gate when an open finding meets the threshold', () => {
    assert.equal(decideExit(report, { failOn: 'high' }), 1);
    assert.equal(decideExit(report, { failOn: 'medium' }), 1);
  });

  it('passes the --fail-on gate when nothing meets the threshold', () => {
    assert.equal(decideExit(report, { failOn: 'critical' }), 0);
  });

  it('applies the --min-score gate independently', () => {
    assert.equal(decideExit(report, { minScore: 90 }), 1); // 85 < 90
    assert.equal(decideExit(report, { minScore: 80 }), 0); // 85 >= 80
  });

  it('returns 2 when the zone errored out', () => {
    assert.equal(decideExit({ error: 'bad token' }, { failOn: 'high' }), 2);
  });
});

describe('decideExit (account report)', () => {
  it('fails if ANY zone trips the gate', () => {
    const acct = { zones: [
      zoneReport(95, [F('PASS', 'HIGH')]),
      zoneReport(40, [F('FAIL', 'CRITICAL')]),
    ] };
    assert.equal(decideExit(acct, { failOn: 'high' }), 1);
    assert.equal(decideExit(acct, { minScore: 50 }), 1); // second zone is 40
  });

  it('passes when every zone is clean', () => {
    const acct = { zones: [zoneReport(95, [F('PASS', 'HIGH')]), zoneReport(88, [])] };
    assert.equal(decideExit(acct, { failOn: 'high', minScore: 80 }), 0);
  });

  it('propagates a per-zone error as exit 2', () => {
    const acct = { zones: [zoneReport(95, []), { error: 'no access' }] };
    assert.equal(decideExit(acct, {}), 2);
  });
});
