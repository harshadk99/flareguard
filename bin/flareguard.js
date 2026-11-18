#!/usr/bin/env node
/**
 * FlareGuard CLI — run the Cloudflare control-plane security audit from your
 * terminal or CI, using the same baseline + engine as the Worker.
 *
 *   CLOUDFLARE_API_TOKEN=<token> npx @harshad99/flareguard audit --zone <zone-id>
 *   CLOUDFLARE_API_TOKEN=<token> npx @harshad99/flareguard audit --account <account-id>   # all zones
 *
 * Privacy: the token and IDs live only in memory for the duration of the run.
 * Nothing is stored or transmitted anywhere except Cloudflare's own API, and the
 * report prints to your terminal (IDs are shown only as one-way hashes).
 */
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { runZoneAudit, runAccountAudit } from '../src/audit/engine.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const FAIL_ON_SEV = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' };

function version() {
  try { return JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')).version; }
  catch { return '0.0.0'; }
}

const HELP = () => `flareguard ${version()} — Cloudflare control-plane security audit

USAGE
  flareguard audit --zone <zone-id> [--account <account-id>] [options]
  flareguard audit --account <account-id> [options]      # every zone in the account

AUTH
  CLOUDFLARE_API_TOKEN   API token with read access (required; or --token)
  CLOUDFLARE_ACCOUNT_ID  default account (optional; or --account)

OPTIONS
  --zone <id>        Zone to audit
  --account <id>     Account id. With --zone it also runs Zero Trust + Worker checks.
                     Without --zone it audits every zone in the account.
  --token <token>    API token (prefer the CLOUDFLARE_API_TOKEN env var)
  --json             Print the raw JSON report instead of the summary
  --fail-on <sev>    Exit 1 if any open finding is >= sev: low|medium|high|critical
  --min-score <n>    Exit 1 if the score is below n (0-100)
  -h, --help         Show this help
  -v, --version      Show version

EXIT CODES
  0  ok (and any gate passed)   1  gate failed   2  usage / auth / runtime error`;

// ── pure helpers (exported for tests) ────────────────────────────────────────
export function openAtOrAbove(findings, minSev) {
  const floor = SEV_RANK[minSev] ?? 0;
  return (findings || []).filter(f =>
    (f.status === 'FAIL' || f.status === 'WARNING') && (SEV_RANK[f.severity] ?? 0) >= floor);
}

export function decideExit(report, { failOn, minScore } = {}) {
  const zones = report.zones || [report];
  let code = 0;
  for (const z of zones) {
    if (z.error) return 2;
    if (failOn && openAtOrAbove(z.findings, FAIL_ON_SEV[failOn]).length > 0) code = 1;
    if (minScore != null && (z.summary?.score ?? 100) < minScore) code = 1;
  }
  return code;
}

// ── formatting ───────────────────────────────────────────────────────────────
const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (c, s) => (COLOR ? `\x1b[${c}m${s}\x1b[0m` : String(s));
const bold = s => paint('1', s), dim = s => paint('2', s);
const red = s => paint('31', s), grn = s => paint('32', s), yel = s => paint('33', s);
const gray = s => paint('90', s), mag = s => paint('35', s);

const SYMBOL = { PASS: grn('✓'), FAIL: red('✗'), WARNING: yel('!'), NA: gray('–'), ERROR: gray('?') };
const SEV_PAINT = { CRITICAL: mag, HIGH: red, MEDIUM: yel, LOW: dim, INFO: dim };
const scoreColor = n => (n >= 80 ? grn(n) : n >= 50 ? yel(n) : red(n));

function formatZone(report) {
  if (report.error) return `${red('✗')} ${bold(report.zone_name || 'zone')} — ${red('error:')} ${report.error}`;
  const s = report.summary;
  const out = [''];
  out.push(`${bold('FlareGuard')} ${dim('·')} ${bold(report.zone_name)}`);
  out.push(`Score ${bold(scoreColor(s.score) + '/100')}   ${s.open_critical} open critical, ${s.open_high} open high`);
  out.push(dim(`${s.total_checks} checks · ${s.passed} pass · ${s.failed} fail · ${s.warnings} warn · ${s.na} n/a · ${s.errors} error`));

  const order = { FAIL: 0, WARNING: 1, ERROR: 2 };
  const actionable = report.findings
    .filter(f => f.status in order)
    .sort((a, b) => (order[a.status] - order[b.status]) || ((SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)));

  if (actionable.length) {
    out.push('', bold('Findings'));
    for (const f of actionable) {
      const sev = (SEV_PAINT[f.severity] || dim)(String(f.severity).padEnd(8));
      out.push(`  ${SYMBOL[f.status]} ${sev} ${f.id}  ${f.name}`);
      if (f.message) out.push(`      ${dim(f.message)}`);
      if (f.remediation) out.push(`      ${dim('→ ' + f.remediation)}`);
    }
  } else {
    out.push('', grn('  ✓ no open findings'));
  }

  const na = report.findings.filter(f => f.status === 'NA');
  if (na.length) {
    out.push('', gray(`n/a (${na.length}, excluded from scoring — plan-gated or not applicable):`));
    out.push(gray('  ' + na.map(f => f.id).join(', ')));
  }
  return out.join('\n');
}

function formatAccount(report) {
  const zones = report.zones || [];
  const out = zones.map(formatZone);
  const ok = zones.filter(z => !z.error);
  if (ok.length) {
    const avg = Math.round(ok.reduce((a, z) => a + (z.summary?.score ?? 0), 0) / ok.length);
    out.push('', bold(`${zones.length} zones scanned · average score ${scoreColor(avg)}/100`));
  }
  return out.join('\n');
}

// ── main ──────────────────────────────────────────────────────────────────────
export async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        zone: { type: 'string' },
        account: { type: 'string' },
        token: { type: 'string' },
        json: { type: 'boolean', default: false },
        'fail-on': { type: 'string' },
        'min-score': { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });
  } catch (err) {
    process.stderr.write(red(`error: ${err.message}`) + '\n\n' + HELP() + '\n');
    return 2;
  }

  const { values: v, positionals } = parsed;
  if (v.version) { process.stdout.write(version() + '\n'); return 0; }
  const cmd = positionals[0] || 'audit';
  if (v.help || cmd === 'help') { process.stdout.write(HELP() + '\n'); return 0; }
  if (cmd !== 'audit') { process.stderr.write(red(`unknown command: ${cmd}`) + '\n\n' + HELP() + '\n'); return 2; }

  const token = v.token || process.env.CLOUDFLARE_API_TOKEN;
  const account = v.account || process.env.CLOUDFLARE_ACCOUNT_ID || null;
  const zone = v.zone || null;

  if (!token) { process.stderr.write(red('error: no API token. Set CLOUDFLARE_API_TOKEN or pass --token.') + '\n'); return 2; }
  if (!zone && !account) { process.stderr.write(red('error: specify --zone <id> (or --account <id> to scan every zone).') + '\n'); return 2; }

  const failOn = v['fail-on']?.toLowerCase();
  if (failOn && !FAIL_ON_SEV[failOn]) { process.stderr.write(red('error: --fail-on must be one of low|medium|high|critical') + '\n'); return 2; }
  const minScore = v['min-score'] != null ? Number(v['min-score']) : null;
  if (minScore != null && Number.isNaN(minScore)) { process.stderr.write(red('error: --min-score must be a number') + '\n'); return 2; }

  let report;
  try {
    report = zone
      ? await runZoneAudit(zone, token, account, undefined, undefined, {})
      : await runAccountAudit(account, token, undefined, undefined, {});
  } catch (err) {
    process.stderr.write(red(`audit failed: ${err.message}`) + '\n');
    return 2;
  }

  process.stdout.write((v.json
    ? JSON.stringify(report, null, 2)
    : (report.zones ? formatAccount(report) : formatZone(report))) + '\n');

  return decideExit(report, { failOn, minScore });
}

// Run only when invoked directly (not when imported by tests).
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2))
    .then(code => process.exit(code))
    .catch(err => { process.stderr.write(`fatal: ${err?.stack || err}\n`); process.exit(2); });
}
