import yaml from 'js-yaml';
import { CloudflareAPI } from '../utils/cf-api.js';
import { evaluateZoneSetting } from './evaluators/zone-setting.js';
import { evaluateWAF } from './evaluators/waf.js';
import { evaluateDNSSEC } from './evaluators/dnssec.js';
import { evaluateBot } from './evaluators/bot.js';
import { evaluateRateLimit } from './evaluators/rate-limit.js';
import { evaluateAccess } from './evaluators/access.js';
import { evaluateWorkers } from './evaluators/workers.js';
import { evaluatePageShield } from './evaluators/page-shield.js';
import { evaluateLogpush } from './evaluators/logpush.js';

// Baseline is bundled at deploy time — loaded once per isolate lifetime
let _baseline = null;
async function getBaseline(env) {
  if (_baseline) return _baseline;
  // In production, baseline.yaml is served via a static asset binding or embedded.
  // For Workers we embed it as a string via the build step.
  // During local dev we use the BASELINE_YAML env var or the bundled string.
  const raw = env?.BASELINE_YAML ?? BUNDLED_BASELINE;
  _baseline = yaml.load(raw);
  return _baseline;
}

/**
 * Run a zone audit.
 * @param {string} zoneId
 * @param {string} apiToken
 * @param {string|null} accountId  – optional, enables ZT + Worker checks
 * @param {object} env             – Cloudflare Worker env bindings
 * @param {object} [cache]         – optional KV cache helper
 */
export async function runZoneAudit(zoneId, apiToken, accountId, env, cache) {
  const api = new CloudflareAPI(apiToken);

  // Validate zone + token before running checks
  let zone;
  try {
    zone = await api.getZone(zoneId);
  } catch (err) {
    throw new Error(`Invalid zone ID or API token: ${err.message}`);
  }

  const baseline = await getBaseline(env);
  const findings = await Promise.all(
    baseline.map(check => dispatch(check, api, zoneId, accountId, cache))
  );

  return buildReport(zone, findings, accountId);
}

/**
 * Run an account-wide scan across all zones.
 */
export async function runAccountAudit(accountId, apiToken, env, cache) {
  const api = new CloudflareAPI(apiToken);

  let zones;
  try {
    zones = await api.listZones(accountId);
  } catch (err) {
    throw new Error(`Could not list zones: ${err.message}`);
  }

  const results = await Promise.all(
    zones.map(z => runZoneAudit(z.id, apiToken, accountId, env, cache).catch(err => ({
      zone_id: z.id,
      zone_name: z.name,
      error: err.message,
    })))
  );

  return { account_id: accountId, zones: results };
}

// ── Dispatcher ─────────────────────────────────────────────────────────────────

async function dispatch(check, api, zoneId, accountId, _cache) {
  try {
    switch (check.service) {
      case 'zone-setting': return evaluateZoneSetting(check, api, zoneId);
      case 'waf':          return evaluateWAF(check, api, zoneId);
      case 'dnssec':       return evaluateDNSSEC(check, api, zoneId);
      case 'bot':          return evaluateBot(check, api, zoneId);
      case 'rate-limit':   return evaluateRateLimit(check, api, zoneId);
      case 'access':       return evaluateAccess(check, api, zoneId, accountId);
      case 'workers':      return evaluateWorkers(check, api, zoneId, accountId);
      case 'page-shield':  return evaluatePageShield(check, api, zoneId);
      case 'logpush':      return evaluateLogpush(check, api, zoneId, accountId);
      default:
        return naResult(check, `Service "${check.service}" not implemented.`);
    }
  } catch (err) {
    return naResult(check, `Evaluator threw an unexpected error: ${err.message}`);
  }
}

function naResult(check, message) {
  return {
    id: check.id, name: check.name, category: check.category,
    service: check.service, severity: check.severity,
    nist_controls: check.nist_controls ?? [],
    cis_controls: check.cis_controls ?? [],
    status: 'NA', message, remediation: null,
  };
}

// ── Report builder ─────────────────────────────────────────────────────────────

function buildReport(zone, findings, accountId) {
  const passed  = findings.filter(f => f.status === 'PASS').length;
  const failed  = findings.filter(f => f.status === 'FAIL').length;
  const warnings = findings.filter(f => f.status === 'WARNING').length;
  const na      = findings.filter(f => f.status === 'NA').length;
  const scored  = findings.filter(f => f.status !== 'NA').length;
  const score   = scored > 0 ? Math.round((passed / scored) * 100) : 0;

  return {
    timestamp: new Date().toISOString(),
    zone_id: zone.id,
    zone_name: zone.name,
    account_id: accountId ?? zone.account?.id ?? null,
    summary: { total_checks: findings.length, passed, failed, warnings, na, score },
    findings,
  };
}

// ── Bundled baseline (fallback when BASELINE_YAML env var not set) ─────────────
// This string is replaced at build time by the contents of baseline.yaml.
// For local wrangler dev it reads from the env var set in .dev.vars.
const BUNDLED_BASELINE = `
- id: CF-SSL-001
  name: SSL/TLS Mode is Full (Strict)
  category: SSL/TLS
  service: zone-setting
  setting: ssl
  expect: strict
  severity: HIGH
  nist_controls: [SC-8, SC-12, SC-13]
  remediation: Set SSL/TLS encryption to "Full (Strict)" in SSL/TLS settings.

- id: CF-TLS-001
  name: Minimum TLS Version is 1.2 or higher
  category: SSL/TLS
  service: zone-setting
  setting: min_tls_version
  expect_min_tls: "1.2"
  severity: HIGH
  nist_controls: [SC-8, SC-13]
  remediation: Set Minimum TLS Version to 1.2 in SSL/TLS > Edge Certificates.

- id: CF-TLS-002
  name: TLS 1.3 is enabled
  category: SSL/TLS
  service: zone-setting
  setting: tls_1_3
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-8, SC-13]
  remediation: Enable TLS 1.3 in SSL/TLS > Edge Certificates.

- id: CF-HTTPS-001
  name: Always Use HTTPS is enabled
  category: SSL/TLS
  service: zone-setting
  setting: always_use_https
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-8]
  remediation: Enable "Always Use HTTPS" in SSL/TLS > Edge Certificates.

- id: CF-TLS-003
  name: Opportunistic Encryption is enabled
  category: SSL/TLS
  service: zone-setting
  setting: opportunistic_encryption
  expect: "on"
  severity: LOW
  nist_controls: [SC-8]
  remediation: Enable Opportunistic Encryption in SSL/TLS > Edge Certificates.

- id: CF-SEC-001
  name: Browser Integrity Check is enabled
  category: Security
  service: zone-setting
  setting: browser_check
  expect: "on"
  severity: MEDIUM
  nist_controls: [SI-3, SI-4]
  remediation: Enable Browser Integrity Check in Security > Settings.

- id: CF-SEC-002
  name: Security Level is Medium or higher
  category: Security
  service: zone-setting
  setting: security_level
  expect_one_of: [medium, high, under_attack]
  severity: MEDIUM
  nist_controls: [SC-7, SI-4]
  remediation: Set Security Level to Medium or higher in Security > Settings.

- id: CF-SEC-003
  name: Email Obfuscation is enabled
  category: Security
  service: zone-setting
  setting: email_obfuscation
  expect: "on"
  severity: LOW
  nist_controls: [SI-19]
  remediation: Enable Email Obfuscation in Scrape Shield settings.

- id: CF-WAF-001
  name: OWASP Core Rule Set is enabled
  category: WAF
  service: waf
  severity: CRITICAL
  nist_controls: [SI-3, SC-7]
  remediation: Enable the OWASP Core Rule Set with Medium or High sensitivity in Security > WAF.

- id: CF-WAF-002
  name: WAF is in block mode (not detect-only)
  category: WAF
  service: waf
  severity: HIGH
  nist_controls: [SI-3, SC-7]
  remediation: Set WAF package action to Block rather than Simulate/Log.

- id: CF-DNS-001
  name: DNSSEC is enabled and active
  category: DNS
  service: dnssec
  severity: HIGH
  nist_controls: [SC-8, SC-20]
  remediation: Enable DNSSEC in DNS settings and add the DS record to your registrar.

- id: CF-BOT-001
  name: Bot Fight Mode or Bot Management is enabled
  category: Bot Protection
  service: bot
  severity: HIGH
  nist_controls: [SC-5, SI-4]
  remediation: Enable Bot Fight Mode (free) or Bot Management (enterprise) in Security > Bots.

- id: CF-RL-001
  name: At least one rate limiting rule is configured
  category: Rate Limiting
  service: rate-limit
  severity: MEDIUM
  nist_controls: [SC-5, SI-4]
  remediation: Configure rate limiting rules in Security > WAF > Rate Limiting Rules.

- id: ZT-001
  name: MFA is enforced on all Access applications
  category: Zero Trust
  service: access
  severity: HIGH
  nist_controls: [IA-2, AC-3]
  remediation: Add an MFA requirement to all Access application policies.

- id: ZT-002
  name: At least one identity provider is configured
  category: Zero Trust
  service: access
  severity: HIGH
  nist_controls: [IA-2, IA-8]
  remediation: Configure an identity provider in Zero Trust > Settings > Authentication.

- id: WRK-001
  name: No zombie workers detected
  category: Workers
  service: workers
  severity: HIGH
  nist_controls: [CM-2, CM-8]
  remediation: Remove or document workers that have not been updated in 90+ days and have no routes.

- id: WRK-002
  name: No workers with plain-text secret-like env vars
  category: Workers
  service: workers
  severity: CRITICAL
  nist_controls: [IA-5, SC-12]
  remediation: Use Secret bindings instead of plain-text env vars for sensitive values.

- id: CF-HSTS-001
  name: HTTP Strict Transport Security (HSTS) is enabled
  category: Transport Security
  service: zone-setting
  setting: security_header
  expect_nested:
    path: strict_transport_security.enabled
    value: "true"
  severity: HIGH
  nist_controls: [SC-8, "SC-8(1)"]
  cis_controls: ["3.10"]
  remediation: Enable HSTS in SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS).

- id: CF-HSTS-002
  name: HSTS max-age is at least 6 months (15768000 seconds)
  category: Transport Security
  service: zone-setting
  setting: security_header
  expect_nested:
    path: strict_transport_security.max_age
    value: "15768000"
  severity: MEDIUM
  nist_controls: [SC-8, "SC-8(1)"]
  cis_controls: ["3.10"]
  remediation: Set HSTS max-age to at least 15768000 seconds (6 months) to qualify for browser preload lists.

- id: CF-HTTPS-002
  name: Automatic HTTPS Rewrites is enabled
  category: Transport Security
  service: zone-setting
  setting: automatic_https_rewrites
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-8]
  cis_controls: ["3.10"]
  remediation: Enable Automatic HTTPS Rewrites in SSL/TLS > Edge Certificates to fix mixed content.

- id: CF-ORIGIN-001
  name: Authenticated Origin Pulls (mTLS) is enabled
  category: Transport Security
  service: zone-setting
  setting: tls_client_auth
  expect: "on"
  severity: HIGH
  nist_controls: [SC-8, SC-17, MA-9]
  cis_controls: ["3.10"]
  remediation: Enable Authenticated Origin Pulls in SSL/TLS > Origin Server to verify requests from Cloudflare to your origin.

- id: CF-HTTP-001
  name: HTTP/2 is enabled
  category: Protocol Hygiene
  service: zone-setting
  setting: http2
  expect: "on"
  severity: LOW
  nist_controls: [SC-8, CM-6]
  cis_controls: ["12.6"]
  remediation: Enable HTTP/2 in Speed > Optimization > Protocol Optimization.

- id: CF-HTTP-002
  name: HTTP/3 (QUIC) is enabled
  category: Protocol Hygiene
  service: zone-setting
  setting: http3
  expect: "on"
  severity: LOW
  nist_controls: [SC-8, CM-6]
  cis_controls: ["12.6"]
  remediation: Enable HTTP/3 in Speed > Optimization > Protocol Optimization to reduce connection latency.

- id: CF-IPV6-001
  name: IPv6 compatibility is enabled
  category: Protocol Hygiene
  service: zone-setting
  setting: ipv6
  expect: "on"
  severity: LOW
  nist_controls: [CM-6, CM-7]
  cis_controls: ["12.6"]
  remediation: Enable IPv6 compatibility in Network settings.

- id: CF-LOG-001
  name: At least one active Logpush job is configured
  category: Observability
  service: logpush
  severity: HIGH
  nist_controls: [AU-2, AU-9, SI-4]
  cis_controls: ["6.1", "8.2"]
  remediation: Configure a Logpush job in Analytics > Logpush to export HTTP request logs to your SIEM or storage.

- id: CF-PS-001
  name: Page Shield is enabled
  category: Observability
  service: page-shield
  severity: HIGH
  nist_controls: [SI-3, SI-4, SA-9]
  cis_controls: ["8.2"]
  remediation: Enable Page Shield in Security > Page Shield to monitor client-side scripts for supply chain attacks.

- id: CF-PS-002
  name: Page Shield policy enforcement is active (not monitor-only)
  category: Observability
  service: page-shield
  severity: MEDIUM
  nist_controls: [SI-3, SA-9]
  cis_controls: ["8.2"]
  remediation: Enable Page Shield policy enforcement in Security > Page Shield > Policies to block unapproved scripts.

- id: CF-SEC-004
  name: Hotlink Protection is enabled
  category: Content Security
  service: zone-setting
  setting: hotlink_protection
  expect: "on"
  severity: LOW
  nist_controls: [SI-8, AC-3]
  cis_controls: ["9.3"]
  remediation: Enable Hotlink Protection in Scrape Shield to prevent unauthorized embedding of your content.

- id: CF-CERT-001
  name: Certificate Transparency Monitoring is enabled
  category: Transport Security
  service: zone-setting
  setting: certificate_transparency_monitoring
  expect: "on"
  severity: MEDIUM
  nist_controls: [SC-17, SI-4]
  cis_controls: ["3.10"]
  remediation: Enable Certificate Transparency Monitoring in SSL/TLS > Edge Certificates to receive alerts for unauthorized certificates.
`;
