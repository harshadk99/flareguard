/**
 * Authenticated Origin Pulls (mTLS from Cloudflare's edge to the origin).
 * This control only makes sense when there is a customer-controlled origin to
 * authenticate to. When the zone is served entirely by Cloudflare Pages/Workers
 * there is no origin hop, so a disabled setting is N/A, not a FAIL.
 *
 * Fail-safe by design — a real missing-AOP finding must never be hidden:
 *   - setting "on"                         → PASS
 *   - setting off, DNS unreadable          → FAIL (can't prove there's no origin)
 *   - setting off, no proxied content recs → FAIL (can't prove it's Pages-only)
 *   - setting off, a non-Cloudflare origin → FAIL (there IS an origin)
 *   - setting off, every proxied origin is Cloudflare-owned → NA
 */
import { pass, fail, na, unevaluable } from '../finding.js';

// Cloudflare-owned CNAME targets (Pages, Workers, R2, agents gateway, etc.).
const CF_ORIGIN_SUFFIXES = ['.pages.dev', '.workers.dev', '.r2.dev', '.r2.cloudflarestorage.com', '.cloudflare.com'];
// Non-routable placeholders used when a hostname is served by a Worker, with no
// real origin behind it: RFC 5737 TEST-NET v4 ranges and the RFC 6666 v6 discard prefix.
const PLACEHOLDER_V4_PREFIXES = ['192.0.2.', '198.51.100.', '203.0.113.'];
const CONTENT_TYPES = new Set(['A', 'AAAA', 'CNAME']);

function isCloudflareOwned(target) {
  const t = String(target || '').toLowerCase().replace(/\.$/, '');
  return CF_ORIGIN_SUFFIXES.some(suffix => t.endsWith(suffix));
}

/** True when a proxied record resolves to no reachable customer origin (Cloudflare infra or a placeholder). */
function hasNoCustomerOrigin(r) {
  if (r.type === 'CNAME') return isCloudflareOwned(r.content);
  const c = String(r.content || '').toLowerCase();
  if (r.type === 'A') return PLACEHOLDER_V4_PREFIXES.some(p => c.startsWith(p));
  if (r.type === 'AAAA') return c.startsWith('100::'); // 100::/64 discard
  return false;
}

export async function evaluateOriginPull(check, api, zoneId) {
  let value;
  try {
    value = (await api.getZoneSetting(zoneId, check.setting)).value;
  } catch (err) {
    return unevaluable(check, err);
  }

  if (String(value) === 'on') return pass(check, `${check.setting} is "on"`);

  const fail_off = () => fail(check, `${check.setting} is "${value}", expected "on"`);

  // AOP is off — only excuse it if we can prove there's no origin to authenticate to.
  let records;
  try {
    records = await api.listDNSRecords(zoneId);
  } catch {
    return fail_off(); // can't inspect origins → surface the finding
  }

  const content = (records || []).filter(r => r.proxied && CONTENT_TYPES.has(r.type));
  if (content.length === 0) return fail_off(); // nothing proven

  // Only excuse AOP when every proxied content record provably has no customer
  // origin (Cloudflare Pages/Workers/infra, or a non-routable placeholder).
  if (!content.every(hasNoCustomerOrigin)) return fail_off();

  return na(check,
    `No customer origin to authenticate — ${content.length} proxied record(s), all served by Cloudflare ` +
    `(Pages/Workers/infra or placeholder). Authenticated Origin Pulls does not apply; excluded from scoring.`);
}
