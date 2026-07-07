# Contributing to FlareGuard

Thank you for your interest in contributing. FlareGuard is an open-source CSPM tool for the Cloudflare ecosystem — contributions that improve security coverage, compliance accuracy, or developer experience are welcome.

---

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [The Fastest Contribution: Adding a Security Check](#the-fastest-contribution-adding-a-security-check)
- [Adding a New Evaluator](#adding-a-new-evaluator)
- [Updating Compliance Mappings](#updating-compliance-mappings)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Security Disclosures](#security-disclosures)

---

## Ways to Contribute

| Type | Effort | Where to start |
|------|--------|----------------|
| Add a zone-setting check | ~10 min | Edit `baseline.yaml` only — no code |
| Add a new evaluator | ~1–2 hr | `src/audit/evaluators/` + `engine.js` |
| Update a compliance mapping | ~15 min | `mappings/nist-800-53-r5.yaml` or `mappings/cis-v8.yaml` |
| Fix a bug in an evaluator | ~30 min | `src/audit/evaluators/<service>.js` |
| Improve the UI | varies | `src/ui/landing.js` or `src/ui/dashboard.js` |
| Report a false positive / false negative | 5 min | Open a GitHub issue |

---

## The Fastest Contribution: Adding a Security Check

If the check maps to an existing Cloudflare zone setting (the vast majority of cases), **no code is required**. Edit `baseline.yaml` only.

### Step 1 — Find the Cloudflare setting ID

The Cloudflare API exposes zone settings at:
```
GET https://api.cloudflare.com/client/v4/zones/{zone_id}/settings
```

Each setting has an `id` field (e.g. `always_use_https`, `min_tls_version`, `http2`). That's the value you use for `setting:` in the YAML.

### Step 2 — Add the check to `baseline.yaml`

```yaml
- id: CF-XXX-001                        # unique ID, follow the pattern
  name: Descriptive name of the check
  category: SSL/TLS                     # existing category or new one
  service: zone-setting                 # use zone-setting for API-exposed settings
  setting: the_cloudflare_setting_id
  expect: "on"                          # exact match
  # OR:
  expect_one_of: [value1, value2]       # acceptable values
  # OR:
  expect_min_tls: "1.2"                 # for TLS version comparisons
  # OR:
  expect_nested:                        # for object-valued settings (e.g. HSTS)
    path: nested.key.path
    value: "true"
  severity: MEDIUM                      # CRITICAL | HIGH | MEDIUM | LOW | INFO
  nist_controls: [SC-8]                 # NIST SP 800-53 Rev 5 control IDs
  cis_controls: ["3.10"]                # CIS Controls v8 IDs (optional)
  remediation: One sentence telling the user exactly how to fix this in the Cloudflare dashboard.
```

### Step 3 — Update `BUNDLED_BASELINE` in `src/audit/engine.js`

The Worker bundles the baseline as a string for edge deployment. Copy your new check entry to the end of the `BUNDLED_BASELINE` template literal in `engine.js`. This keeps local dev and production in sync.

### Step 4 — Test it

```bash
npm run dev
# Open http://localhost:8787/audit and run an audit
# Verify your new check ID appears in the findings
```

### Check ID conventions

| Prefix | Category |
|--------|----------|
| `CF-SSL-` | SSL/TLS settings |
| `CF-TLS-` | TLS version/protocol |
| `CF-HTTPS-` | HTTPS enforcement |
| `CF-HSTS-` | HSTS headers |
| `CF-ORIGIN-` | Origin security |
| `CF-WAF-` | WAF rules |
| `CF-DNS-` | DNS / DNSSEC |
| `CF-BOT-` | Bot protection |
| `CF-RL-` | Rate limiting |
| `CF-SEC-` | General security settings |
| `CF-LOG-` | Logging / observability |
| `CF-PS-` | Page Shield |
| `CF-HTTP-` | HTTP protocol settings |
| `CF-IPV6-` | IPv6 |
| `CF-CERT-` | Certificate management |
| `ZT-` | Zero Trust / Access |
| `WRK-` | Workers |

---

## Adding a New Evaluator

Use this when the check requires a Cloudflare API call that isn't a simple zone setting lookup — for example, checking Access policies, Logpush jobs, or Page Shield.

### Step 1 — Add the API method to `src/utils/cf-api.js`

```js
getMyNewResource(zoneId) {
  return this.#get(`/zones/${zoneId}/my-resource`);
}
```

### Step 2 — Create `src/audit/evaluators/my-service.js`

```js
export async function evaluateMyService(check, api, zoneId, accountId) {
  let data;
  try {
    data = await api.getMyNewResource(zoneId);
  } catch (e) {
    return result(check, 'NA', `Could not fetch resource: ${e.message}`);
  }

  if (check.id === 'CF-NEW-001') {
    return data?.enabled
      ? result(check, 'PASS', 'Resource is enabled.')
      : result(check, 'FAIL', 'Resource is disabled.', check.remediation);
  }

  return result(check, 'NA', `Check ${check.id} not implemented.`);
}

function result(check, status, message, remediation) {
  return {
    id: check.id, name: check.name, category: check.category,
    service: check.service, severity: check.severity,
    nist_controls: check.nist_controls ?? [],
    cis_controls: check.cis_controls ?? [],
    status, message,
    remediation: (status === 'FAIL' || status === 'WARNING')
      ? (remediation ?? check.remediation)
      : null,
  };
}
```

### Step 3 — Register in `src/audit/engine.js`

```js
// Import
import { evaluateMyService } from './evaluators/my-service.js';

// Add to the dispatcher switch
case 'my-service': finding = await evaluateMyService(check, api, zoneId, accountId); break;
```

### Step 4 — Add checks to `baseline.yaml` using `service: my-service`

---

## Updating Compliance Mappings

Mappings live in `mappings/` and are compiled into `src/utils/mappings.js` for edge runtime use.

### When a control description changes (same version)

Edit the relevant entry in `mappings/nist-800-53-r5.yaml` or `mappings/cis-v8.yaml`, then sync the change to the matching object in `src/utils/mappings.js`.

### When a new framework version is published (e.g. NIST Rev 6)

1. Create `mappings/nist-800-53-r6.yaml` following the existing format
2. Update `mappings/index.yaml`:
   ```yaml
   nist_800_53:
     active: Rev 6
     file: nist-800-53-r6.yaml
   ```
3. Update `NIST_800_53` and `FRAMEWORK_VERSIONS` in `src/utils/mappings.js`
4. Review `baseline.yaml` — only update control IDs if they changed in the new revision

The check-to-control assignments (which Cloudflare setting maps to which NIST control) are intentional interpretations. If you believe a mapping is incorrect, open an issue with a reference to the control definition.

---

## Development Setup

```bash
git clone https://github.com/harshadk99/flareguard.git
cd flareguard
npm install

# Create .dev.vars for local credentials (never commit this file)
cp .dev.vars.example .dev.vars   # or create manually:
cat > .dev.vars << EOF
CF_ZONE_ID=your_zone_id
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
CACHE_TTL_SECONDS=300
ENVIRONMENT=development
EOF

npm run dev
# → http://localhost:8787
```

**Required API token permissions for full local testing:**

- Zone Read
- SSL and Certificates Read
- Firewall Services Read
- DNS Read
- Account Settings Read
- Access: Apps and Policies Read
- Logs Read
- Page Shield Read

---

## Code Style

- **ES modules** throughout (`import`/`export`, no `require`)
- **No external runtime dependencies** beyond `js-yaml` (already included) — the Worker must stay lean
- **Evaluators are pure functions** — they receive `(check, api, zoneId, accountId)` and return a finding object. No side effects, no global state
- **Graceful degradation** — if an API call fails, return `NA` with a clear message, never throw unhandled errors out of an evaluator
- **Privacy by default** — never log zone IDs, account IDs, or API tokens. Use `hashId()` from `src/utils/privacy.js` before any storage write
- Existing files use 2-space indentation; match the surrounding style

---

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b add/cf-new-001`
2. Make your changes
3. Test locally with `npm run dev`
4. Verify your check appears correctly in the findings UI at `http://localhost:8787/audit`
5. Open a PR with:
   - What the check covers and why it matters
   - Which Cloudflare API endpoint/setting it reads
   - The NIST/CIS controls it maps to and a brief justification
   - A screenshot or JSON snippet showing the finding in action

PRs that add checks without a clear security rationale or framework mapping will be declined.

---

## Security Disclosures

If you discover a security vulnerability in FlareGuard itself, please do **not** open a public GitHub issue. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
