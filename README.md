# FlareGuard

**The first open-source Cloud Security Posture Management (CSPM) tool purpose-built for the Cloudflare developer ecosystem.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen.svg)](https://flareguard.harshad-surfer.workers.dev/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)

<div align="center">
  <br />
  <a href="https://flareguard.harshad-surfer.workers.dev/">
    <img src="https://img.shields.io/badge/Try_Live_Demo-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Try Live Demo" />
  </a>
  <br /><br />
</div>

---

## The Problem

Mainstream CSPM tools — Wiz, Orca, Prisma Cloud — are designed for cloud infrastructure: AWS S3 buckets, Azure VMs, GCP IAM policies. They have no visibility into Cloudflare's control plane.

Yet millions of organizations now run their security perimeter *on* Cloudflare: TLS termination, WAF, Zero Trust Access, Workers, AI Gateway. A misconfigured Cloudflare zone — DNSSEC disabled, WAF in detect-only mode, no MFA on Access applications — exposes the same blast radius as a misconfigured cloud resource. **No existing tool catches it.**

FlareGuard is the missing audit layer for the Cloudflare stack.

---

## What FlareGuard Does

FlareGuard runs as a Cloudflare Worker — the same serverless runtime it audits. It connects to the Cloudflare API using credentials provided at request time, evaluates your configuration against a curated security baseline, and returns a structured report with:

- A **security score** (0–100) derived from weighted pass/fail/warning findings
- **Per-finding remediation guidance** with direct links to the relevant Cloudflare dashboard
- **NIST SP 800-53 Rev 5** and **CIS Controls v8** control mappings — resolved to full titles, descriptions, and reference URLs
- **Drift detection** — a structured diff between any two historical audits
- **Zombie Worker detection** — identifies stale, unrouted scripts that represent unmanaged attack surface

---

## Security Baseline — 29 Checks Across 9 Categories

| Category | Checks | Severity Range | Framework Coverage |
|----------|--------|----------------|--------------------|
| SSL/TLS | 5 | HIGH → LOW | NIST SC-8, SC-13 |
| Transport Security | 6 | HIGH → MEDIUM | NIST SC-8(1), CIS 3.10 |
| WAF | 2 | CRITICAL → HIGH | NIST SI-3, SC-7 |
| DNS | 1 | HIGH | NIST SC-20 |
| Bot Protection | 1 | HIGH | NIST SC-5 |
| Rate Limiting | 1 | MEDIUM | NIST SC-5 |
| Zero Trust | 2 | HIGH | NIST IA-2, AC-3 |
| Workers | 2 | CRITICAL → HIGH | NIST CM-8, IA-5 |
| Observability | 3 | HIGH → MEDIUM | NIST AU-2, SI-4, CIS 6.1, 8.2 |
| Protocol Hygiene | 3 | LOW | NIST CM-6, CIS 12.6 |
| Content Security | 1 | LOW | NIST SI-8, CIS 9.3 |

Selected checks:

| ID | Name | Severity | CIS | NIST |
|----|------|----------|-----|------|
| CF-SSL-001 | SSL/TLS mode is Full (Strict) | HIGH | — | SC-8, SC-13 |
| CF-HSTS-001 | HSTS is enabled | HIGH | 3.10 | SC-8(1) |
| CF-HSTS-002 | HSTS max-age ≥ 6 months (preload-eligible) | MEDIUM | 3.10 | SC-8(1) |
| CF-ORIGIN-001 | Authenticated Origin Pulls (mTLS) enabled | HIGH | 3.10 | SC-8, MA-9 |
| CF-WAF-001 | OWASP Core Rule Set enabled | CRITICAL | — | SI-3, SC-7 |
| CF-WAF-002 | WAF in block mode, not detect-only | HIGH | — | SI-3, SC-7 |
| CF-DNS-001 | DNSSEC active | HIGH | — | SC-20 |
| CF-LOG-001 | Active Logpush job configured | HIGH | 6.1, 8.2 | AU-2, AU-9 |
| CF-PS-001 | Page Shield enabled | HIGH | 8.2 | SI-3, SA-9 |
| CF-PS-002 | Page Shield in enforcement mode | MEDIUM | 8.2 | SI-3 |
| ZT-001 | MFA enforced on all Access applications | HIGH | — | IA-2, AC-3 |
| ZT-002 | Identity provider configured | HIGH | — | IA-2, IA-8 |
| WRK-001 | No zombie workers (stale + unrouted) | HIGH | — | CM-2, CM-8 |
| WRK-002 | No plain-text secret-like environment variables | CRITICAL | — | IA-5, SC-12 |
| CF-CERT-001 | Certificate Transparency Monitoring enabled | MEDIUM | 3.10 | SC-17 |

---

## Architecture

FlareGuard is designed for the serverless edge. No databases, no agents, no persistent infrastructure required.

```
POST /api/audit/zone
         │
         ▼
   Cloudflare Worker (flareguard)
         │
         ├── Audit Engine
         │       │
         │       ├── baseline.yaml  ← 29 checks, declarative YAML
         │       ├── Dispatcher     ← routes check.service → evaluator
         │       │
         │       ├── zone-setting   (SSL, TLS, HSTS, HTTP/2+3, mTLS, IPv6...)
         │       ├── waf            (OWASP CRS, block mode)
         │       ├── dnssec         (DNSSEC status + algorithm)
         │       ├── bot            (Bot Fight Mode / Bot Management)
         │       ├── rate-limit     (rate limiting rules)
         │       ├── access         (Zero Trust MFA, IdP — real API calls)
         │       ├── workers        (zombie detection, secret scanning)
         │       ├── page-shield    (Page Shield status + policy mode)
         │       └── logpush        (Logpush jobs, zone + account level)
         │
         ├── Mappings Layer
         │       ├── NIST SP 800-53 Rev 5  (24 controls, fully resolved)
         │       └── CIS Controls v8       (5 controls, with IG metadata)
         │
         └── Report Builder
                 └── score, findings[], resolved_controls[], framework_versions{}
```

**Stateless by default.** The audit runs entirely in-memory. Credentials are used once and discarded. Optional persistent storage (D1 + KV + R2 + Queues) activates only when bindings are present — enabling audit history, drift detection, and async account-wide scanning.

**Privacy-first.** API tokens never leave the request lifecycle. Zone and account IDs are hashed (SHA-256, truncated to 16 hex chars) before any storage write. Raw identifiers are never persisted.

---

## Versioned Compliance Mappings

FlareGuard separates *what to check* (baseline.yaml) from *what a control means* (mappings/).

```
mappings/
  nist-800-53-r5.yaml   ← source of truth for NIST Rev 5
  cis-v8.yaml           ← source of truth for CIS v8
  index.yaml            ← declares active framework version per framework
src/utils/
  mappings.js           ← compiled runtime module (no file I/O at edge)
```

Every finding in the API response carries fully resolved control metadata:

```json
{
  "id": "CF-HSTS-001",
  "status": "FAIL",
  "resolved_controls": {
    "nist": [{
      "id": "SC-8(1)",
      "title": "Transmission Confidentiality and Integrity | Cryptographic Protection",
      "family": "System and Communications Protection",
      "description": "...",
      "url": "https://csrc.nist.gov/..."
    }],
    "cis": [{
      "id": "3.10",
      "title": "Encrypt Sensitive Data in Transit",
      "group": "CIS Control 3: Data Protection",
      "implementation_groups": ["IG1", "IG2", "IG3"]
    }],
    "framework_versions": {
      "nist_800_53": "NIST SP 800-53 Rev 5",
      "cis_controls": "CIS Controls v8"
    }
  }
}
```

When NIST or CIS publishes a new revision: add a new mapping file, update `mappings/index.yaml`. The check definitions in `baseline.yaml` are unaffected unless control IDs themselves change.

---

## Getting Started

### Prerequisites
- [Cloudflare](https://cloudflare.com) account with at least one zone
- [Node.js](https://nodejs.org) v18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Run Locally

```bash
git clone https://github.com/harshadk99/flareguard.git
cd flareguard
npm install
npm run dev
# → http://localhost:8787
```

### Deploy to Cloudflare (stateless, zero config)

```bash
npx wrangler login
npm run deploy
```

No KV, D1, R2, or Queue provisioning needed. The worker is fully operational stateless.

### Enable Persistent Storage (optional)

Unlocks audit history, drift detection, and async account-wide scanning:

```bash
npm run db:create && npm run kv:create && npm run r2:create && npm run queue:create
npm run db:migrate:remote
```

Uncomment the binding sections in `wrangler.toml` and redeploy.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard SPA |
| `GET` | `/api/status` | Worker health, active bindings, privacy attestation |
| `POST` | `/api/test-connection` | Validate credentials against live Cloudflare API |
| `POST` | `/api/audit/zone` | Run a full zone security audit |
| `POST` | `/api/audit/account` | Enqueue account-wide scan across all zones |
| `GET` | `/api/history/:zoneId` | Audit history for a zone (requires D1) |
| `GET` | `/api/drift/:zoneId` | Structured diff between two most recent audits (requires D1) |
| `GET` | `/api/audit/:auditId/findings` | Full findings for a specific audit (requires D1) |

**Zone Audit Request**

```bash
curl -X POST https://flareguard.harshad-surfer.workers.dev/api/audit/zone \
  -H "Content-Type: application/json" \
  -d '{
    "zone_id": "your-zone-id",
    "api_token": "your-cloudflare-api-token",
    "account_id": "your-account-id"
  }'
```

`account_id` is optional but required for Zero Trust, Workers, Logpush, and Page Shield checks.

**Required API Token Permissions**

| Permission | Checks Enabled |
|------------|----------------|
| Zone Read | All zone settings |
| SSL and Certificates Read | TLS, HSTS, Authenticated Origin Pulls |
| Firewall Services Read | WAF, rate limits |
| DNS Read | DNSSEC |
| Account Settings Read | Worker scripts |
| Access: Apps and Policies Read | Zero Trust MFA |
| Logs Read | Logpush jobs |
| Page Shield Read | Page Shield status |

---

## Extending the Baseline

Adding a check for a zone setting requires only YAML — no code:

```yaml
- id: CF-NEW-001
  name: My new security check
  category: Security
  service: zone-setting
  setting: <cloudflare_setting_id>
  expect: "on"              # or: expect_one_of, expect_min_tls, expect_nested
  severity: MEDIUM
  nist_controls: [SC-7]
  cis_controls: ["3.10"]
  remediation: Enable this setting in the Cloudflare dashboard.
```

For checks that require custom API calls, add an evaluator in `src/audit/evaluators/` and register it in `src/audit/engine.js`. The evaluator receives the check definition and a fully authenticated API client.

---

## Roadmap

- [ ] Scheduled scans via Cron Triggers — continuous posture monitoring
- [ ] Slack / email alerts on drift — operational security integration
- [ ] AI Gateway security checks mapped to NIST AI RMF
- [ ] Workers AI posture checks mapped to OWASP LLM Top 10
- [ ] AI Bill of Materials (AIBOM) — inventory of AI models and Gateway routes per account
- [ ] Multi-account dashboard
- [ ] Compliance report export — PDF and hosted shareable URL

---

## Why This Matters

Cloudflare serves over 20% of the internet. The organizations running on it — from startups to enterprises — now use Cloudflare as their security perimeter, not just a CDN. Zero Trust Access replaces VPNs. Workers replace origin servers. AI Gateway proxies LLM traffic.

No compliance framework auditor, no CSPM vendor, and no existing open-source tool has kept pace with this shift. FlareGuard is an attempt to close that gap — starting with the 29 controls that matter most, mapped to the frameworks that enterprises actually use for compliance evidence.

---

## Disclaimer

FlareGuard is an independent open-source project. It is not affiliated with, endorsed by, or associated with Cloudflare, Inc. All Cloudflare product names are trademarks of Cloudflare, Inc.

---

## License

MIT — see [LICENSE](LICENSE)

## Author

[Harshad Sadashiv Kadam](https://harshadsadashivkadam.com)
