# FlareGuard

> Open-source CSPM for the Cloudflare stack

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

FlareGuard audits your entire Cloudflare environment — zone security, Zero Trust policies, and Workers — in a single run. No infrastructure to manage. Nothing stored by default.

**Existing CSPM tools cover AWS, GCP, and Azure. Cloudflare is a blind spot. FlareGuard fills that gap.**

---

## What It Checks

| Category | Checks | Examples |
|---|---|---|
| SSL/TLS | 5 | Full (Strict) mode, TLS 1.2+ minimum, TLS 1.3, Always HTTPS |
| Security | 3 | Browser Integrity Check, Security Level, Email Obfuscation |
| WAF | 2 | OWASP Core Rule Set, block vs. detect-only mode |
| DNS | 1 | DNSSEC active |
| Bot Protection | 1 | Bot Fight Mode / Bot Management |
| Rate Limiting | 1 | At least one active rule |
| Zero Trust | 2 | MFA on all Access apps, identity provider configured |
| Workers | 2 | Zombie worker detection, plain-text secret scanning |

All findings map to NIST SP 800-53 controls.

---

## Architecture

Built on the Cloudflare stack — no external infrastructure required.

```
Zone Audit Request
       │
       ▼
  Audit Engine  ──── baseline.yaml (17 checks)
       │
       ├── zone-setting evaluator  (SSL, TLS, security settings)
       ├── waf evaluator           (OWASP CRS, block mode)
       ├── dnssec evaluator        (DNSSEC status)
       ├── bot evaluator           (Bot Fight Mode / Management)
       ├── rate-limit evaluator    (rate limiting rules)
       ├── access evaluator        (Zero Trust MFA, IdP)
       └── workers evaluator       (zombie detection, secret scanning)
```

**Stateless by default.** Audit runs in-memory, result returned in the response. Optional persistent storage (D1 + KV + R2 + Queues) activates when bindings are present — enables audit history, drift detection, and async account-wide scanning.

**Privacy-first.** API tokens never leave the request. Zone IDs are hashed (SHA-256) before any storage write. Raw credentials are never persisted.

---

## Getting Started

### Prerequisites
- [Cloudflare](https://cloudflare.com) account
- [Node.js](https://nodejs.org) v16+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Run Locally (zero setup)

```bash
git clone https://github.com/harshadk99/flareguard.git
cd flareguard
npm install
npm run dev
```

Open `http://localhost:8787` — enter your Zone ID and API token to run an audit.

### Deploy to Cloudflare

```bash
npx wrangler login
npm run deploy
```

That's it. The worker deploys stateless — no KV, D1, R2, or Queue provisioning needed.

### Enable Persistent Storage (optional)

To unlock audit history, drift detection, and async account-wide scanning:

```bash
npm run db:create    # creates D1 database
npm run kv:create    # creates KV namespace
npm run r2:create    # creates R2 bucket
npm run queue:create # creates Queue
npm run db:migrate:remote
```

Then uncomment the binding sections in `wrangler.toml` and redeploy.

---

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/status` | Active features + privacy attestation |
| `POST` | `/api/test-connection` | Validate credentials against live Cloudflare API |
| `POST` | `/api/audit/zone` | Run a zone security audit |
| `POST` | `/api/audit/account` | Enqueue account-wide scan across all zones |
| `GET` | `/api/history/:zoneId` | Audit history (requires D1) |
| `GET` | `/api/drift/:zoneId` | Drift between two most recent audits (requires D1) |
| `GET` | `/api/audit/:auditId/findings` | Detailed findings for one audit (requires D1) |

### Zone Audit Request

```bash
curl -X POST https://your-worker.workers.dev/api/audit/zone \
  -H "Content-Type: application/json" \
  -d '{
    "zone_id": "your-32-char-zone-id",
    "api_token": "your-cloudflare-api-token",
    "account_id": "your-account-id"
  }'
```

`account_id` is optional but enables Zero Trust and Worker checks.

### Required API Token Permissions

| Permission | Purpose |
|---|---|
| Zone Read | Basic zone settings |
| SSL and Certificates Read | TLS configuration |
| Firewall Services Read | WAF packages, rate limits |
| DNS Read | DNSSEC status |
| Account Settings Read | Worker scripts, Access apps |
| Access: Apps and Policies Read | Zero Trust MFA checks |

---

## Adding Security Checks

Add a check to `baseline.yaml` — no code required for zone settings:

```yaml
- id: CF-PERF-001
  name: HTTP/2 is enabled
  category: Performance
  service: zone-setting
  setting: http2
  expect: "on"
  severity: LOW
  nist_controls: [SC-8]
  remediation: Enable HTTP/2 in Speed > Optimization.
```

For new service types, add an evaluator in `src/audit/evaluators/` and register it in `src/audit/engine.js`.

---

## Roadmap

- [ ] Scheduled scans (Cron Triggers)
- [ ] Slack / email alerts on drift
- [ ] AI Gateway security checks (NIST AI RMF mapping)
- [ ] Workers AI posture checks (OWASP LLM Top 10)
- [ ] Multi-account dashboard
- [ ] CIS Benchmark profile for Cloudflare
- [ ] Compliance report export (PDF / hosted URL)

---

## Disclaimer

FlareGuard is an independent open-source project developed in personal time. It is not affiliated with, endorsed by, or associated with Cloudflare, Inc. in any way. All Cloudflare product names are trademarks of Cloudflare, Inc.

---

## License

MIT — see [LICENSE](LICENSE).

## Author

[Harshad Sadashiv Kadam](https://harshadsadashivkadam.com)
