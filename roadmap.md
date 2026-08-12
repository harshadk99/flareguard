# FlareGuard Roadmap

Honest status of where the project is and what matures it next.

## Shipped (trust the audit)

- Zone settings, DNSSEC, bot, rate-limit (rulesets), managed WAF (rulesets), Page Shield, Logpush, Access, Workers
- Severity-weighted scoring; ERROR path for unevaluable API calls (not scored as FAIL)
- Privacy-first JSON export (hashed IDs by default)
- Stateless Worker by default; optional D1 / KV / R2 / Queue

## Next (make the product coherent)

1. **GitHub Action** — fail CI on open CRITICAL findings
2. **Plan-aware expectations** — Free vs Pro vs Enterprise change what FAIL vs NA means
3. **Deeper Zero Trust** — policy quality beyond "MFA present somewhere"
4. **Scheduled scans + alerts** — Cron + webhook when CRITICAL/HIGH regresses
5. **Real config drift** — setting snapshots, not only status flips between audits

## Later (only after the above)

- AI Gateway / Workers AI checks
- Exception / waiver model
- Multi-account tenancy

## Not goals right now

- Competing with Wiz/Orca on multi-cloud
- PDF executive reports before the single-zone audit is fully trusted
- Advertising History/Drift as core features while D1 stays opt-out
