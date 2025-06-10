# FlareGuard Verification Checklist

Use this checklist to manually verify the audit findings against your actual Cloudflare configuration.

## How to Use
1. Run a FlareGuard audit on your zone
2. Log in to the Cloudflare dashboard for the same zone
3. Check each setting below to compare against the audit results

## WAF Settings
- [ ] **CF-WAF-001**: WAF is enabled
  - Location: Security > WAF
  - Expected: WAF should be enabled/active

- [ ] **CF-WAF-002**: OWASP Core Rule Set is enabled
  - Location: Security > WAF > Managed Rules
  - Expected: OWASP Core Rule Set should be enabled

## SSL/TLS Settings
- [ ] **CF-SSL-001**: SSL/TLS Encryption is set to Full (Strict)
  - Location: SSL/TLS > Overview
  - Expected: Encryption mode should be set to "Full (strict)"

- [ ] **CF-TLS-001**: Minimum TLS Version is 1.2 or higher
  - Location: SSL/TLS > Edge Certificates
  - Expected: Minimum TLS Version should be 1.2 or 1.3

- [ ] **CF-TLS-002**: Opportunistic Encryption is enabled
  - Location: SSL/TLS > Edge Certificates
  - Expected: Opportunistic Encryption should be ON

- [ ] **CF-TLS-003**: TLS 1.3 is enabled
  - Location: SSL/TLS > Edge Certificates
  - Expected: TLS 1.3 should be enabled

- [ ] **CF-HTTPS-001**: Always Use HTTPS is enabled
  - Location: SSL/TLS > Edge Certificates
  - Expected: Always Use HTTPS should be ON

- [ ] **CF-HSTS-001**: HTTP Strict Transport Security (HSTS) is enabled
  - Location: SSL/TLS > Edge Certificates
  - Expected: HSTS should be enabled

## DNS Settings
- [ ] **CF-DNSSEC-001**: DNSSEC is enabled
  - Location: DNS > Settings
  - Expected: DNSSEC should be enabled

## Bot Management
- [ ] **CF-BOT-001**: Bot Fight Mode is enabled
  - Location: Security > Bots
  - Expected: Bot Fight Mode or Bot Management should be enabled

## Security Settings
- [ ] **CF-BROWSER-001**: Browser Integrity Check is enabled
  - Location: Security > Settings
  - Expected: Browser Integrity Check should be ON

- [ ] **CF-CHALLENGE-001**: Security Level is set to Medium or Higher
  - Location: Security > Settings
  - Expected: Security Level should be Medium, High, or I'm Under Attack

## Firewall Settings
- [ ] **CF-FIREWALL-001**: Has active firewall rules
  - Location: Security > WAF > Firewall Rules
  - Expected: At least one active firewall rule should exist

## Scrape Shield
- [ ] **CF-EMAIL-001**: Email Obfuscation is enabled
  - Location: Scrape Shield
  - Expected: Email Obfuscation should be ON

---

## Validation Process
For each check:
1. Navigate to the specified location in your Cloudflare dashboard
2. Compare the actual setting with the expected value
3. Check if the audit result (PASS/FAIL/WARNING) accurately reflects your configuration
4. Note any discrepancies for future improvement of FlareGuard

## Submit Feedback
If you find any inaccuracies in the audit results, please let us know so we can improve the tool. 