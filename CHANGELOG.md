# Changelog

All notable changes to FlareGuard will be documented in this file.

## [1.1.0] - 2023-07-15

### Added
- Added real-time API integration for core zone settings
- Added comparison_results.md to document verification findings

### Changed
- **Major**: Now fetches live data from the Cloudflare API instead of using hard-coded values
- Improved accuracy of security audit results
- Renamed custom `fetch` function to `handleRequest` to avoid collision with global `fetch` function
- Updated wrangler.toml to remove site assets configuration that was causing KV namespace errors
- Optimized worker deployment process

### Fixed
- Fixed incorrect audit results due to hard-coded values
- Fixed function name collision with global `fetch` function
- Fixed KV namespace errors during deployment

### Note
- The verification scripts (`verify_working.sh` and `verify_settings.sh`) mentioned in this version are not yet implemented

## [1.0.0] - 2023-06-01

### Added
- Initial release of FlareGuard
- Basic security auditing for Cloudflare zone configurations
- Web dashboard for viewing audit results
- Security baseline defined in YAML
- Remediation guidance for security issues
- NIST controls mapping
- Security scoring system

### Implemented Checks
- SSL/TLS Mode
- Minimum TLS Version
- Always Use HTTPS
- Opportunistic Encryption
- TLS 1.3
- Browser Integrity Check
- Email Obfuscation
- Security Level 