# Changelog

All notable changes to FlareGuard will be documented in this file.

## [1.1.0] - 2025-06-12

### Added
- Added verification scripts (`verify_working.sh` and `verify_settings.sh`) to validate audit results
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

## [1.0.0] - 2025-06-01

### Added
- Initial release of FlareGuard
- Security auditing for Cloudflare zone configurations
- Web dashboard for viewing audit results
- Security baseline defined in YAML
- Remediation guidance for security issues
- NIST controls mapping
- Security scoring system 