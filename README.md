# FlareGuard - Cloudflare Security Auditing Tool

FlareGuard is a comprehensive security auditing tool for Cloudflare configurations, designed to help organizations ensure their Cloudflare setup follows security best practices. It provides an easy-to-use dashboard for security teams to quickly identify and remediate security issues.

![FlareGuard Dashboard](https://via.placeholder.com/800x400?text=FlareGuard+Dashboard)

## Features

### Multi-Zone Security Auditing
- Audit multiple zones simultaneously
- Compare security posture across zones
- Identify common issues affecting multiple zones
- Prioritize remediation efforts based on severity and impact

### Zone Security Checks
- SSL/TLS configuration validation
- WAF (Web Application Firewall) setup review
- DNSSEC implementation verification
- Security headers analysis
- Always Use HTTPS enforcement
- Opportunistic Encryption validation
- Browser Integrity Check verification
- Email Obfuscation verification
- Security Level assessment

### Zero Trust & Access Security
- Access applications security assessment
- Identity provider configuration verification
- Device posture checks evaluation
- Access policy security analysis
- Approval workflows for critical applications
- Session duration validation
- Gateway DNS filtering verification
- "Allow All" policies detection

### Comprehensive Reporting
- Security score calculation
- Detailed remediation recommendations
- Executive summary for leadership
- Exportable reports for compliance purposes
- Trend analysis across audit runs

## Getting Started

### Prerequisites
- Cloudflare account
- Zone ID(s) for the domain(s) you want to audit
- API token with appropriate permissions

### API Token Permissions Required
For basic zone security auditing:
- Zone Read
- SSL and Certificates Read
- WAF Read
- DNS Read
- Page Rules Read

For Zero Trust auditing:
- Account Access: Apps and Policies Read
- Gateway: DNS Read
- Zero Trust: Access Read

### Using the Dashboard
1. Navigate to the FlareGuard dashboard
2. Enter your Cloudflare Zone ID (or Account ID for Zero Trust)
3. Enter your API token
4. Choose the audit type (Zone Security, Zero Trust, or Multi-Zone)
5. Click "Run Audit"

### Understanding Results
The dashboard presents results in several sections:
- **Summary**: Overall security score and key metrics
- **Issues**: Detailed list of identified issues sorted by severity
- **Recommendations**: Specific actions to remediate issues
- **Details**: In-depth explanation of each security check

## Security Baselines

### Zone Security Baseline
FlareGuard evaluates your zone against security best practices including:
- SSL/TLS mode: Full (Strict) recommended
- Minimum TLS version: TLS 1.2 recommended
- Always Use HTTPS: Should be enabled
- Opportunistic Encryption: Should be enabled
- TLS 1.3: Should be enabled
- Browser Integrity Check: Should be enabled
- Email Obfuscation: Should be enabled
- Security Level: Medium or higher recommended

### Zero Trust Baseline
For Zero Trust configurations, FlareGuard checks:
- MFA required for all Access applications
- Appropriate session durations (8 hours max recommended)
- Device posture checks implemented
- No "Allow All" policies
- Secure identity provider configuration
- Browser isolation for sensitive applications
- Geo-restrictions for sensitive applications
- Approval groups for critical applications

## Implementation Details

FlareGuard is implemented as a Cloudflare Worker, making it easy to deploy and maintain. The security checks are executed directly using the Cloudflare API, ensuring up-to-date and accurate results.

### Architecture
- **Worker**: Core service that handles API requests and responses
- **Dashboard UI**: User-friendly interface for viewing results
- **API Module**: Handles communication with Cloudflare API
- **Security Modules**: Specialized modules for different security domains
- **Multi-Zone Module**: Coordinates audits across multiple zones

## Roadmap

See the [roadmap.md](roadmap.md) file for planned enhancements to FlareGuard.

## Verification Tools

For users who want to verify FlareGuard's findings directly against the Cloudflare API, we provide several verification tools:

- **verify_settings.sh**: Shell script to query Cloudflare API directly
- **verify_access_apps.sh**: Shell script to verify Access Apps configuration
- **verification_checklist.md**: Manual verification checklist

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Cloudflare for their excellent API documentation
- The security community for defining best practices

## Contact

For questions or support, please open an issue on GitHub. 