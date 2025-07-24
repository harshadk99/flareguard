# FlareGuard

> 🛡️ **Cloud Security Posture Management for Cloudflare**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen.svg)](https://flareguard.harshad-surfer.workers.dev/)

<div align="center">
  <br />
  <h1>
    <a href="https://flareguard.harshad-surfer.workers.dev/">
      <img src="https://img.shields.io/badge/🔥_TRY_FLAREGUARD_LIVE_DEMO_🔥-FF7A59?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Try FlareGuard Live Demo" height="60" />
    </a>
  </h1>
  <h3><i>Experience the power of FlareGuard CSPM firsthand!</i></h3>
  <br />
</div>

## Comprehensive CSPM for Your Cloudflare Environment

FlareGuard is a powerful, serverless CSPM (Cloud Security Posture Management) platform designed specifically for Cloudflare. It continuously scans your Cloudflare configurations for vulnerabilities, misconfigurations, and compliance gaps, delivering actionable insights to strengthen your security posture.

**Why FlareGuard CSPM?**

- 🔍 **Complete Security Visibility** - Assess your entire Cloudflare environment from zones to Zero Trust
- 🚀 **Zero Infrastructure** - Runs entirely as a Cloudflare Worker with no backend servers
- 📊 **Actionable Insights** - Get a security score and prioritized recommendations
- 🔐 **Compliance Ready** - Compare your settings against industry security standards
- 🏆 **NIST Mapped** - All findings mapped to NIST security controls
- 🔄 **Expandable Coverage** - Currently focused on zone security with roadmap for Zero Trust, Access, and more

## Current Status

FlareGuard CSPM is in active development. Our modular architecture allows us to expand security coverage across the Cloudflare ecosystem.

### What's Working

- ✅ Zone security posture assessment
- ✅ Real-time API integration for configuration analysis
- ✅ Security scoring with compliance mapping
- ✅ Detailed remediation guidance
- ✅ NIST controls mapping

### On Our Roadmap (Community Contributions Welcome!)

- 🚀 Advanced zone security checks (WAF, Rate Limiting, DNSSEC, etc.)
- 🚀 Zero Trust security posture assessment
- 🚀 Multi-zone management for enterprise environments
- 🚀 Historical security posture tracking

See our detailed [roadmap.md](roadmap.md) file for our development plans and how you can contribute.

## Future Vision

Our vision for FlareGuard is to become the definitive CSPM platform for the entire Cloudflare ecosystem. Beyond zone security, we're building a comprehensive solution that provides security visibility across all Cloudflare services. Check out our [landing page mockup](./landing_page_update.html) to see the planned user interface with enhanced features.

### Planned Enhancements

- **Enterprise CSPM Dashboard** - Unified security view across all Cloudflare services
- **Multi-Service Coverage** - Expanding beyond zones to Zero Trust, Access, Pages, and more
- **Advanced Risk Scoring** - Sophisticated algorithms for precise security posture evaluation
- **Compliance Reporting** - Pre-built reports for common frameworks (NIST, ISO, CIS)
- **Automated Remediation** - One-click fixes for common security issues

We welcome community contributions to help make this vision a reality!

## How It Works

FlareGuard provides a simple workflow to audit your Cloudflare zone security settings. The screenshots below show the web interface in action.

> **Security Note:** When using FlareGuard or sharing screenshots, always redact sensitive information like Zone IDs, API tokens, and domain names. The screenshots below are examples only and should not contain real credentials.
> 
> **Important:** Before sharing any screenshots of your FlareGuard usage:
> 1. Redact or blur all Zone IDs (32-character hexadecimal strings)
> 2. Never include API tokens in screenshots
> 3. Consider redacting domain names if they're for internal or sensitive systems
> 4. Verify no sensitive information appears in the URL bar or browser tabs

### 1. Enter Credentials

Enter your Cloudflare Zone ID and API Token to begin the security audit.

![Step 1: Enter Credentials](docs/assets/1.png)

### 2. Run Audit

Run the security audit to evaluate your zone against security best practices.

![Step 2: Run Audit](docs/assets/3.png)

### 3. View Results

Review the detailed results showing passed and failed checks, with remediation guidance.

![Step 3: View Results](docs/assets/4.png)

## Latest Updates

- **Real-time API Integration**: Now fetches live data from the Cloudflare API for basic zone settings
- **Improved Accuracy**: Security audit results now accurately reflect your actual Cloudflare configuration
- **Fixed Function Name Collision**: Resolved issues with global fetch function for better reliability
- **Optimized Deployment**: Removed unnecessary KV namespace dependencies for smoother deployment

## Features

- 🔍 **Comprehensive Security Assessment** - Analyzes Cloudflare configurations against security best practices
- 🔐 **Customizable Security Baselines** - Compare settings against YAML-defined security baselines tailored to your needs
- 📊 **Security Posture Scoring** - Calculates overall security score with detailed breakdowns by category
- 🏢 **Compliance Frameworks** - Maps findings to NIST security controls for compliance reporting
- 📝 **Actionable Remediation** - Provides step-by-step guidance to resolve each security gap
- 🔄 **Continuous Monitoring** - Connects directly to Cloudflare API for up-to-date assessment
- 🌐 **Serverless Architecture** - Runs entirely as a Cloudflare Worker with no infrastructure to maintain
- 🔌 **Extensible Platform** - Modular design allows for expanding coverage to additional Cloudflare services

## Architecture

```mermaid
flowchart LR
    %% Main components
    User([User])
    Dashboard["Dashboard UI"]
    API["API Layer"]
    Audit["Audit Engine"]
    Baseline["Security Baseline"]
    Report["Report Generator"]
    CloudflareAPI["Cloudflare API"]
    
    %% Clean flow
    User --> Dashboard --> API --> Audit
    Baseline --> Audit
    Audit --> CloudflareAPI
    CloudflareAPI --> Audit
    Audit --> Report --> API --> Dashboard --> User
    
    %% Legend with clearer status
    subgraph Legend[" "]
        Current["✅ Current: Basic Zone Security"]:::current
        Future["🤝 Community: Advanced Features"]:::future
    end
    
    %% Styling
    classDef primary fill:#f38020,stroke:#333,stroke-width:1px,color:white;
    classDef secondary fill:#faad3f,stroke:#333,stroke-width:1px,color:white;
    classDef api fill:#404041,stroke:#333,stroke-width:1px,color:white;
    classDef ui fill:#4CAF50,stroke:#333,stroke-width:1px,color:white;
    classDef user fill:#9C27B0,stroke:#333,stroke-width:1px,color:white;
    classDef legend fill:none,stroke:none;
    classDef current fill:#4CAF50,stroke:#333,stroke-width:1px,color:white;
    classDef future fill:#1976D2,stroke:#333,stroke-width:1px,color:white;
    
    class Dashboard ui;
    class API,Audit primary;
    class Baseline,Report secondary;
    class CloudflareAPI api;
    class User user;
    class Legend legend;
```

## Getting Started

### Prerequisites

- [Cloudflare](https://cloudflare.com) account
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (for deployment)
- Node.js (v16+)

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/harshadk99/flareguard.git
   cd flareguard
   ```

2. Install dependencies
   ```bash
   npm install
   ```

3. Deploy to Cloudflare Workers
   ```bash
   wrangler deploy
   ```

## Usage

### Quick Start

1. Enter your Cloudflare Zone ID
2. Enter your Cloudflare API Token with appropriate permissions
3. Click "Test Connection" to verify credentials
4. Click "Run Audit" to analyze your zone

### Required API Token Permissions

Your Cloudflare API token needs these permissions:
- Zone Read
- SSL and Certificates Read

### Understanding Results

The audit provides results in several sections:
- **Summary** - Overall security score and statistics
- **Issue List** - Detailed findings sorted by severity
- **Remediation** - Specific recommendations to improve security

## Security & Privacy

**FlareGuard prioritizes your security and privacy:**

- No credentials or sensitive data are stored
- All processing happens at request time in the Cloudflare Worker
- API tokens are only used for the duration of the audit
- No data is logged or persisted after the audit completes
- Uses `type="password"` fields to protect token visibility

## Security Checks Currently Implemented

FlareGuard currently evaluates your zone against these security best practices:

| Check | Recommendation | NIST Controls |
|-------|----------------|---------------|
| SSL/TLS Mode | Full (Strict) | SC-8, SC-12 |
| Minimum TLS Version | TLS 1.2+ | SC-8, SC-13 |
| Always Use HTTPS | Enabled | SC-8, SC-7 |
| Opportunistic Encryption | Enabled | SC-8 |
| TLS 1.3 | Enabled | SC-8, SC-13 |
| Browser Integrity Check | Enabled | SI-3 |
| Email Obfuscation | Enabled | SC-18 |
| Security Level | Medium+ | SC-5 |

## Security Checks for Community Development

We welcome community contributions to implement these additional security checks:

| Check | Recommendation | NIST Controls | Difficulty |
|-------|----------------|---------------|------------|
| WAF Core Rule Set | Enabled | SC-7, SI-4 | Medium |
| Bot Management | Enabled | SC-5, SI-4 | Medium |
| DNSSEC | Enabled | SC-8, SC-20 | Easy |
| Rate Limiting | Configured | SC-5, SI-4 | Medium |
| WAF Logging | Enabled | AU-2, AU-11 | Easy |
| Country Blocking | Configured | AC-3, SC-7 | Medium |
| Certificate Expiration | >30 days | SC-12, CM-6 | Easy |
| Strong Cipher Suites | No weak ciphers | SC-8, SC-13 | Medium |

See our [roadmap.md](roadmap.md) for more details on how you can contribute to these features.

## Contributing

We welcome and encourage contributions from the community! FlareGuard is an open-source project with many exciting opportunities for enhancement.

### Ways to Contribute

- **Implement New Security Checks**: Add one of the security checks from our community development list
- **Improve Documentation**: Enhance the docs, add examples, or clarify instructions
- **Fix Bugs**: Help us identify and fix issues
- **Add Features**: Implement new features from our roadmap
- **Suggest Ideas**: Open an issue with your feature suggestions

### Contribution Process

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add some amazing feature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Getting Help

- Check our [roadmap.md](roadmap.md) for detailed development plans
- Open an issue to discuss your ideas before starting development
- Join our community discussions in the Issues section

For major changes, please open an issue first to discuss what you'd like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Cloudflare for their excellent API documentation
- The security community for defining best practices
- All contributors who help improve this tool 

## Testing with Environment Variables

For local testing and development, you can use environment variables to securely store your Cloudflare credentials:

1. **Set up your environment variables**:
   ```bash
   npm run setup:env
   ```
   This interactive script will prompt you for your Cloudflare Zone ID and API Token and store them in a `.env` file.

2. **Run the test with environment variables**:
   ```bash
   npm run test:env
   ```

The `.env` file is automatically added to `.gitignore` to prevent accidentally committing your credentials to the repository. 