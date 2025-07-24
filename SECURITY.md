# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in FlareGuard, please report it by creating an issue marked as "Security Vulnerability" in the GitHub repository. We take all security issues seriously and will respond promptly.

## Security Best Practices

### API Token Handling

1. **Never commit API tokens to version control**
   - Always use environment variables or secure credential storage
   - The `.env` file is included in `.gitignore` to prevent accidental commits

2. **Limit API token permissions**
   - Use the principle of least privilege
   - Only request the specific permissions needed for the audit:
     - Zone Read
     - SSL and Certificates Read

3. **Token expiration**
   - Create tokens with expiration dates when possible
   - Revoke tokens when they are no longer needed

### Local Development

1. **Environment variables**
   - Use the `npm run setup:env` script to securely store credentials
   - Ensure `.env` file permissions are restricted to the owner (mode 600)

2. **Audit results**
   - The `audit_results.json` file is included in `.gitignore`
   - Sanitize any output that might contain sensitive information

### Deployment

1. **Cloudflare Worker security**
   - Workers run in isolated environments
   - No persistent storage of credentials
   - All processing happens at request time

2. **User interface security**
   - API tokens are input in password fields to prevent shoulder surfing
   - No credentials are stored in browser storage or cookies

## Security Features

1. **Input validation**
   - All user inputs are validated before use
   - API token format is verified before attempting to use it

2. **Secure defaults**
   - Restrictive file permissions for credential files
   - Automatic .gitignore verification

3. **Data minimization**
   - Only necessary data is collected for audits
   - No user data is stored persistently

## Vulnerability Disclosure

Please include the following information when reporting security vulnerabilities:

1. Type of issue
2. Full path to the affected file(s)
3. Location of the affected source code
4. Any special configuration required to reproduce the issue
5. Step-by-step instructions to reproduce the issue
6. Proof-of-concept or exploit code (if possible)
7. Impact of the issue

We appreciate your help in keeping FlareGuard secure! 