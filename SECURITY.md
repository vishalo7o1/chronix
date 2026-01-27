# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Chronix, please report it responsibly.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Use [GitHub Security Advisories](https://github.com/icecubesandwich/chronix/security/advisories/new) to report privately
3. Alternatively, email: `security@0xtb.sh`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Depends on severity, typically 30-90 days

### Disclosure Policy

- Please allow reasonable time for a fix before public disclosure
- We will credit reporters in release notes (unless you prefer anonymity)
- We will not pursue legal action against good-faith security researchers

## Security Features

Chronix includes:

- Argon2id password hashing
- Server-side session management
- CSRF protection
- Rate limiting
- Input sanitization
- Secure cookie attributes (HttpOnly, SameSite, Secure when behind TLS)

## Self-Hosting Recommendations

- Deploy behind a TLS-terminating reverse proxy
- Use strong, unique passwords
- Keep the application updated
- Restrict network access where possible
