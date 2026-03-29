# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please use [GitHub Security Advisories](https://github.com/muratdemirci/mitnick/security/advisories/new) to report vulnerabilities privately.

Include as much of the following as possible:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix and release**: Depends on severity, typically within 2 weeks for critical issues

## Disclosure Policy

- We follow responsible disclosure practices
- We will coordinate with you on public disclosure timing
- Credit will be given to reporters in the release notes (unless you prefer to remain anonymous)

## Scope

As a security analysis tool, we take the following especially seriously:

- Vulnerabilities that could cause mitnick to execute code from analyzed packages
- Path traversal during tarball extraction
- Denial of service via crafted packages
- False negatives that could cause mitnick to miss real threats
