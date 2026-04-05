# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-03-25

### Added

- **CLI**: `mitnick check` command for pre-install security analysis of npm packages
- **CLI**: Support for checking multiple packages at once
- **CLI**: `--json` flag for machine-readable JSON output
- **CLI**: `--sarif` flag for SARIF v2.1.0 output (GitHub Security tab integration)
- **CLI**: `--fail-on <severity>` flag for CI/CD pipeline integration
- **CLI**: `--verbose` flag for detailed analysis output
- **Programmatic API**: Public exports for using mitnick as a library (`AnalysisEngine`, `createAnalyzers`, `fetchPackageMetadata`, `downloadAndExtract`)
- **Semver Support**: Version resolution with semver ranges (`^`, `~`, `>=`, complex ranges)
- **Analyzer**: Vulnerability Scanner — detects known CVEs via the OSV database
- **Analyzer**: Install Scripts — flags suspicious `preinstall`/`postinstall` hooks
- **Analyzer**: Typosquatting — detects names similar to popular packages
- **Analyzer**: Obfuscation — identifies high-entropy strings, `eval()`, `new Function()`, Base64 blobs
- **Analyzer**: Network Calls — flags `fetch()`, `http.request()`, hardcoded IP addresses
- **Analyzer**: Sensitive Data — detects `process.env` harvesting, access to credential files
- **Analyzer**: License — checks for missing or copyleft licenses
- **Analyzer**: Maintainer — flags single-maintainer risk (bus factor)
- **Analyzer**: Dependency Confusion — detects public packages mimicking private naming patterns
- **Analyzer**: Dormant Package — identifies packages reactivated after long inactivity
- **Analyzer**: Prototype Pollution — detects `__proto__` access, unsafe merge functions
- **Scoring**: 0-100 security score with letter grades (A/B/C/D/F)
- **Registry Client**: npm registry API client with Zod validation
- **Tarball**: Secure tarball download and extraction with path traversal protection

[1.0.0]: https://github.com/muratdemirci/mitnick/releases/tag/v1.0.0
