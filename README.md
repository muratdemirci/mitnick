# mitnick

Pre-install security analysis CLI for npm packages. Analyze packages **before** installation to detect vulnerabilities, malicious code, typosquatting, and supply chain attacks.

Named after [Kevin Mitnick](https://en.wikipedia.org/wiki/Kevin_Mitnick), one of the most famous security experts in history.

## Why?

npm supply chain attacks are escalating. In 2025 alone, packages like `debug` and `chalk` (2.6B+ weekly downloads) were compromised. Existing tools like `npm audit` only work **after** installation — by then, malicious `postinstall` scripts have already executed.

**mitnick** fetches and analyzes package tarballs from the npm registry without ever executing their code. Nothing runs on your machine except mitnick itself.

## Install

```bash
npm install -g mitnick
```

Or use directly with npx:

```bash
npx mitnick check express
```

## Usage

```bash
# Check a single package
mitnick check express

# Check a specific version
mitnick check express@4.19.2

# Check multiple packages at once
mitnick check express lodash chalk

# JSON output for scripts and tooling
mitnick check --json express

# SARIF output for GitHub Security tab
mitnick check --sarif express

# CI mode — exit code 1 if any finding meets the severity threshold
mitnick check --fail-on high express

# Verbose output with extra details
mitnick check --verbose express
```

## Output

```
  mitnick v1.0.0 — Security Analysis

  Checking express@4.19.2...

  ✓ Vulnerability Scanner     2 findings
  ✓ Install Scripts           0 findings
  ✓ Typosquatting             0 findings
  ✓ Obfuscation               0 findings
  ✓ Network Calls             1 finding
  ✓ Sensitive Data            0 findings
  ✓ License                   0 findings
  ✓ Maintainer                1 finding
  ✓ Dependency Confusion      0 findings
  ✓ Dormant Package           0 findings
  ✓ Prototype Pollution       0 findings

  Score: 79/100 (C)

  ┌──────────┬──────────┬──────────────────────────────────────┐
  │ Severity │ Analyzer │ Finding                              │
  ├──────────┼──────────┼──────────────────────────────────────┤
  │ HIGH     │ Vuln     │ CVE-2024-XXXX in qs@6.5.2           │
  │ MEDIUM   │ Vuln     │ CVE-2024-YYYY in path-to-regexp@0.1 │
  │ MEDIUM   │ Network  │ Uses http module for outbound calls  │
  │ LOW      │ Maint    │ Single maintainer (bus factor = 1)   │
  └──────────┴──────────┴──────────────────────────────────────┘

  Analyzed in 1.2s
```

## Security Analyzers

mitnick runs 11 security analyzers on every package:

| Analyzer | What it detects |
|----------|----------------|
| **Vulnerability Scanner** | Known CVEs via the [OSV](https://osv.dev) database and GitHub Advisory DB |
| **Install Scripts** | `preinstall`/`postinstall` hooks with suspicious commands (curl, wget, eval, shell spawning) |
| **Typosquatting** | Package names suspiciously similar to popular packages (Levenshtein distance, character substitution) |
| **Obfuscation** | High-entropy strings, `eval()`, `new Function()`, Base64 blobs, hex-encoded code |
| **Network Calls** | `fetch()`, `http.request()`, axios/got imports, hardcoded IP addresses |
| **Sensitive Data** | `process.env` harvesting, access to `~/.ssh`, `~/.aws`, `~/.npmrc`, credential files |
| **License** | Missing licenses, copyleft (GPL/AGPL), SPDX compliance |
| **Maintainer** | Single-maintainer risk (bus factor), new/inactive accounts |
| **Dependency Confusion** | Public packages mimicking internal/private naming patterns |
| **Dormant Package** | Packages reactivated after long inactivity (common attack vector) |
| **Prototype Pollution** | `__proto__` access, `Object.prototype` mutation, unsafe merge functions |

## Scoring

Each package gets a score from 0 to 100 based on findings:

| Severity | Points deducted |
|----------|----------------|
| Critical | -25 |
| High | -15 |
| Medium | -8 |
| Low | -3 |
| Info | 0 |

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 50-69 | D |
| 0-49 | F |

## CI/CD Integration

### Exit codes

Use `--fail-on` to fail your pipeline when findings meet a severity threshold:

```bash
# Fail if any critical or high severity finding exists
mitnick check --fail-on high express
```

Exit code `1` means findings were found at or above the threshold. Exit code `0` means the package passed.

### GitHub Actions

```yaml
- name: Security check dependencies
  run: npx mitnick check --fail-on medium $(cat package.json | jq -r '.dependencies | keys[]')
```

### SARIF upload to GitHub Security tab

```yaml
- name: Run mitnick
  run: npx mitnick check --sarif express > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Requirements

- Node.js >= 18.0.0

## Development

```bash
# Clone and install
git clone https://github.com/your-username/mitnick.git
cd mitnick
npm install

# Build
npm run build

# Run tests (298 tests)
npm test

# Run tests with coverage
npm run test:coverage

# Type check
npm run typecheck
```

## Architecture

```
src/
├── cli/          CLI entry point, commands, formatters (terminal/JSON/SARIF)
├── core/         Analysis engine, scoring system, shared types
├── registry/     npm registry client, tarball download and extraction
├── analyzers/    11 security analyzers (each implements Analyzer interface)
└── utils/        AST parsing, HTTP client, filesystem helpers, logger
```

All analyzers implement a shared `Analyzer` interface and are executed in parallel. Adding a new analyzer requires zero changes to existing code (Open/Closed Principle).

## License

[MIT](LICENSE)
