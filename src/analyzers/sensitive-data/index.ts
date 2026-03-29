/**
 * Sensitive Data Analyzer — detects access to environment variables,
 * credential files, sensitive filesystem paths, and secret key files.
 */

import type { Finding } from '../../core/types.js';
import { parseSource, walkAST, extractStringLiterals, isMemberAccess } from '../../utils/ast.js';
import { truncate } from '../../utils/strings.js';
import { FileBasedAnalyzer } from '../file-based-analyzer.js';

// ─── Constants ────────────────────────────────────────────

/** Sensitive filesystem paths. */
const SENSITIVE_PATHS: readonly string[] = [
  '~/.ssh',
  '~/.aws',
  '~/.npmrc',
  '~/.gnupg',
  '~/.config',
  '~/.netrc',
  '~/.bash_history',
  '~/.zsh_history',
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '.env',
  '.env.local',
  '.env.production',
];

/** File patterns that commonly contain secrets. */
const SENSITIVE_FILE_PATTERNS: readonly RegExp[] = [
  /\.pem$/i,
  /\.key$/i,
  /\bid_rsa\b/i,
  /\bid_ed25519\b/i,
  /\bid_ecdsa\b/i,
  /\bcredentials\.json\b/i,
  /\bservice[_-]?account\.json\b/i,
  /\b\.env\b/,
  /\btoken\.json\b/i,
  /\bsecrets?\.(json|ya?ml|toml)\b/i,
  /\bkeystore\b/i,
  /\bknown_hosts\b/i,
];

/** Sensitive-sounding environment variable name fragments. */
const SENSITIVE_ENV_NAMES: readonly string[] = [
  'SECRET',
  'TOKEN',
  'API_KEY',
  'APIKEY',
  'PASSWORD',
  'PASSWD',
  'PRIVATE_KEY',
  'ACCESS_KEY',
  'AWS_SECRET',
  'DATABASE_URL',
  'DB_PASSWORD',
];

// ─── Analyzer ─────────────────────────────────────────────

export class SensitiveDataAnalyzer extends FileBasedAnalyzer {
  readonly name = 'sensitive-data';
  readonly description =
    'Detects access to environment variables, credentials, and sensitive file paths';

  protected analyzeFile(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    findings.push(...this.detectProcessEnvAccess(source, relPath));
    findings.push(...this.detectSensitivePaths(source, relPath));
    findings.push(...this.detectSensitiveFilePatterns(source, relPath));
    findings.push(...this.detectEnvHarvesting(source, relPath));

    return findings;
  }

  private detectProcessEnvAccess(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    let envAccessCount = 0;
    const state = { bulkEnvAccess: false };

    walkAST(parsed.ast, (node) => {
      // process.env
      if (isMemberAccess(node, 'process', 'env')) {
        envAccessCount++;

        // Check if this is the object in a further member expression (process.env.SECRET_KEY)
        // We count them; too many distinct env accesses is suspicious
      }

      // Object.keys(process.env) or Object.entries(process.env) — bulk harvesting
      if (node.type === 'CallExpression') {
        const callee = node['callee'];
        if (typeof callee === 'object' && callee !== null) {
          const calleeNode = callee as Record<string, unknown>;
          if (calleeNode['type'] === 'MemberExpression') {
            const obj = calleeNode['object'] as Record<string, unknown> | undefined;
            const prop = calleeNode['property'] as Record<string, unknown> | undefined;
            if (
              obj?.['type'] === 'Identifier' &&
              obj['name'] === 'Object' &&
              prop?.['type'] === 'Identifier' &&
              (prop['name'] === 'keys' || prop['name'] === 'entries' || prop['name'] === 'values')
            ) {
              const args = node['arguments'];
              if (Array.isArray(args) && args.length > 0) {
                const firstArg = args[0] as Record<string, unknown> | undefined;
                if (
                  firstArg?.['type'] === 'MemberExpression' &&
                  typeof firstArg['object'] === 'object' &&
                  firstArg['object'] !== null
                ) {
                  const argObj = firstArg['object'] as Record<string, unknown>;
                  const argProp = firstArg['property'] as Record<string, unknown> | undefined;
                  if (
                    argObj['type'] === 'Identifier' &&
                    argObj['name'] === 'process' &&
                    argProp?.['type'] === 'Identifier' &&
                    argProp['name'] === 'env'
                  ) {
                    state.bulkEnvAccess = true;
                  }
                }
              }
            }
          }
        }
      }

      // JSON.stringify(process.env)
      if (node.type === 'CallExpression') {
        const callee = node['callee'];
        if (typeof callee === 'object' && callee !== null) {
          const calleeNode = callee as Record<string, unknown>;
          if (calleeNode['type'] === 'MemberExpression') {
            const obj = calleeNode['object'] as Record<string, unknown> | undefined;
            const prop = calleeNode['property'] as Record<string, unknown> | undefined;
            if (
              obj?.['type'] === 'Identifier' &&
              obj['name'] === 'JSON' &&
              prop?.['type'] === 'Identifier' &&
              prop['name'] === 'stringify'
            ) {
              const args = node['arguments'];
              if (Array.isArray(args) && args.length > 0) {
                const firstArg = args[0] as Record<string, unknown> | undefined;
                if (
                  firstArg?.['type'] === 'MemberExpression' &&
                  typeof firstArg['object'] === 'object' &&
                  firstArg['object'] !== null
                ) {
                  const argObj = firstArg['object'] as Record<string, unknown>;
                  const argProp = firstArg['property'] as Record<string, unknown> | undefined;
                  if (
                    argObj['type'] === 'Identifier' &&
                    argObj['name'] === 'process' &&
                    argProp?.['type'] === 'Identifier' &&
                    argProp['name'] === 'env'
                  ) {
                    state.bulkEnvAccess = true;
                  }
                }
              }
            }
          }
        }
      }
    });

    if (state.bulkEnvAccess) {
      findings.push({
        analyzer: this.name,
        severity: 'high',
        title: 'Bulk environment variable harvesting detected',
        description:
          'The package accesses the entire process.env object (via Object.keys, Object.entries, or JSON.stringify). ' +
          'This may be used to exfiltrate secrets.',
        file: relPath,
        recommendation: 'Investigate what the package does with the full environment.',
      });
    } else if (envAccessCount > 5) {
      findings.push({
        analyzer: this.name,
        severity: 'high',
        title: `Excessive process.env access (${envAccessCount} occurrences)`,
        description: `The package accesses process.env ${envAccessCount} times, which may indicate environment harvesting.`,
        file: relPath,
        recommendation: 'Review which environment variables are being read and why.',
      });
    } else if (envAccessCount > 0) {
      findings.push({
        analyzer: this.name,
        severity: 'info',
        title: `process.env access detected (${envAccessCount} occurrences)`,
        description: `The package reads environment variables (${envAccessCount} access points).`,
        file: relPath,
        recommendation: 'Verify the package only reads expected configuration variables.',
      });
    }

    return findings;
  }

  private detectSensitivePaths(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const strings = extractStringLiterals(source, relPath);

    const flagged = new Set<string>();

    for (const str of strings) {
      for (const sensitivePath of SENSITIVE_PATHS) {
        if (str.includes(sensitivePath) && !flagged.has(sensitivePath)) {
          flagged.add(sensitivePath);
          findings.push({
            analyzer: this.name,
            severity: 'critical',
            title: `Access to sensitive path: ${sensitivePath}`,
            description:
              `The package contains a reference to "${sensitivePath}", ` +
              'which may indicate credential theft or reconnaissance.',
            file: relPath,
            recommendation: 'Investigate why the package accesses this sensitive path.',
          });
        }
      }
    }

    return findings;
  }

  private detectSensitiveFilePatterns(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const strings = extractStringLiterals(source, relPath);

    const flagged = new Set<string>();

    for (const str of strings) {
      for (const pattern of SENSITIVE_FILE_PATTERNS) {
        if (pattern.test(str) && !flagged.has(str)) {
          flagged.add(str);
          findings.push({
            analyzer: this.name,
            severity: 'critical',
            title: `Credential file reference: ${truncate(str, 60)}`,
            description: `The package references a file matching sensitive credential pattern: "${truncate(str, 120)}".`,
            file: relPath,
            recommendation: 'Verify why the package needs access to credential files.',
          });
          break; // Only match first pattern per string
        }
      }
    }

    return findings;
  }

  private detectEnvHarvesting(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    const strings = extractStringLiterals(source, relPath);
    const foundSensitiveEnvs: string[] = [];

    for (const str of strings) {
      const upperStr = str.toUpperCase();
      for (const envName of SENSITIVE_ENV_NAMES) {
        if (upperStr.includes(envName)) {
          foundSensitiveEnvs.push(str);
          break;
        }
      }
    }

    // Only flag if process.env is also accessed
    if (foundSensitiveEnvs.length > 0 && source.includes('process.env')) {
      findings.push({
        analyzer: this.name,
        severity: 'high',
        title: 'Sensitive environment variable names detected',
        description:
          `The package references sensitive-sounding env variable names: ` +
          `${foundSensitiveEnvs
            .slice(0, 5)
            .map((s) => `"${s}"`)
            .join(', ')}`,
        file: relPath,
        recommendation: 'Verify the package is not exfiltrating secret values.',
      });
    }

    return findings;
  }
}
