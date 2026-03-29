/**
 * Install Script Analyzer — detects lifecycle scripts in package.json
 * and analyzes their contents for suspicious patterns.
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding, Severity } from '../../core/types.js';
import { truncate } from '../../utils/strings.js';
import { logger } from '../../utils/logger.js';

// ─── Constants ────────────────────────────────────────────

const LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'postuninstall',
] as const;

type LifecycleHook = (typeof LIFECYCLE_HOOKS)[number];

interface SuspiciousPattern {
  readonly pattern: RegExp;
  readonly label: string;
  readonly severity: Severity;
}

const SUSPICIOUS_PATTERNS: readonly SuspiciousPattern[] = [
  { pattern: /\bcurl\b/i, label: 'curl command (network download)', severity: 'critical' },
  { pattern: /\bwget\b/i, label: 'wget command (network download)', severity: 'critical' },
  { pattern: /\beval\b/, label: 'eval usage (dynamic code execution)', severity: 'critical' },
  {
    pattern: /\bnew\s+Function\b/,
    label: 'new Function() (dynamic code creation)',
    severity: 'critical',
  },
  {
    pattern: /\b(base64|atob|btoa|Buffer\.from)\b/,
    label: 'encoded string handling',
    severity: 'critical',
  },
  {
    pattern: /\b(sh|bash|cmd|powershell|pwsh)\s+-c\b/,
    label: 'shell spawning',
    severity: 'critical',
  },
  {
    pattern: /\bchild_process\b/,
    label: 'child_process usage (subprocess spawning)',
    severity: 'critical',
  },
  {
    pattern: /\b(exec|execSync|spawn|spawnSync|execFile)\b/,
    label: 'process execution',
    severity: 'critical',
  },
  {
    pattern: /process\.env/,
    label: 'environment variable access',
    severity: 'high',
  },
  {
    pattern: /\$\{?\w*HOME\b|\$\{?\w*USER\b|\$\{?\w*PATH\b/,
    label: 'environment variable reference',
    severity: 'high',
  },
  {
    pattern: /https?:\/\/[^\s"']+/,
    label: 'hardcoded URL',
    severity: 'high',
  },
  {
    pattern: /\brm\s+-rf\b/,
    label: 'recursive file deletion',
    severity: 'high',
  },
] as const;

// ─── Analyzer ─────────────────────────────────────────────

export class InstallScriptAnalyzer implements Analyzer {
  readonly name = 'install-scripts';
  readonly description =
    'Detects lifecycle scripts and analyzes their contents for suspicious patterns';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const scripts = context.packageJson['scripts'];
      if (scripts === null || scripts === undefined || typeof scripts !== 'object') {
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      const scriptsRecord = scripts as Readonly<Record<string, unknown>>;

      for (const hook of LIFECYCLE_HOOKS) {
        const scriptValue = scriptsRecord[hook];
        if (typeof scriptValue !== 'string') continue;

        const scriptContent = scriptValue;

        // Flag presence of any lifecycle hook
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: `Lifecycle script detected: ${hook}`,
          description: `The package defines a "${hook}" script: "${truncate(scriptContent, 120)}"`,
          recommendation:
            'Review the script carefully before installing. Consider using --ignore-scripts flag.',
        });

        // Analyze content for suspicious patterns
        const suspiciousMatches = this.detectSuspiciousPatterns(scriptContent, hook);
        findings.push(...suspiciousMatches);
      }
    } catch (error: unknown) {
      logger.warn(
        `[${this.name}] Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    return Promise.resolve({
      analyzer: this.name,
      findings,
      duration: performance.now() - start,
    });
  }

  private detectSuspiciousPatterns(script: string, hook: LifecycleHook): readonly Finding[] {
    const findings: Finding[] = [];

    for (const { pattern, label, severity } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(script)) {
        findings.push({
          analyzer: this.name,
          severity: severity === 'critical' ? 'critical' : 'high',
          title: `Suspicious content in ${hook}: ${label}`,
          description: `The "${hook}" script contains ${label}. Script: "${truncate(script, 200)}"`,
          recommendation:
            'Inspect the script manually. This pattern is commonly seen in malicious packages.',
        });
      }
    }

    return findings;
  }
}
