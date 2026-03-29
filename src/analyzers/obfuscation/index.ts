/**
 * Obfuscation Analyzer — detects obfuscated code via entropy analysis,
 * eval/Function patterns, base64 blobs, and hex-encoded strings.
 */

import type { AnalysisContext, AnalyzerResult, Finding } from '../../core/types.js';
import {
  parseSource,
  walkAST,
  extractStringLiterals,
  getNodeLine,
  isCallTo,
  optionalLine,
} from '../../utils/ast.js';
import { FileBasedAnalyzer } from '../file-based-analyzer.js';

// ─── Constants ────────────────────────────────────────────

const ENTROPY_THRESHOLD = 4.5;
const MIN_STRING_LENGTH_FOR_ENTROPY = 20;
const BASE64_MIN_LENGTH = 256;
const BASE64_PATTERN = /^[A-Za-z0-9+/=]{256,}$/;
const HEX_ENCODED_PATTERN = /(\\x[0-9a-fA-F]{2}){8,}/;

// ─── Helpers ──────────────────────────────────────────────

function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

// ─── Analyzer ─────────────────────────────────────────────

export class ObfuscationAnalyzer extends FileBasedAnalyzer {
  readonly name = 'obfuscation';
  readonly description = 'Detects obfuscated code using entropy analysis and pattern matching';

  async analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const result = await super.analyze(context);

    // Escalate if both eval and obfuscation signals are present in the same package
    const escalation = this.escalateEvalPlusObfuscation(result.findings);

    return {
      ...result,
      findings: [...result.findings, ...escalation],
    };
  }

  protected analyzeFile(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    findings.push(...this.detectDynamicExecution(source, relPath));
    findings.push(...this.detectBufferBase64(source, relPath));
    findings.push(...this.detectHighEntropyStrings(source, relPath));
    findings.push(...this.detectHexEncoded(source, relPath));
    findings.push(...this.detectBase64Blobs(source, relPath));

    return findings;
  }

  private detectDynamicExecution(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (isCallTo(node, 'eval')) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: 'eval() detected',
          description:
            'Use of eval() can execute arbitrary code and is a common obfuscation technique.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Review the eval() usage and consider replacing with safer alternatives.',
        });
      }

      if (
        node.type === 'NewExpression' &&
        typeof node['callee'] === 'object' &&
        node['callee'] !== null &&
        (node['callee'] as Record<string, unknown>)['type'] === 'Identifier' &&
        (node['callee'] as Record<string, unknown>)['name'] === 'Function'
      ) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: 'new Function() detected',
          description:
            'new Function() dynamically creates code from strings, commonly used for obfuscation.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Review the dynamic function creation and ensure it is not malicious.',
        });
      }
    });

    return findings;
  }

  private detectBufferBase64(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (node.type !== 'CallExpression') return;

      const callee = node['callee'];
      if (typeof callee !== 'object' || callee === null) return;

      const calleeNode = callee as Record<string, unknown>;
      if (calleeNode['type'] !== 'MemberExpression') return;

      const obj = calleeNode['object'] as Record<string, unknown> | undefined;
      const prop = calleeNode['property'] as Record<string, unknown> | undefined;

      if (
        obj?.['type'] === 'Identifier' &&
        obj['name'] === 'Buffer' &&
        prop?.['type'] === 'Identifier' &&
        prop['name'] === 'from'
      ) {
        const args = node['arguments'];
        if (Array.isArray(args) && args.length >= 2) {
          const encodingArg = args[1] as Record<string, unknown> | undefined;
          if (encodingArg?.['type'] === 'Literal' && encodingArg['value'] === 'base64') {
            findings.push({
              analyzer: this.name,
              severity: 'high',
              title: 'Buffer.from() with base64 encoding',
              description:
                'Buffer.from(..., "base64") is commonly used to hide malicious payloads.',
              file: relPath,
              ...optionalLine(getNodeLine(node)),
              recommendation: 'Decode and inspect the base64 content for malicious code.',
            });
          }
        }
      }
    });

    return findings;
  }

  private detectHighEntropyStrings(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const strings = extractStringLiterals(source, relPath);

    let flagCount = 0;
    for (const str of strings) {
      if (str.length < MIN_STRING_LENGTH_FOR_ENTROPY) continue;
      const entropy = shannonEntropy(str);
      if (entropy > ENTROPY_THRESHOLD) {
        flagCount++;
        if (flagCount <= 5) {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: 'High-entropy string detected',
            description:
              `String literal with Shannon entropy ${entropy.toFixed(2)} ` +
              `(threshold: ${ENTROPY_THRESHOLD}). Length: ${str.length} chars. ` +
              `Preview: "${str.slice(0, 60)}..."`,
            file: relPath,
            recommendation:
              'High-entropy strings may indicate encoded/encrypted malicious payloads.',
          });
        }
      }
    }

    if (flagCount > 5) {
      findings.push({
        analyzer: this.name,
        severity: 'high',
        title: `${flagCount - 5} additional high-entropy strings omitted`,
        description: `File contains ${flagCount} total high-entropy strings.`,
        file: relPath,
        recommendation: 'Manual review recommended for files with many high-entropy strings.',
      });
    }

    return findings;
  }

  private detectHexEncoded(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    if (HEX_ENCODED_PATTERN.test(source)) {
      findings.push({
        analyzer: this.name,
        severity: 'high',
        title: 'Hex-encoded string sequences detected',
        description:
          'Long sequences of hex-encoded characters (\\xNN) were found, which may hide malicious content.',
        file: relPath,
        recommendation: 'Decode and inspect the hex content.',
      });
    }

    return findings;
  }

  private detectBase64Blobs(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const strings = extractStringLiterals(source, relPath);

    for (const str of strings) {
      if (str.length >= BASE64_MIN_LENGTH && BASE64_PATTERN.test(str)) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: 'Large Base64 blob detected',
          description:
            `A Base64-encoded string of ${str.length} characters was found. ` +
            `Large base64 blobs may contain hidden executable code.`,
          file: relPath,
          recommendation: 'Decode the base64 content and inspect it for malicious payloads.',
        });
        break;
      }
    }

    return findings;
  }

  private escalateEvalPlusObfuscation(findings: readonly Finding[]): Finding[] {
    const hasEval = findings.some(
      (f) => f.title.includes('eval()') || f.title.includes('new Function()'),
    );
    const hasObfuscation = findings.some(
      (f) =>
        f.title.includes('entropy') ||
        f.title.includes('Base64') ||
        f.title.includes('base64') ||
        f.title.includes('Hex-encoded'),
    );

    if (hasEval && hasObfuscation) {
      return [
        {
          analyzer: this.name,
          severity: 'critical',
          title: 'Eval combined with obfuscation signals',
          description:
            'This package contains both dynamic code execution (eval/new Function) and ' +
            'obfuscation indicators (high-entropy strings, base64, or hex encoding). ' +
            'This combination is a strong indicator of malicious intent.',
          recommendation: 'Do NOT install this package without thorough manual review.',
        },
      ];
    }

    return [];
  }
}
