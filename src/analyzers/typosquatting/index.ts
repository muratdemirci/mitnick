/**
 * Typosquatting Analyzer — detects package names that are suspiciously
 * similar to popular npm packages via Levenshtein distance and common
 * character substitutions.
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding, Severity } from '../../core/types.js';
import { POPULAR_PACKAGES } from './popular-packages.js';
import { logger } from '../../utils/logger.js';

// ─── Substitution pairs ──────────────────────────────────

interface SubstitutionRule {
  readonly from: string;
  readonly to: string;
}

/** Common character substitutions used in typosquatting. */
const SUBSTITUTIONS: readonly SubstitutionRule[] = [
  { from: '0', to: 'o' },
  { from: 'o', to: '0' },
  { from: '1', to: 'l' },
  { from: 'l', to: '1' },
  { from: 'rn', to: 'm' },
  { from: 'm', to: 'rn' },
  { from: '-', to: '_' },
  { from: '_', to: '-' },
];

// ─── Levenshtein ──────────────────────────────────────────

function levenshteinDistance(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;

  if (la === 0) return lb;
  if (lb === 0) return la;

  // Use two-row approach for memory efficiency
  let previousRow: number[] = Array.from({ length: lb + 1 }, (_, i) => i);
  let currentRow: number[] = new Array<number>(lb + 1);

  for (let i = 1; i <= la; i++) {
    currentRow[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const deletion = (previousRow[j] ?? 0) + 1;
      const insertion = (currentRow[j - 1] ?? 0) + 1;
      const substitution = (previousRow[j - 1] ?? 0) + cost;
      currentRow[j] = Math.min(deletion, insertion, substitution);
    }
    [previousRow, currentRow] = [currentRow, previousRow];
  }

  return previousRow[lb] ?? la;
}

// ─── Substitution check ──────────────────────────────────

function applySubstitutions(name: string): readonly string[] {
  const variants: string[] = [];

  for (const { from, to } of SUBSTITUTIONS) {
    let idx = name.indexOf(from);
    while (idx !== -1) {
      const variant = name.slice(0, idx) + to + name.slice(idx + from.length);
      variants.push(variant);
      idx = name.indexOf(from, idx + 1);
    }
  }

  return variants;
}

// ─── Analyzer ─────────────────────────────────────────────

export class TyposquattingAnalyzer implements Analyzer {
  readonly name = 'typosquatting';
  readonly description = 'Detects package names that may be typosquatting popular npm packages';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const packageName = context.packageName;

      // Skip scoped packages — they can't easily typosquat unscoped ones
      // and skip if the name exactly matches a popular package
      const normalizedName = packageName.replace(/^@[^/]+\//, '');

      if (POPULAR_PACKAGES.includes(normalizedName)) {
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      // Check Levenshtein distance against all popular packages
      const alreadyFlagged = new Set<string>();

      for (const popular of POPULAR_PACKAGES) {
        // Skip packages with very different lengths (distance would be too high)
        if (Math.abs(normalizedName.length - popular.length) > 2) continue;

        const distance = levenshteinDistance(normalizedName, popular);

        if (distance === 1) {
          findings.push(this.createFinding(normalizedName, popular, 'high', distance));
          alreadyFlagged.add(popular);
        } else if (distance === 2) {
          findings.push(this.createFinding(normalizedName, popular, 'medium', distance));
          alreadyFlagged.add(popular);
        }
      }

      // Check common character substitutions
      const variants = applySubstitutions(normalizedName);
      for (const variant of variants) {
        if (POPULAR_PACKAGES.includes(variant) && !alreadyFlagged.has(variant)) {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: `Possible typosquat of "${variant}"`,
            description:
              `Package name "${normalizedName}" uses a common character substitution ` +
              `that makes it look like the popular package "${variant}".`,
            recommendation: `Verify you intended to install "${normalizedName}" and not "${variant}".`,
          });
          alreadyFlagged.add(variant);
        }
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

  private createFinding(
    name: string,
    popular: string,
    severity: Severity,
    distance: number,
  ): Finding {
    return {
      analyzer: this.name,
      severity,
      title: `Possible typosquat of "${popular}" (distance: ${distance})`,
      description:
        `Package name "${name}" has a Levenshtein distance of ${distance} from ` +
        `the popular package "${popular}" (potential typosquatting).`,
      recommendation: `Verify you intended to install "${name}" and not "${popular}".`,
    };
  }
}
