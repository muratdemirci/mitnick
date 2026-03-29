/**
 * Security scoring engine.
 *
 * Pure functions that compute a security score and grade
 * from analyzer findings. No side effects.
 */

import {
  GRADE_THRESHOLDS,
  SEVERITY_DEDUCTIONS,
  SEVERITY_LEVELS,
  type AnalyzerResult,
  type Finding,
  type Grade,
  type Severity,
} from './types.js';

// ─── Score Result ────────────────────────────────────────

export interface ScoreResult {
  readonly score: number;
  readonly grade: Grade;
  readonly totalFindings: number;
  readonly findingsBySeverity: Readonly<Record<Severity, number>>;
}

// ─── Helpers ─────────────────────────────────────────────

/**
 * Collect all findings from analyzer results into a flat array.
 */
function collectFindings(results: readonly AnalyzerResult[]): readonly Finding[] {
  return results.flatMap((r) => r.findings);
}

/**
 * Count findings grouped by severity level.
 */
function countBySeverity(findings: readonly Finding[]): Readonly<Record<Severity, number>> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return counts;
}

/**
 * Compute raw score by deducting points per finding severity.
 * Clamped to [0, 100].
 */
function computeScore(findings: readonly Finding[]): number {
  let score = 100;

  for (const finding of findings) {
    score -= SEVERITY_DEDUCTIONS[finding.severity];
  }

  return Math.max(0, Math.min(100, score));
}

/**
 * Map a numeric score to a letter grade using GRADE_THRESHOLDS.
 */
function computeGrade(score: number): Grade {
  for (const threshold of GRADE_THRESHOLDS) {
    if (score >= threshold.min) {
      return threshold.grade;
    }
  }
  // GRADE_THRESHOLDS always includes min: 0, so this is unreachable.
  // Satisfy the compiler with a fallback.
  return 'F';
}

// ─── Public API ──────────────────────────────────────────

/**
 * Calculate a complete security score from analyzer results.
 *
 * - Starts at 100
 * - Deducts points per finding based on severity
 * - Clamps to [0, 100]
 * - Maps to letter grade (A/B/C/D/F)
 *
 * This is a pure function with no side effects.
 */
export function calculateScore(results: readonly AnalyzerResult[]): ScoreResult {
  const findings = collectFindings(results);
  const score = computeScore(findings);
  const grade = computeGrade(score);
  const findingsBySeverity = countBySeverity(findings);
  const totalFindings = findings.length;

  return {
    score,
    grade,
    totalFindings,
    findingsBySeverity,
  };
}

/**
 * Check whether any finding meets or exceeds the given severity threshold.
 * Used by --fail-on to determine exit code.
 */
export function hasFindsAtOrAbove(
  results: readonly AnalyzerResult[],
  threshold: Severity,
): boolean {
  const thresholdIndex = SEVERITY_LEVELS.indexOf(threshold);
  const findings = collectFindings(results);

  return findings.some((f) => SEVERITY_LEVELS.indexOf(f.severity) <= thresholdIndex);
}
