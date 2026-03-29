/**
 * Analysis engine that orchestrates all security analyzers.
 *
 * Accepts analyzers via constructor injection (DI) and runs them
 * in parallel using Promise.allSettled. Individual analyzer failures
 * are caught without stopping the remaining analyzers.
 */

import type { Analyzer } from '../analyzers/analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, SecurityReport } from './types.js';
import { calculateScore } from './scorer.js';

export class AnalysisEngine {
  private readonly analyzers: readonly Analyzer[];

  constructor(analyzers: readonly Analyzer[]) {
    this.analyzers = analyzers;
  }

  /**
   * Run all registered analyzers against the given context in parallel.
   *
   * - Uses Promise.allSettled so one failure does not cancel others
   * - Failed analyzers produce an empty result with zero findings
   * - Measures total wall-clock duration
   * - Computes aggregate score via the scorer module
   */
  async analyze(context: AnalysisContext): Promise<SecurityReport> {
    const startTime = performance.now();

    const settled = await Promise.allSettled(
      this.analyzers.map((analyzer) => analyzer.analyze(context)),
    );

    const results: AnalyzerResult[] = settled.map((outcome, index) => {
      if (outcome.status === 'fulfilled') {
        return outcome.value;
      }

      // Analyzer threw — produce a graceful empty result
      const analyzer = this.analyzers[index];
      const analyzerName = analyzer?.name ?? `unknown-analyzer-${index}`;
      const errorMessage =
        outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason);

      console.error(`[mitnick] Analyzer "${analyzerName}" failed: ${errorMessage}`);

      return {
        analyzer: analyzerName,
        findings: [],
        duration: 0,
      } satisfies AnalyzerResult;
    });

    const duration = Math.round(performance.now() - startTime);
    const { score, grade, totalFindings, findingsBySeverity } = calculateScore(results);

    return {
      packageName: context.packageName,
      version: context.version,
      score,
      grade,
      results,
      totalFindings,
      findingsBySeverity,
      analyzedAt: new Date().toISOString(),
      duration,
    };
  }
}
