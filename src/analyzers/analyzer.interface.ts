import type { AnalysisContext, AnalyzerResult } from '../core/types.js';

/**
 * Contract for all security analyzers.
 *
 * Each analyzer is a self-contained strategy that examines a specific
 * security concern. Analyzers are registered with the engine and executed
 * in parallel during analysis.
 *
 * To add a new analyzer:
 * 1. Create a new directory under src/analyzers/
 * 2. Implement this interface
 * 3. Register it in analyzer.registry.ts
 *
 * No existing code needs to change (Open/Closed Principle).
 */
export interface Analyzer {
  /** Unique identifier for this analyzer (e.g., "vulnerability-scanner") */
  readonly name: string;

  /** Human-readable description shown in reports */
  readonly description: string;

  /**
   * Analyze a package and return findings.
   *
   * Implementations must:
   * - Never throw — catch errors and return empty findings with a warning
   * - Never execute code from the analyzed package
   * - Be stateless — no side effects between calls
   * - Return duration in milliseconds
   */
  analyze(context: AnalysisContext): Promise<AnalyzerResult>;
}
