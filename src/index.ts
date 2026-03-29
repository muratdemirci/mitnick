/**
 * Mitnick — Public programmatic API.
 *
 * Provides the core analysis engine, types, and utilities
 * so consumers can use mitnick as a library, not just a CLI.
 *
 * @example
 * ```ts
 * import { AnalysisEngine, createAnalyzers, fetchPackageMetadata, downloadAndExtract } from 'mitnick';
 *
 * const result = await fetchPackageMetadata('express');
 * if (result.ok) {
 *   const tarball = await downloadAndExtract(result.tarballUrl, result.metadata.name);
 *   if (tarball.ok) {
 *     const engine = new AnalysisEngine(createAnalyzers());
 *     const report = await engine.analyze({ ... });
 *     await tarball.cleanup();
 *   }
 * }
 * ```
 */

// ─── Core ─────────────────────────────────────────────────
export { AnalysisEngine } from './core/engine.js';
export { calculateScore, hasFindsAtOrAbove } from './core/scorer.js';
export type { ScoreResult } from './core/scorer.js';

// ─── Types ────────────────────────────────────────────────
export type {
  Severity,
  Grade,
  Finding,
  AnalyzerResult,
  AnalysisContext,
  SecurityReport,
  RegistryMetadata,
  MaintainerInfo,
  PackageSpecifier,
  OutputFormat,
  CheckOptions,
} from './core/types.js';

export {
  SEVERITY_LEVELS,
  SEVERITY_ORDER,
  SEVERITY_DEDUCTIONS,
  GRADE_THRESHOLDS,
} from './core/types.js';

// ─── Analyzers ────────────────────────────────────────────
export type { Analyzer } from './analyzers/analyzer.interface.js';
export { createAnalyzers } from './analyzers/analyzer.registry.js';

// ─── Registry ─────────────────────────────────────────────
export { fetchPackageMetadata } from './registry/client.js';
export type {
  RegistryResult,
  RegistrySuccess,
  RegistryError,
  RegistryErrorKind,
} from './registry/client.js';

export { downloadAndExtract } from './registry/tarball.js';
export type {
  TarballResult,
  TarballSuccess,
  TarballError,
  TarballErrorKind,
} from './registry/tarball.js';
