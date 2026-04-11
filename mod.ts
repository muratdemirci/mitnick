/**
 * Mitnick — Pre-install security analysis for npm packages.
 *
 * Analyze packages before installation to detect vulnerabilities,
 * malicious code, typosquatting, and supply chain attacks.
 *
 * @module
 */

export {
  // Core
  AnalysisEngine,
  calculateScore,
  hasFindsAtOrAbove,

  // Types
  SEVERITY_LEVELS,
  SEVERITY_ORDER,
  SEVERITY_DEDUCTIONS,
  GRADE_THRESHOLDS,

  // Analyzers
  createAnalyzers,

  // Registry
  fetchPackageMetadata,
  downloadAndExtract,
} from './src/index.ts';

export type {
  // Core types
  ScoreResult,

  // Types
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

  // Analyzer interface
  Analyzer,

  // Registry types
  RegistryResult,
  RegistrySuccess,
  RegistryError,
  RegistryErrorKind,
  TarballResult,
  TarballSuccess,
  TarballError,
  TarballErrorKind,
} from './src/index.ts';
