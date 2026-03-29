/**
 * Core type definitions for the Mitnick security analysis engine.
 *
 * All types use readonly properties and discriminated unions
 * to enforce immutability and type safety throughout the system.
 */

// ─── Severity ──────────────────────────────────────────────

export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;

export type Severity = (typeof SEVERITY_LEVELS)[number];

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
} as const;

export const SEVERITY_DEDUCTIONS: Readonly<Record<Severity, number>> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
} as const;

// ─── Grade ─────────────────────────────────────────────────

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export const GRADE_THRESHOLDS: readonly { readonly min: number; readonly grade: Grade }[] = [
  { min: 90, grade: 'A' },
  { min: 80, grade: 'B' },
  { min: 70, grade: 'C' },
  { min: 50, grade: 'D' },
  { min: 0, grade: 'F' },
] as const;

// ─── Finding ───────────────────────────────────────────────

export interface Finding {
  readonly analyzer: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly file?: string;
  readonly line?: number;
  readonly recommendation?: string;
}

// ─── Analyzer Result ───────────────────────────────────────

export interface AnalyzerResult {
  readonly analyzer: string;
  readonly findings: readonly Finding[];
  readonly duration: number;
}

// ─── Registry Metadata ─────────────────────────────────────

export interface MaintainerInfo {
  readonly name: string;
  readonly email?: string;
}

export interface RegistryMetadata {
  readonly name: string;
  readonly version: string;
  readonly description?: string;
  readonly license?: string;
  readonly maintainers: readonly MaintainerInfo[];
  readonly publishedAt?: string;
  readonly versions: readonly string[];
  readonly timeMap: Readonly<Record<string, string>>;
  readonly distTags: Readonly<Record<string, string>>;
  readonly homepage?: string;
  readonly repository?: string;
}

// ─── Analysis Context ──────────────────────────────────────

export interface AnalysisContext {
  readonly packageName: string;
  readonly version: string;
  readonly packageJson: Readonly<Record<string, unknown>>;
  readonly extractedPath: string;
  readonly registryMetadata: RegistryMetadata;
}

// ─── Security Report ───────────────────────────────────────

export interface SecurityReport {
  readonly packageName: string;
  readonly version: string;
  readonly score: number;
  readonly grade: Grade;
  readonly results: readonly AnalyzerResult[];
  readonly totalFindings: number;
  readonly findingsBySeverity: Readonly<Record<Severity, number>>;
  readonly analyzedAt: string;
  readonly duration: number;
}

// ─── CLI Options ───────────────────────────────────────────

export type OutputFormat = 'terminal' | 'json' | 'sarif';

export interface CheckOptions {
  readonly packages: readonly string[];
  readonly format: OutputFormat;
  readonly failOn?: Severity;
  readonly verbose: boolean;
}

// ─── Parsed Package Specifier ──────────────────────────────

export interface PackageSpecifier {
  readonly name: string;
  readonly version?: string;
}
