/**
 * Terminal formatter — beautiful human-readable output using chalk.
 *
 * Displays analyzer results with status icons, a findings table
 * sorted by severity, the overall score with color coding, and duration.
 */

import chalk from 'chalk';
import type { Formatter } from './formatter.interface.js';
import {
  SEVERITY_ORDER,
  type AnalyzerResult,
  type Finding,
  type Grade,
  type SecurityReport,
  type Severity,
} from '../../core/types.js';

// ─── Constants ───────────────────────────────────────────

const SEVERITY_COLORS: Readonly<Record<Severity, (text: string) => string>> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const GRADE_COLORS: Readonly<Record<Grade, (text: string) => string>> = {
  A: chalk.green.bold,
  B: chalk.green,
  C: chalk.yellow,
  D: chalk.red,
  F: chalk.red.bold,
};

const CHECK_MARK = chalk.green('\u2713');
const CROSS_MARK = chalk.red('\u2717');

// ─── Helpers ─────────────────────────────────────────────

function padRight(text: string, width: number): string {
  return text.length >= width ? text : text + ' '.repeat(width - text.length);
}

function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatAnalyzerLine(result: AnalyzerResult): string {
  const icon = result.findings.length > 0 ? CROSS_MARK : CHECK_MARK;
  const name = padRight(result.analyzer, 28);
  const count = result.findings.length;
  const suffix = count === 1 ? 'finding' : 'findings';
  const countText = count > 0 ? chalk.yellow(`${count} ${suffix}`) : chalk.gray(`0 ${suffix}`);

  return `  ${icon} ${name} ${countText}`;
}

function sortFindingsBySeverity(findings: readonly Finding[]): readonly Finding[] {
  return [...findings].sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.severity];
    const orderB = SEVERITY_ORDER[b.severity];
    return orderA - orderB;
  });
}

function buildFindingsTable(findings: readonly Finding[]): string {
  if (findings.length === 0) {
    return `\n  ${chalk.green('No findings — package looks clean!')}\n`;
  }

  const sorted = sortFindingsBySeverity(findings);

  // Calculate column widths
  const sevWidth = 10;
  const analyzerWidth = Math.max(10, ...sorted.map((f) => f.analyzer.length)) + 2;
  const titleWidth = Math.max(20, ...sorted.map((f) => f.title.length));

  const headerSev = padRight('Severity', sevWidth);
  const headerAnalyzer = padRight('Analyzer', analyzerWidth);
  const headerFinding = padRight('Finding', titleWidth);

  const dividerSev = '\u2500'.repeat(sevWidth);
  const dividerAnalyzer = '\u2500'.repeat(analyzerWidth);
  const dividerFinding = '\u2500'.repeat(titleWidth);

  const lines: string[] = [];
  lines.push('');
  lines.push(
    `  \u250c${'\u2500'.repeat(sevWidth + 1)}\u252c${'\u2500'.repeat(analyzerWidth + 1)}\u252c${'\u2500'.repeat(titleWidth + 1)}\u2510`,
  );
  lines.push(
    `  \u2502 ${chalk.bold(headerSev)}\u2502 ${chalk.bold(headerAnalyzer)}\u2502 ${chalk.bold(headerFinding)}\u2502`,
  );
  lines.push(
    `  \u251c${dividerSev}\u2500\u253c${dividerAnalyzer}\u2500\u253c${dividerFinding}\u2500\u2524`,
  );

  for (const finding of sorted) {
    const sevLabel = finding.severity.toUpperCase();
    const colorize = SEVERITY_COLORS[finding.severity];
    const sevCell = padRight(
      colorize(sevLabel),
      sevWidth + (colorize(sevLabel).length - sevLabel.length),
    );
    const analyzerCell = padRight(finding.analyzer, analyzerWidth);
    const titleCell = padRight(finding.title, titleWidth);

    lines.push(`  \u2502 ${sevCell}\u2502 ${analyzerCell}\u2502 ${titleCell}\u2502`);
  }

  lines.push(
    `  \u2514${'\u2500'.repeat(sevWidth + 1)}\u2534${'\u2500'.repeat(analyzerWidth + 1)}\u2534${'\u2500'.repeat(titleWidth + 1)}\u2518`,
  );

  return lines.join('\n');
}

// ─── Formatter ───────────────────────────────────────────

export class TerminalFormatter implements Formatter {
  readonly name = 'terminal' as const;

  format(report: SecurityReport): string {
    const lines: string[] = [];

    // Header
    lines.push('');
    lines.push(`  ${chalk.bold.cyan('mitnick')} — Security Analysis`);
    lines.push('');
    lines.push(`  Checking ${chalk.bold(`${report.packageName}@${report.version}`)}...`);
    lines.push('');

    // Analyzer results
    for (const result of report.results) {
      lines.push(formatAnalyzerLine(result));
    }

    // Score
    const gradeColor = GRADE_COLORS[report.grade];
    lines.push('');
    lines.push(`  Score: ${gradeColor(`${report.score}/100`)} (${gradeColor(report.grade)})`);

    // Findings table
    const allFindings = report.results.flatMap((r) => r.findings);
    lines.push(buildFindingsTable(allFindings));

    // Duration
    lines.push(`  Analyzed in ${formatDuration(report.duration)}`);
    lines.push('');

    return lines.join('\n');
  }
}
