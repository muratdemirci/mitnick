import { describe, it, expect } from 'vitest';
import { TerminalFormatter } from '../../../src/cli/formatters/terminal.js';
import type { SecurityReport } from '../../../src/core/types.js';

// ─── Fixtures ─────────────────────────────────────────────

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    packageName: 'test-pkg',
    version: '1.0.0',
    score: 100,
    grade: 'A',
    results: [],
    totalFindings: 0,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    analyzedAt: '2024-01-01T00:00:00.000Z',
    duration: 150,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────

describe('TerminalFormatter', () => {
  const formatter = new TerminalFormatter();

  it('has the name "terminal"', () => {
    expect(formatter.name).toBe('terminal');
  });

  it('produces output containing package name and version', () => {
    const output = formatter.format(makeReport());
    expect(output).toContain('test-pkg');
    expect(output).toContain('1.0.0');
  });

  it('produces output containing the score', () => {
    const output = formatter.format(makeReport({ score: 85, grade: 'B' }));
    expect(output).toContain('85');
    expect(output).toContain('100');
  });

  it('produces output containing the grade', () => {
    const output = formatter.format(makeReport({ score: 85, grade: 'B' }));
    expect(output).toContain('B');
  });

  it('shows "mitnick" header', () => {
    const output = formatter.format(makeReport());
    expect(output).toContain('mitnick');
  });

  it('shows duration', () => {
    const output = formatter.format(makeReport({ duration: 150 }));
    expect(output).toContain('150ms');
  });

  it('formats duration in seconds when >= 1000ms', () => {
    const output = formatter.format(makeReport({ duration: 2500 }));
    expect(output).toContain('2.5s');
  });

  it('shows "No findings" message when there are no findings', () => {
    const output = formatter.format(makeReport());
    expect(output).toContain('No findings');
  });

  it('shows analyzer results with check marks for clean analyzers', () => {
    const report = makeReport({
      results: [{ analyzer: 'vulnerability-scanner', findings: [], duration: 10 }],
    });
    const output = formatter.format(report);
    expect(output).toContain('vulnerability-scanner');
    // Check mark character
    expect(output).toContain('\u2713');
  });

  it('shows analyzer results with cross marks for analyzers with findings', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'code-scanner',
          findings: [
            {
              analyzer: 'code-scanner',
              severity: 'high',
              title: 'eval() usage',
              description: 'Dangerous eval',
            },
          ],
          duration: 10,
        },
      ],
      totalFindings: 1,
      findingsBySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      score: 85,
      grade: 'B',
    });
    const output = formatter.format(report);
    expect(output).toContain('\u2717');
    expect(output).toContain('1 finding');
  });

  it('shows plural "findings" for count > 1', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'code-scanner',
          findings: [
            { analyzer: 'code-scanner', severity: 'high', title: 'f1', description: 'd1' },
            { analyzer: 'code-scanner', severity: 'low', title: 'f2', description: 'd2' },
          ],
          duration: 10,
        },
      ],
      totalFindings: 2,
      score: 82,
      grade: 'B',
    });
    const output = formatter.format(report);
    expect(output).toContain('2 findings');
  });

  it('displays findings table with severity, analyzer, and title', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'test-analyzer',
          findings: [
            {
              analyzer: 'test-analyzer',
              severity: 'critical',
              title: 'Command injection',
              description: 'desc',
            },
          ],
          duration: 5,
        },
      ],
      totalFindings: 1,
      score: 75,
      grade: 'C',
    });
    const output = formatter.format(report);
    expect(output).toContain('CRITICAL');
    expect(output).toContain('test-analyzer');
    expect(output).toContain('Command injection');
  });

  it('sorts findings by severity in the table (critical first)', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            { analyzer: 'scanner', severity: 'low', title: 'Low issue', description: 'd' },
            {
              analyzer: 'scanner',
              severity: 'critical',
              title: 'Critical issue',
              description: 'd',
            },
            { analyzer: 'scanner', severity: 'medium', title: 'Medium issue', description: 'd' },
          ],
          duration: 5,
        },
      ],
      totalFindings: 3,
      score: 64,
      grade: 'D',
    });
    const output = formatter.format(report);
    const criticalPos = output.indexOf('CRITICAL');
    const mediumPos = output.indexOf('MEDIUM');
    const lowPos = output.indexOf('LOW');

    expect(criticalPos).toBeLessThan(mediumPos);
    expect(mediumPos).toBeLessThan(lowPos);
  });

  it('handles all grades (A through F)', () => {
    const grades = ['A', 'B', 'C', 'D', 'F'] as const;
    const scores = [95, 85, 75, 55, 30] as const;

    for (let i = 0; i < grades.length; i++) {
      const output = formatter.format(makeReport({ score: scores[i], grade: grades[i] }));
      expect(output).toContain(String(scores[i]));
      // The grade letter should appear in the output
      expect(output).toContain(grades[i]!);
    }
  });

  it('returns a non-empty string', () => {
    const output = formatter.format(makeReport());
    expect(typeof output).toBe('string');
    expect(output.length).toBeGreaterThan(0);
  });
});
