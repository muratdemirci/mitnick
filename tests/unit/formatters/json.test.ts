import { describe, it, expect } from 'vitest';
import { JsonFormatter } from '../../../src/cli/formatters/json.js';
import type { SecurityReport } from '../../../src/core/types.js';

// ─── Fixtures ─────────────────────────────────────────────

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    packageName: 'test-pkg',
    version: '1.0.0',
    score: 92,
    grade: 'A',
    results: [
      {
        analyzer: 'test-analyzer',
        findings: [
          {
            analyzer: 'test-analyzer',
            severity: 'medium',
            title: 'Something found',
            description: 'A medium issue',
            file: 'index.js',
            line: 42,
            recommendation: 'Fix it',
          },
        ],
        duration: 15,
      },
    ],
    totalFindings: 1,
    findingsBySeverity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
    analyzedAt: '2024-01-15T10:00:00.000Z',
    duration: 250,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────

describe('JsonFormatter', () => {
  const formatter = new JsonFormatter();

  it('has the name "json"', () => {
    expect(formatter.name).toBe('json');
  });

  it('produces valid JSON', () => {
    const output = formatter.format(makeReport());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('produces pretty-printed JSON (indented with 2 spaces)', () => {
    const output = formatter.format(makeReport());
    // Pretty-printed JSON has newlines and indentation
    expect(output).toContain('\n');
    expect(output).toContain('  ');
  });

  it('includes all top-level report fields', () => {
    const report = makeReport();
    const output = formatter.format(report);
    const parsed = JSON.parse(output);

    expect(parsed.packageName).toBe('test-pkg');
    expect(parsed.version).toBe('1.0.0');
    expect(parsed.score).toBe(92);
    expect(parsed.grade).toBe('A');
    expect(parsed.totalFindings).toBe(1);
    expect(parsed.analyzedAt).toBe('2024-01-15T10:00:00.000Z');
    expect(parsed.duration).toBe(250);
  });

  it('includes findingsBySeverity with all severity levels', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      medium: 1,
      low: 0,
      info: 0,
    });
  });

  it('includes results array with analyzer details', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.results).toHaveLength(1);
    expect(parsed.results[0].analyzer).toBe('test-analyzer');
    expect(parsed.results[0].duration).toBe(15);
  });

  it('includes findings with all fields', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    const finding = parsed.results[0].findings[0];
    expect(finding.analyzer).toBe('test-analyzer');
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBe('Something found');
    expect(finding.description).toBe('A medium issue');
    expect(finding.file).toBe('index.js');
    expect(finding.line).toBe(42);
    expect(finding.recommendation).toBe('Fix it');
  });

  it('produces correct output for empty findings', () => {
    const report = makeReport({
      results: [],
      totalFindings: 0,
      score: 100,
      grade: 'A',
      findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });
    const output = formatter.format(report);
    const parsed = JSON.parse(output);

    expect(parsed.results).toEqual([]);
    expect(parsed.totalFindings).toBe(0);
    expect(parsed.score).toBe(100);
  });

  it('round-trips the report — parsed output matches input', () => {
    const report = makeReport();
    const output = formatter.format(report);
    const parsed = JSON.parse(output);

    // Deep equality (the formatter should faithfully serialize the report)
    expect(parsed).toEqual(report);
  });

  it('handles multiple results with multiple findings', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'a1',
          findings: [{ analyzer: 'a1', severity: 'critical', title: 't1', description: 'd1' }],
          duration: 10,
        },
        {
          analyzer: 'a2',
          findings: [
            { analyzer: 'a2', severity: 'low', title: 't2', description: 'd2' },
            { analyzer: 'a2', severity: 'info', title: 't3', description: 'd3' },
          ],
          duration: 5,
        },
      ],
      totalFindings: 3,
    });

    const output = formatter.format(report);
    const parsed = JSON.parse(output);

    expect(parsed.results).toHaveLength(2);
    expect(parsed.results[0].findings).toHaveLength(1);
    expect(parsed.results[1].findings).toHaveLength(2);
  });
});
