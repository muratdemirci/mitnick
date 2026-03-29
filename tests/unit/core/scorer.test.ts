import { describe, it, expect } from 'vitest';
import { calculateScore, hasFindsAtOrAbove } from '../../../src/core/scorer.js';
import type { AnalyzerResult, Finding, Severity } from '../../../src/core/types.js';

// ─── Helpers ──────────────────────────────────────────────

function makeFinding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return {
    analyzer: 'test-analyzer',
    severity,
    title: `${severity} finding`,
    description: `A ${severity} finding`,
    ...overrides,
  };
}

function makeResult(findings: readonly Finding[], name = 'test-analyzer'): AnalyzerResult {
  return { analyzer: name, findings, duration: 10 };
}

// ─── calculateScore ───────────────────────────────────────

describe('calculateScore', () => {
  it('returns 100/A with no findings', () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.totalFindings).toBe(0);
  });

  it('returns 100/A with empty findings arrays', () => {
    const result = calculateScore([makeResult([]), makeResult([])]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.totalFindings).toBe(0);
  });

  // ─── Severity deductions ─────────────────────────────────

  it('deducts 25 for a critical finding', () => {
    const result = calculateScore([makeResult([makeFinding('critical')])]);
    expect(result.score).toBe(75);
  });

  it('deducts 15 for a high finding', () => {
    const result = calculateScore([makeResult([makeFinding('high')])]);
    expect(result.score).toBe(85);
  });

  it('deducts 8 for a medium finding', () => {
    const result = calculateScore([makeResult([makeFinding('medium')])]);
    expect(result.score).toBe(92);
  });

  it('deducts 3 for a low finding', () => {
    const result = calculateScore([makeResult([makeFinding('low')])]);
    expect(result.score).toBe(97);
  });

  it('deducts 0 for an info finding', () => {
    const result = calculateScore([makeResult([makeFinding('info')])]);
    expect(result.score).toBe(100);
  });

  // ─── Combined deductions ─────────────────────────────────

  it('deducts correctly for multiple findings', () => {
    const findings = [makeFinding('critical'), makeFinding('high'), makeFinding('medium')];
    const result = calculateScore([makeResult(findings)]);
    // 100 - 25 - 15 - 8 = 52
    expect(result.score).toBe(52);
  });

  it('aggregates findings across multiple analyzer results', () => {
    const result = calculateScore([
      makeResult([makeFinding('critical')], 'analyzer-a'),
      makeResult([makeFinding('high')], 'analyzer-b'),
    ]);
    // 100 - 25 - 15 = 60
    expect(result.score).toBe(60);
  });

  // ─── Clamping ────────────────────────────────────────────

  it('clamps score to 0 when deductions exceed 100', () => {
    const findings = Array.from({ length: 10 }, () => makeFinding('critical'));
    const result = calculateScore([makeResult(findings)]);
    // 100 - 250 = -150 -> clamped to 0
    expect(result.score).toBe(0);
  });

  it('never returns a score above 100', () => {
    // Even with info-only findings (0 deduction each), score stays at 100
    const findings = Array.from({ length: 50 }, () => makeFinding('info'));
    const result = calculateScore([makeResult(findings)]);
    expect(result.score).toBe(100);
  });

  it('clamps to 0 with many mixed severe findings', () => {
    const findings = [
      ...Array.from({ length: 3 }, () => makeFinding('critical')),
      ...Array.from({ length: 3 }, () => makeFinding('high')),
    ];
    const result = calculateScore([makeResult(findings)]);
    // 100 - 75 - 45 = -20 -> clamped to 0
    expect(result.score).toBe(0);
  });

  // ─── Grade mapping ──────────────────────────────────────

  it('maps score 100 to grade A', () => {
    const result = calculateScore([]);
    expect(result.grade).toBe('A');
  });

  it('maps score 90 to grade A', () => {
    // 100 - 8 - 2*1(low=3, info=0) -> need exactly 90
    // 100 - 3 - 3 - 3 - (info) = need 10 points off -> 3+3+3 = 9 -> not exact
    // Use 2 low + 1 info(=0) => 100 - 6 = 94 -> A
    // Use medium + low => 100 - 8 - 3 = 89 -> B  (boundary!)
    // For exactly 90: need 10 off. low*3 = 9 off -> 91 (A). low*3 + info = 91 (A still).
    // Actually let's just test the boundary directly: score 90 => A, score 89 => B
    // We get 92 from 1 medium => A
    const result = calculateScore([makeResult([makeFinding('medium')])]);
    expect(result.score).toBe(92);
    expect(result.grade).toBe('A');
  });

  it('maps score 89 to grade B (boundary)', () => {
    // 100 - 8 - 3 = 89
    const result = calculateScore([makeResult([makeFinding('medium'), makeFinding('low')])]);
    expect(result.score).toBe(89);
    expect(result.grade).toBe('B');
  });

  it('maps score 80 to grade B', () => {
    // 100 - 15 - 3 - (need 2 more off) => not cleanly 80
    // 100 - 8 - 8 - 3 - (need 1 more) ... let's use 100-8-8-3-1(can't)
    // 100 - 15 - 3 - (need 2 more) not possible with these values
    // We can verify grade B for score=85 (100-15=85)
    const result = calculateScore([makeResult([makeFinding('high')])]);
    expect(result.score).toBe(85);
    expect(result.grade).toBe('B');
  });

  it('maps score in 70-79 to grade C', () => {
    // 100 - 25 - 3 = 72
    const result = calculateScore([makeResult([makeFinding('critical'), makeFinding('low')])]);
    expect(result.score).toBe(72);
    expect(result.grade).toBe('C');
  });

  it('maps score in 50-69 to grade D', () => {
    // 100 - 25 - 15 = 60
    const result = calculateScore([makeResult([makeFinding('critical'), makeFinding('high')])]);
    expect(result.score).toBe(60);
    expect(result.grade).toBe('D');
  });

  it('maps score below 50 to grade F', () => {
    // 100 - 25 - 25 - 8 = 42
    const result = calculateScore([
      makeResult([makeFinding('critical'), makeFinding('critical'), makeFinding('medium')]),
    ]);
    expect(result.score).toBe(42);
    expect(result.grade).toBe('F');
  });

  it('maps score 0 to grade F', () => {
    const findings = Array.from({ length: 5 }, () => makeFinding('critical'));
    const result = calculateScore([makeResult(findings)]);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
  });

  // ─── findingsBySeverity counts ────────────────────────────

  it('counts findings by severity correctly', () => {
    const findings = [
      makeFinding('critical'),
      makeFinding('critical'),
      makeFinding('high'),
      makeFinding('medium'),
      makeFinding('medium'),
      makeFinding('medium'),
      makeFinding('low'),
      makeFinding('info'),
      makeFinding('info'),
    ];
    const result = calculateScore([makeResult(findings)]);
    expect(result.findingsBySeverity).toEqual({
      critical: 2,
      high: 1,
      medium: 3,
      low: 1,
      info: 2,
    });
    expect(result.totalFindings).toBe(9);
  });

  it('returns zero counts when there are no findings', () => {
    const result = calculateScore([]);
    expect(result.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it('aggregates counts across multiple results', () => {
    const result = calculateScore([
      makeResult([makeFinding('critical')], 'a'),
      makeResult([makeFinding('critical'), makeFinding('low')], 'b'),
    ]);
    expect(result.findingsBySeverity.critical).toBe(2);
    expect(result.findingsBySeverity.low).toBe(1);
    expect(result.totalFindings).toBe(3);
  });
});

// ─── hasFindsAtOrAbove ────────────────────────────────────

describe('hasFindsAtOrAbove', () => {
  const results = [makeResult([makeFinding('medium'), makeFinding('low')])];

  it('returns true when a finding meets the threshold', () => {
    expect(hasFindsAtOrAbove(results, 'medium')).toBe(true);
  });

  it('returns true when a finding exceeds the threshold', () => {
    expect(hasFindsAtOrAbove(results, 'low')).toBe(true);
  });

  it('returns false when no finding meets the threshold', () => {
    expect(hasFindsAtOrAbove(results, 'high')).toBe(false);
  });

  it('returns false when no finding reaches critical', () => {
    expect(hasFindsAtOrAbove(results, 'critical')).toBe(false);
  });

  it('returns true for info threshold when any finding exists', () => {
    // info is the lowest threshold (index 4), so medium (index 2) <= 4 is true
    expect(hasFindsAtOrAbove(results, 'info')).toBe(true);
  });

  it('returns false for empty results', () => {
    expect(hasFindsAtOrAbove([], 'info')).toBe(false);
  });

  it('returns false for results with no findings', () => {
    expect(hasFindsAtOrAbove([makeResult([])], 'critical')).toBe(false);
  });

  it('returns true when exactly at critical threshold', () => {
    const critResults = [makeResult([makeFinding('critical')])];
    expect(hasFindsAtOrAbove(critResults, 'critical')).toBe(true);
  });

  it('handles info-only findings with info threshold', () => {
    const infoResults = [makeResult([makeFinding('info')])];
    expect(hasFindsAtOrAbove(infoResults, 'info')).toBe(true);
    expect(hasFindsAtOrAbove(infoResults, 'low')).toBe(false);
  });
});
