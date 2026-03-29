import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AnalysisEngine } from '../../../src/core/engine.js';
import type { Analyzer } from '../../../src/analyzers/analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult } from '../../../src/core/types.js';

// ─── Fixtures ─────────────────────────────────────────────

function makeContext(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    packageName: 'test-pkg',
    version: '1.0.0',
    packageJson: { name: 'test-pkg', version: '1.0.0' },
    extractedPath: '/tmp/test',
    registryMetadata: {
      name: 'test-pkg',
      version: '1.0.0',
      maintainers: [],
      versions: ['1.0.0'],
      timeMap: {},
      distTags: { latest: '1.0.0' },
    },
    ...overrides,
  };
}

function makeAnalyzer(name: string, result: AnalyzerResult): Analyzer {
  return {
    name,
    description: `${name} description`,
    analyze: vi.fn<(ctx: AnalysisContext) => Promise<AnalyzerResult>>().mockResolvedValue(result),
  };
}

function makeThrowingAnalyzer(name: string, error: Error | string): Analyzer {
  return {
    name,
    description: `${name} description`,
    analyze: vi
      .fn<(ctx: AnalysisContext) => Promise<AnalyzerResult>>()
      .mockRejectedValue(typeof error === 'string' ? new Error(error) : error),
  };
}

// ─── Tests ────────────────────────────────────────────────

describe('AnalysisEngine', () => {
  const context = makeContext();

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('runs all registered analyzers', async () => {
    const a1 = makeAnalyzer('a1', { analyzer: 'a1', findings: [], duration: 5 });
    const a2 = makeAnalyzer('a2', { analyzer: 'a2', findings: [], duration: 3 });

    const engine = new AnalysisEngine([a1, a2]);
    await engine.analyze(context);

    expect(a1.analyze).toHaveBeenCalledOnce();
    expect(a2.analyze).toHaveBeenCalledOnce();
    expect(a1.analyze).toHaveBeenCalledWith(context);
    expect(a2.analyze).toHaveBeenCalledWith(context);
  });

  it('aggregates results from all analyzers', async () => {
    const finding = {
      analyzer: 'a1',
      severity: 'high' as const,
      title: 'Test',
      description: 'Test desc',
    };
    const a1 = makeAnalyzer('a1', { analyzer: 'a1', findings: [finding], duration: 5 });
    const a2 = makeAnalyzer('a2', { analyzer: 'a2', findings: [], duration: 3 });

    const engine = new AnalysisEngine([a1, a2]);
    const report = await engine.analyze(context);

    expect(report.results).toHaveLength(2);
    expect(report.totalFindings).toBe(1);
    expect(report.findingsBySeverity.high).toBe(1);
  });

  it('handles analyzer failure gracefully — other analyzers still run', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const a1 = makeThrowingAnalyzer('failing-analyzer', 'kaboom');
    const finding = {
      analyzer: 'a2',
      severity: 'low' as const,
      title: 'found something',
      description: 'desc',
    };
    const a2 = makeAnalyzer('a2', { analyzer: 'a2', findings: [finding], duration: 7 });

    const engine = new AnalysisEngine([a1, a2]);
    const report = await engine.analyze(context);

    // The failing analyzer produces an empty result
    expect(report.results).toHaveLength(2);
    expect(report.results[0]!.analyzer).toBe('failing-analyzer');
    expect(report.results[0]!.findings).toEqual([]);
    expect(report.results[0]!.duration).toBe(0);

    // The passing analyzer still ran
    expect(report.results[1]!.findings).toHaveLength(1);
    expect(report.totalFindings).toBe(1);

    // Error was logged
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('failing-analyzer'));

    consoleSpy.mockRestore();
  });

  it('handles analyzer that throws a non-Error value', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const a1: Analyzer = {
      name: 'string-thrower',
      description: 'throws a string',
      analyze: vi
        .fn<(ctx: AnalysisContext) => Promise<AnalyzerResult>>()
        .mockRejectedValue('raw string error'),
    };

    const engine = new AnalysisEngine([a1]);
    const report = await engine.analyze(context);

    expect(report.results).toHaveLength(1);
    expect(report.results[0]!.findings).toEqual([]);
    expect(consoleSpy).toHaveBeenCalled();

    consoleSpy.mockRestore();
  });

  it('measures duration (duration >= 0)', async () => {
    const a1 = makeAnalyzer('a1', { analyzer: 'a1', findings: [], duration: 1 });
    const engine = new AnalysisEngine([a1]);
    const report = await engine.analyze(context);

    expect(report.duration).toBeTypeOf('number');
    expect(report.duration).toBeGreaterThanOrEqual(0);
  });

  it('produces correct report structure', async () => {
    const engine = new AnalysisEngine([
      makeAnalyzer('a1', { analyzer: 'a1', findings: [], duration: 1 }),
    ]);
    const report = await engine.analyze(context);

    expect(report).toMatchObject({
      packageName: 'test-pkg',
      version: '1.0.0',
      score: 100,
      grade: 'A',
      totalFindings: 0,
    });
    expect(report.analyzedAt).toBeTruthy();
    expect(new Date(report.analyzedAt).getTime()).not.toBeNaN();
    expect(report.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it('works with zero analyzers', async () => {
    const engine = new AnalysisEngine([]);
    const report = await engine.analyze(context);

    expect(report.results).toHaveLength(0);
    expect(report.score).toBe(100);
    expect(report.grade).toBe('A');
    expect(report.totalFindings).toBe(0);
  });

  it('computes aggregate score from all findings', async () => {
    const a1 = makeAnalyzer('a1', {
      analyzer: 'a1',
      findings: [{ analyzer: 'a1', severity: 'critical', title: 't', description: 'd' }],
      duration: 5,
    });
    const a2 = makeAnalyzer('a2', {
      analyzer: 'a2',
      findings: [{ analyzer: 'a2', severity: 'high', title: 't', description: 'd' }],
      duration: 3,
    });

    const engine = new AnalysisEngine([a1, a2]);
    const report = await engine.analyze(context);

    // 100 - 25 - 15 = 60
    expect(report.score).toBe(60);
    expect(report.grade).toBe('D');
  });

  it('sets packageName and version from context', async () => {
    const ctx = makeContext({ packageName: '@scope/pkg', version: '2.3.4' });
    const engine = new AnalysisEngine([]);
    const report = await engine.analyze(ctx);

    expect(report.packageName).toBe('@scope/pkg');
    expect(report.version).toBe('2.3.4');
  });

  it('handles multiple analyzers all throwing', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const engine = new AnalysisEngine([
      makeThrowingAnalyzer('fail1', 'err1'),
      makeThrowingAnalyzer('fail2', 'err2'),
      makeThrowingAnalyzer('fail3', 'err3'),
    ]);
    const report = await engine.analyze(context);

    expect(report.results).toHaveLength(3);
    expect(report.totalFindings).toBe(0);
    expect(report.score).toBe(100);
    expect(consoleSpy).toHaveBeenCalledTimes(3);

    consoleSpy.mockRestore();
  });
});
