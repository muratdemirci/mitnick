import { DormantPackageAnalyzer } from '../../../src/analyzers/dormant-package/index.js';
import { createMockContext, createMockRegistryMetadata } from '../../helpers.js';

describe('DormantPackageAnalyzer', () => {
  let analyzer: DormantPackageAnalyzer;

  beforeEach(() => {
    analyzer = new DormantPackageAnalyzer();
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('dormant-package');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns no findings for a package with only one version', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0'],
        timeMap: { '1.0.0': '2024-01-01T00:00:00.000Z' },
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns no findings for an active package (short gap between versions)', async () => {
    const ctx = createMockContext({
      version: '2.0.0',
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '1.1.0', '2.0.0'],
        timeMap: {
          '1.0.0': '2024-01-01T00:00:00.000Z',
          '1.1.0': '2024-03-01T00:00:00.000Z',
          '2.0.0': '2024-06-01T00:00:00.000Z',
        },
        distTags: { latest: '2.0.0' },
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('detects dormant package reactivated after >365 days', async () => {
    const ctx = createMockContext({
      version: '2.0.0',
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '2.0.0'],
        timeMap: {
          '1.0.0': '2020-01-01T00:00:00.000Z',
          '2.0.0': '2024-06-01T00:00:00.000Z',
        },
        distTags: { latest: '2.0.0' },
        maintainers: [{ name: 'alice' }, { name: 'bob' }],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const dormant = result.findings.find((f) => f.title.includes('reactivated'));
    expect(dormant).toBeDefined();
    expect(dormant!.severity).toBe('medium');
    expect(dormant!.description).toContain('gap of');
  });

  it('escalates dormant package with single maintainer', async () => {
    const ctx = createMockContext({
      version: '2.0.0',
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '2.0.0'],
        timeMap: {
          '1.0.0': '2020-01-01T00:00:00.000Z',
          '2.0.0': '2024-06-01T00:00:00.000Z',
        },
        distTags: { latest: '2.0.0' },
        maintainers: [{ name: 'suspicious-user' }],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const hijack = result.findings.find((f) => f.title.includes('single maintainer'));
    expect(hijack).toBeDefined();
    expect(hijack!.severity).toBe('high');
    expect(hijack!.description).toContain('suspicious-user');
  });

  it('detects historical dormancy gaps (> 2x threshold)', async () => {
    const ctx = createMockContext({
      version: '4.0.0',
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '2.0.0', '3.0.0', '4.0.0'],
        timeMap: {
          '1.0.0': '2015-01-01T00:00:00.000Z',
          '2.0.0': '2018-06-01T00:00:00.000Z', // 3.4 year gap > 2*365
          '3.0.0': '2018-09-01T00:00:00.000Z',
          '4.0.0': '2024-06-01T00:00:00.000Z', // big gap at the end too
        },
        distTags: { latest: '4.0.0' },
      }),
    });
    const result = await analyzer.analyze(ctx);

    const historical = result.findings.find((f) => f.title.includes('Historical dormancy'));
    expect(historical).toBeDefined();
    expect(historical!.severity).toBe('info');
  });

  it('handles missing time entries gracefully', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '2.0.0'],
        timeMap: {},
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles invalid date strings gracefully', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '2.0.0'],
        timeMap: {
          '1.0.0': 'not-a-date',
          '2.0.0': 'also-not-a-date',
        },
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns no findings when version dates are close together', async () => {
    const ctx = createMockContext({
      version: '1.0.1',
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '1.0.1'],
        timeMap: {
          '1.0.0': '2024-01-01T00:00:00.000Z',
          '1.0.1': '2024-01-15T00:00:00.000Z',
        },
        distTags: { latest: '1.0.1' },
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns duration', async () => {
    const ctx = createMockContext();
    const result = await analyzer.analyze(ctx);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('never throws an error', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: [],
        timeMap: {},
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('dormant-package');
  });
});
