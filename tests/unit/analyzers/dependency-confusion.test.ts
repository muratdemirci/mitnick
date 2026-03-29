import { DependencyConfusionAnalyzer } from '../../../src/analyzers/dependency-confusion/index.js';
import { createMockContext, createMockRegistryMetadata } from '../../helpers.js';

describe('DependencyConfusionAnalyzer', () => {
  let analyzer: DependencyConfusionAnalyzer;

  beforeEach(() => {
    analyzer = new DependencyConfusionAnalyzer();
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('dependency-confusion');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns no findings for a normal package name', async () => {
    const ctx = createMockContext({
      packageName: 'lodash',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0', '3.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('skips scoped packages (returns no findings)', async () => {
    const ctx = createMockContext({
      packageName: '@company/internal-lib',
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('flags packages with -internal suffix (high severity)', async () => {
    const ctx = createMockContext({
      packageName: 'my-lib-internal',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('-internal'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
    expect(finding!.description).toContain('dependency confusion');
  });

  it('flags packages with -private suffix', async () => {
    const ctx = createMockContext({
      packageName: 'acme-utils-private',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('-private'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('flags packages with -corp suffix', async () => {
    const ctx = createMockContext({
      packageName: 'my-service-corp',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('-corp'));
    expect(finding).toBeDefined();
  });

  it('flags packages with internal- prefix', async () => {
    const ctx = createMockContext({
      packageName: 'internal-auth-service',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('internal-'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('flags packages with company- prefix', async () => {
    const ctx = createMockContext({
      packageName: 'company-logger',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('company-'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('escalates recently published packages with org naming', async () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 5);
    const ctx = createMockContext({
      packageName: 'company-auth-internal',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: recentDate.toISOString(),
        versions: ['1.0.0'],
        timeMap: { '1.0.0': recentDate.toISOString() },
      }),
      version: '1.0.0',
    });
    const result = await analyzer.analyze(ctx);

    const escalated = result.findings.find((f) =>
      f.title.includes('Recently published package with internal naming'),
    );
    expect(escalated).toBeDefined();
    expect(escalated!.severity).toBe('high');
  });

  it('flags recently published package with org-looking segments', async () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 5);
    const ctx = createMockContext({
      packageName: 'team-shared-utils',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: recentDate.toISOString(),
        versions: ['1.0.0'],
        timeMap: { '1.0.0': recentDate.toISOString() },
      }),
      version: '1.0.0',
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('organizational naming segments'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('does not flag old packages with org segments', async () => {
    const ctx = createMockContext({
      packageName: 'team-shared-utils',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0', '3.0.0'],
        timeMap: {
          '1.0.0': '2020-01-01T00:00:00.000Z',
          '2.0.0': '2020-06-01T00:00:00.000Z',
          '3.0.0': '2020-12-01T00:00:00.000Z',
        },
      }),
      version: '3.0.0',
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('organizational naming segments'));
    expect(finding).toBeUndefined();
  });

  it('handles case insensitivity for suffix matching', async () => {
    const ctx = createMockContext({
      packageName: 'MyLib-Internal',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('-internal'));
    expect(finding).toBeDefined();
  });

  it('returns duration', async () => {
    const ctx = createMockContext();
    const result = await analyzer.analyze(ctx);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('never throws an error', async () => {
    const ctx = createMockContext({
      packageName: '',
      registryMetadata: createMockRegistryMetadata({
        publishedAt: 'invalid-date',
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('dependency-confusion');
  });
});
