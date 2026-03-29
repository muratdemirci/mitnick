import { MaintainerAnalyzer } from '../../../src/analyzers/maintainer/index.js';
import { createMockContext, createMockRegistryMetadata } from '../../helpers.js';

describe('MaintainerAnalyzer', () => {
  let analyzer: MaintainerAnalyzer;

  beforeEach(() => {
    analyzer = new MaintainerAnalyzer();
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('maintainer');
    expect(analyzer.description).toBeTruthy();
  });

  it('flags single maintainer as low severity (bus factor = 1)', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        maintainers: [{ name: 'alice', email: 'alice@example.com' }],
        publishedAt: '2023-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const busFinding = result.findings.find((f) => f.title.includes('bus factor'));
    expect(busFinding).toBeDefined();
    expect(busFinding!.severity).toBe('low');
    expect(busFinding!.description).toContain('alice');
  });

  it('returns info finding for multiple maintainers', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        maintainers: [{ name: 'alice' }, { name: 'bob' }, { name: 'charlie' }],
        publishedAt: '2023-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const infoFinding = result.findings.find((f) => f.title.includes('3 maintainers'));
    expect(infoFinding).toBeDefined();
    expect(infoFinding!.severity).toBe('info');
    expect(infoFinding!.description).toContain('alice');
    expect(infoFinding!.description).toContain('bob');
    expect(infoFinding!.description).toContain('charlie');
  });

  it('flags no maintainers as medium severity', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        maintainers: [],
        publishedAt: '2023-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const noMaintFinding = result.findings.find((f) => f.title.includes('No maintainers'));
    expect(noMaintFinding).toBeDefined();
    expect(noMaintFinding!.severity).toBe('medium');
  });

  it('flags very recently published version (< 7 days)', async () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 2);
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        publishedAt: recentDate.toISOString(),
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const recentFinding = result.findings.find((f) => f.title.includes('Very recently published'));
    expect(recentFinding).toBeDefined();
    expect(recentFinding!.severity).toBe('medium');
  });

  it('flags recently published version (< 30 days but >= 7 days) as info', async () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 15);
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        publishedAt: recentDate.toISOString(),
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const recentFinding = result.findings.find((f) => f.title.includes('Recently published'));
    expect(recentFinding).toBeDefined();
    expect(recentFinding!.severity).toBe('info');
  });

  it('does not flag old published version', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        publishedAt: '2020-01-01T00:00:00.000Z',
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    const recentFinding = result.findings.find(
      (f) => f.title.includes('Recently published') || f.title.includes('Very recently'),
    );
    expect(recentFinding).toBeUndefined();
  });

  it('flags first published version (single version) as low severity', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0'],
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const firstVersionFinding = result.findings.find((f) => f.title.includes('First published'));
    expect(firstVersionFinding).toBeDefined();
    expect(firstVersionFinding!.severity).toBe('low');
  });

  it('does not flag first version when multiple versions exist', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        versions: ['1.0.0', '1.0.1', '2.0.0'],
        publishedAt: '2020-01-01T00:00:00.000Z',
      }),
    });
    const result = await analyzer.analyze(ctx);

    const firstVersionFinding = result.findings.find((f) => f.title.includes('First published'));
    expect(firstVersionFinding).toBeUndefined();
  });

  it('handles missing publishedAt gracefully', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        publishedAt: undefined,
        versions: ['1.0.0', '2.0.0'],
      }),
    });
    const result = await analyzer.analyze(ctx);

    expect(result.analyzer).toBe('maintainer');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('returns duration', async () => {
    const ctx = createMockContext();
    const result = await analyzer.analyze(ctx);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('never throws an error', async () => {
    const ctx = createMockContext({
      registryMetadata: createMockRegistryMetadata({
        maintainers: [],
        versions: [],
        publishedAt: 'invalid-date',
      }),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('maintainer');
  });
});
