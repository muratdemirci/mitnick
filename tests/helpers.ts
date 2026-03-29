import type { AnalysisContext, RegistryMetadata } from '../src/core/types.js';

export function createMockRegistryMetadata(
  overrides?: Partial<RegistryMetadata>,
): RegistryMetadata {
  return {
    name: 'test-package',
    version: '1.0.0',
    description: 'A test package',
    license: 'MIT',
    maintainers: [{ name: 'test-user', email: 'test@example.com' }],
    publishedAt: '2024-01-15T00:00:00.000Z',
    versions: ['1.0.0'],
    timeMap: { '1.0.0': '2024-01-15T00:00:00.000Z' },
    distTags: { latest: '1.0.0' },
    homepage: 'https://example.com',
    repository: 'https://github.com/test/test-package',
    ...overrides,
  };
}

export function createMockContext(overrides?: Partial<AnalysisContext>): AnalysisContext {
  return {
    packageName: 'test-package',
    version: '1.0.0',
    packageJson: { name: 'test-package', version: '1.0.0' },
    extractedPath: '/tmp/mitnick-test',
    registryMetadata: createMockRegistryMetadata(),
    ...overrides,
  };
}
