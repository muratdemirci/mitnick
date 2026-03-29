import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchPackageMetadata } from '../../../src/registry/client.js';

// ─── Mock dependencies ────────────────────────────────────

vi.mock('../../../src/utils/http.js', () => ({
  fetchJson: vi.fn(),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import { fetchJson } from '../../../src/utils/http.js';

const mockFetchJson = vi.mocked(fetchJson);

// ─── Fixtures ─────────────────────────────────────────────

function makeRegistryDoc(overrides: Record<string, unknown> = {}) {
  return {
    name: 'test-pkg',
    description: 'A test package',
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        version: '1.0.0',
        dist: {
          tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
          shasum: 'abc123',
        },
      },
    },
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
    },
    maintainers: [{ name: 'alice', email: 'alice@example.com' }],
    license: 'MIT',
    homepage: 'https://example.com',
    repository: { url: 'https://github.com/test/test-pkg' },
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────

describe('fetchPackageMetadata', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns metadata for a successful fetch', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.metadata.name).toBe('test-pkg');
    expect(result.metadata.version).toBe('1.0.0');
    expect(result.metadata.license).toBe('MIT');
    expect(result.metadata.maintainers).toEqual([{ name: 'alice', email: 'alice@example.com' }]);
    expect(result.tarballUrl).toBe('https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz');
  });

  it('encodes scoped package names in the URL', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc({ name: '@scope/pkg' }),
      status: 200,
    });

    await fetchPackageMetadata('@scope/pkg');

    expect(mockFetchJson).toHaveBeenCalledWith(
      expect.stringContaining('@scope%2Fpkg'),
      expect.any(Object),
    );
  });

  it('encodes non-scoped packages in the URL', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    await fetchPackageMetadata('test-pkg');

    expect(mockFetchJson).toHaveBeenCalledWith(
      'https://registry.npmjs.org/test-pkg',
      expect.any(Object),
    );
  });

  it('returns not_found error on 404', async () => {
    mockFetchJson.mockResolvedValue({
      ok: false,
      error: 'not_found',
      message: 'HTTP 404',
      status: 404,
    });

    const result = await fetchPackageMetadata('nonexistent-pkg');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('not_found');
    expect(result.message).toContain('nonexistent-pkg');
  });

  it('returns rate_limited error on 429', async () => {
    mockFetchJson.mockResolvedValue({
      ok: false,
      error: 'rate_limited',
      message: 'HTTP 429',
      status: 429,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('rate_limited');
    expect(result.message).toContain('rate limit');
  });

  it('returns network_error for other HTTP failures', async () => {
    mockFetchJson.mockResolvedValue({
      ok: false,
      error: 'server_error',
      message: 'HTTP 500',
      status: 500,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('network_error');
  });

  it('returns validation_error for malformed response', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: { not: 'a valid package doc' },
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('validation_error');
    expect(result.message).toContain('Invalid registry response');
  });

  it('resolves an explicit version', async () => {
    const doc = makeRegistryDoc({
      versions: {
        '1.0.0': {
          version: '1.0.0',
          dist: {
            tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
          },
        },
        '2.0.0': {
          version: '2.0.0',
          dist: {
            tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-2.0.0.tgz',
          },
        },
      },
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg', '2.0.0');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('2.0.0');
    expect(result.tarballUrl).toContain('2.0.0');
  });

  it('resolves a dist-tag (e.g., "next")', async () => {
    const doc = makeRegistryDoc({
      'dist-tags': { latest: '1.0.0', next: '2.0.0-beta.1' },
      versions: {
        '1.0.0': {
          version: '1.0.0',
          dist: {
            tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
          },
        },
        '2.0.0-beta.1': {
          version: '2.0.0-beta.1',
          dist: {
            tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-2.0.0-beta.1.tgz',
          },
        },
      },
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg', 'next');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('2.0.0-beta.1');
  });

  it('returns version_not_found when version does not exist', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg', '9.9.9');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('version_not_found');
    expect(result.message).toContain('9.9.9');
  });

  it('defaults to latest dist-tag when no version specified', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('1.0.0');
  });

  it('includes optional fields in metadata when present', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.description).toBe('A test package');
    expect(result.metadata.homepage).toBe('https://example.com');
    expect(result.metadata.publishedAt).toBe('2024-01-01T00:00:00.000Z');
  });

  it('handles missing optional fields', async () => {
    const doc = makeRegistryDoc({
      description: undefined,
      license: undefined,
      homepage: undefined,
      repository: undefined,
      time: undefined,
      maintainers: undefined,
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.maintainers).toEqual([]);
    expect(result.metadata.versions).toContain('1.0.0');
  });

  it('handles maintainers without email', async () => {
    const doc = makeRegistryDoc({
      maintainers: [{ name: 'bob' }],
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.maintainers).toEqual([{ name: 'bob' }]);
  });

  it('handles repository as a plain string', async () => {
    const doc = makeRegistryDoc({
      repository: 'https://github.com/plain/string',
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.repository).toBe('https://github.com/plain/string');
  });

  // ─── Semver Range Tests ──────────────────────────────────

  it('resolves a caret range (^1.0.0) to the highest matching version', async () => {
    const doc = makeRegistryDoc({
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '1.0.0': {
          version: '1.0.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz' },
        },
        '1.2.0': {
          version: '1.2.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.2.0.tgz' },
        },
        '1.5.3': {
          version: '1.5.3',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.5.3.tgz' },
        },
        '2.0.0': {
          version: '2.0.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-2.0.0.tgz' },
        },
      },
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg', '^1.0.0');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('1.5.3');
  });

  it('resolves a tilde range (~1.2.0) to the highest matching patch version', async () => {
    const doc = makeRegistryDoc({
      'dist-tags': { latest: '1.5.3' },
      versions: {
        '1.2.0': {
          version: '1.2.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.2.0.tgz' },
        },
        '1.2.5': {
          version: '1.2.5',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.2.5.tgz' },
        },
        '1.3.0': {
          version: '1.3.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.3.0.tgz' },
        },
        '1.5.3': {
          version: '1.5.3',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.5.3.tgz' },
        },
      },
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg', '~1.2.0');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('1.2.5');
  });

  it('resolves a complex range (>=1.0.0 <2.0.0)', async () => {
    const doc = makeRegistryDoc({
      'dist-tags': { latest: '3.0.0' },
      versions: {
        '1.0.0': {
          version: '1.0.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz' },
        },
        '1.9.0': {
          version: '1.9.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.9.0.tgz' },
        },
        '2.0.0': {
          version: '2.0.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-2.0.0.tgz' },
        },
        '3.0.0': {
          version: '3.0.0',
          dist: { tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-3.0.0.tgz' },
        },
      },
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg', '>=1.0.0 <2.0.0');

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.metadata.version).toBe('1.9.0');
  });

  it('returns version_not_found for a range with no matching versions', async () => {
    mockFetchJson.mockResolvedValue({
      ok: true,
      data: makeRegistryDoc(),
      status: 200,
    });

    const result = await fetchPackageMetadata('test-pkg', '^5.0.0');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('version_not_found');
  });

  it('returns version_not_found when no latest tag and no version specified', async () => {
    const doc = makeRegistryDoc({
      'dist-tags': {},
    });

    mockFetchJson.mockResolvedValue({ ok: true, data: doc, status: 200 });

    const result = await fetchPackageMetadata('test-pkg');

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('version_not_found');
  });
});
