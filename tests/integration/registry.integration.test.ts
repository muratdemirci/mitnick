/**
 * Integration tests for the npm registry client.
 *
 * These tests hit the real npm registry and verify end-to-end behavior.
 * They are slower and require network access, so they are separated
 * from unit tests and can be run independently.
 */

import { describe, it, expect } from 'vitest';
import { fetchPackageMetadata } from '../../src/registry/client.js';

describe('Registry Client (integration)', () => {
  it('fetches metadata for a well-known package', async () => {
    const result = await fetchPackageMetadata('chalk');

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.metadata.name).toBe('chalk');
    expect(result.metadata.version).toBeDefined();
    expect(result.metadata.maintainers.length).toBeGreaterThan(0);
    expect(result.tarballUrl).toContain('chalk');
    expect(result.tarballUrl).toMatch(/\.tgz$/);
  });

  it('fetches a specific version', async () => {
    const result = await fetchPackageMetadata('chalk', '4.1.2');

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.metadata.name).toBe('chalk');
    expect(result.metadata.version).toBe('4.1.2');
  });

  it('resolves a semver range', async () => {
    const result = await fetchPackageMetadata('chalk', '^4.0.0');

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.metadata.name).toBe('chalk');
    // ^4.0.0 should resolve to the highest 4.x.x version
    expect(result.metadata.version).toMatch(/^4\./);
  });

  it('fetches metadata for a scoped package', async () => {
    const result = await fetchPackageMetadata('@types/node');

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.metadata.name).toBe('@types/node');
    expect(result.metadata.version).toBeDefined();
  });

  it('returns not_found for a nonexistent package', async () => {
    const result = await fetchPackageMetadata('this-package-definitely-does-not-exist-xyz-12345');

    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.error).toBe('not_found');
  });

  it('returns version_not_found for a nonexistent version', async () => {
    const result = await fetchPackageMetadata('chalk', '999.999.999');

    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.error).toBe('version_not_found');
  });
});
