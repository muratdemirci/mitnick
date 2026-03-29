import { describe, it, expect, vi, beforeEach } from 'vitest';
import { downloadAndExtract } from '../../../src/registry/tarball.js';

// ─── Mock dependencies ────────────────────────────────────

vi.mock('../../../src/utils/http.js', () => ({
  fetchBuffer: vi.fn(),
}));

vi.mock('../../../src/utils/fs.js', () => ({
  createTempDir: vi.fn(),
  cleanupTempDir: vi.fn(),
}));

vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
  mkdir: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('tar', () => ({
  extract: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import { fetchBuffer } from '../../../src/utils/http.js';
import { createTempDir, cleanupTempDir } from '../../../src/utils/fs.js';
import * as tar from 'tar';
import { writeFile, mkdir } from 'node:fs/promises';

const mockFetchBuffer = vi.mocked(fetchBuffer);
const mockCreateTempDir = vi.mocked(createTempDir);
const mockCleanupTempDir = vi.mocked(cleanupTempDir);
const mockExtract = vi.mocked(tar.extract);
const mockWriteFile = vi.mocked(writeFile);
const mockMkdir = vi.mocked(mkdir);

// ─── Tests ────────────────────────────────────────────────

describe('downloadAndExtract', () => {
  const tarballUrl = 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz';
  const packageName = 'test-pkg';

  beforeEach(() => {
    vi.resetAllMocks();
    mockCreateTempDir.mockResolvedValue('/tmp/mitnick-abc123');
    mockCleanupTempDir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockMkdir.mockResolvedValue(undefined as unknown as string);
    mockExtract.mockResolvedValue(undefined);
  });

  it('downloads, extracts, and returns success', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: true,
      data: Buffer.from('fake-tgz-data'),
      status: 200,
    });

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.extractedPath).toBe('/tmp/mitnick-abc123/extracted');
    expect(typeof result.cleanup).toBe('function');

    // Verify the flow
    expect(mockCreateTempDir).toHaveBeenCalledOnce();
    expect(mockFetchBuffer).toHaveBeenCalledWith(tarballUrl, { timeout: 60_000 });
    expect(mockWriteFile).toHaveBeenCalledWith(
      '/tmp/mitnick-abc123/package.tgz',
      Buffer.from('fake-tgz-data'),
    );
    expect(mockMkdir).toHaveBeenCalledWith('/tmp/mitnick-abc123/extracted', {
      recursive: true,
    });
    expect(mockExtract).toHaveBeenCalledWith(
      expect.objectContaining({
        file: '/tmp/mitnick-abc123/package.tgz',
        cwd: '/tmp/mitnick-abc123/extracted',
        strip: 1,
      }),
    );
  });

  it('cleanup function removes the temp directory', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: true,
      data: Buffer.from('fake-tgz-data'),
      status: 200,
    });

    const result = await downloadAndExtract(tarballUrl, packageName);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    await result.cleanup();

    expect(mockCleanupTempDir).toHaveBeenCalledWith('/tmp/mitnick-abc123');
  });

  it('returns download_failed when fetch fails', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: false,
      error: 'network',
      message: 'Network error',
    });

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('download_failed');
    expect(result.message).toContain('test-pkg');
    expect(result.message).toContain('Network error');

    // Should clean up temp dir on failure
    expect(mockCleanupTempDir).toHaveBeenCalledWith('/tmp/mitnick-abc123');
  });

  it('returns extraction_failed when tar.extract throws', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: true,
      data: Buffer.from('corrupt-tgz'),
      status: 200,
    });
    mockExtract.mockRejectedValue(new Error('Invalid tarball'));

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('extraction_failed');
    expect(result.message).toContain('Invalid tarball');

    // Should clean up temp dir
    expect(mockCleanupTempDir).toHaveBeenCalledWith('/tmp/mitnick-abc123');
  });

  it('returns extraction_failed with stringified non-Error throw', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: true,
      data: Buffer.from('data'),
      status: 200,
    });
    mockExtract.mockRejectedValue('string error from tar');

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('extraction_failed');
    expect(result.message).toContain('string error from tar');
  });

  it('returns io_error when createTempDir throws', async () => {
    mockCreateTempDir.mockRejectedValue(new Error('Permission denied'));

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('io_error');
    expect(result.message).toContain('Permission denied');
  });

  it('returns io_error when writeFile throws', async () => {
    mockFetchBuffer.mockResolvedValue({
      ok: true,
      data: Buffer.from('data'),
      status: 200,
    });
    mockWriteFile.mockRejectedValue(new Error('Disk full'));

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('io_error');
    expect(result.message).toContain('Disk full');

    // Should clean up
    expect(mockCleanupTempDir).toHaveBeenCalled();
  });

  it('returns io_error with stringified non-Error from outer catch', async () => {
    mockCreateTempDir.mockRejectedValue('raw string');

    const result = await downloadAndExtract(tarballUrl, packageName);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('io_error');
    expect(result.message).toContain('raw string');
  });

  it('does not leak temp dirs — cleans up on every failure path', async () => {
    // fetch fails
    mockFetchBuffer.mockResolvedValue({
      ok: false,
      error: 'not_found',
      message: '404',
    });

    await downloadAndExtract(tarballUrl, packageName);
    expect(mockCleanupTempDir).toHaveBeenCalledTimes(1);
  });
});
