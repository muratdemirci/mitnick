/**
 * Tarball download and extraction for npm packages.
 *
 * Downloads a .tgz from the npm registry, extracts it to a temp directory,
 * and provides cleanup. All npm tarballs contain a top-level `package/`
 * directory which is stripped during extraction.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import * as tar from 'tar';
import { createTempDir, cleanupTempDir } from '../utils/fs.js';
import { fetchBuffer } from '../utils/http.js';
import { logger } from '../utils/logger.js';

// ─── Result Types ─────────────────────────────────────────

export interface TarballSuccess {
  readonly ok: true;
  /** Absolute path to the directory containing extracted package files. */
  readonly extractedPath: string;
  /** Call this to clean up the temp directory when analysis is done. */
  readonly cleanup: () => Promise<void>;
}

export interface TarballError {
  readonly ok: false;
  readonly error: TarballErrorKind;
  readonly message: string;
}

export type TarballResult = TarballSuccess | TarballError;

export type TarballErrorKind =
  | 'download_failed'
  | 'extraction_failed'
  | 'io_error'
  | 'size_exceeded';

const MAX_TARBALL_SIZE = 100 * 1024 * 1024; // 100MB

// ─── Download & Extract ───────────────────────────────────

/**
 * Download a tarball from the given URL and extract it to a temp directory.
 *
 * npm tarballs contain a `package/` top-level directory. We strip one level
 * so the extracted path directly contains the package files.
 *
 * @param tarballUrl - Full URL to the .tgz file on the npm registry
 * @param packageName - Package name (for logging)
 * @returns A discriminated union with the extracted path and cleanup function,
 *          or an error description.
 */
export async function downloadAndExtract(
  tarballUrl: string,
  packageName: string,
): Promise<TarballResult> {
  let tempDir: string | undefined;

  try {
    // Create temp directory
    tempDir = await createTempDir();
    logger.debug(`Created temp directory: ${tempDir}`);

    // Download tarball
    logger.debug(`Downloading tarball for ${packageName}`, { url: tarballUrl });
    const downloadResult = await fetchBuffer(tarballUrl, { timeout: 60_000 });

    if (!downloadResult.ok) {
      await cleanupTempDir(tempDir);
      return {
        ok: false,
        error: 'download_failed',
        message: `Failed to download tarball for ${packageName}: ${downloadResult.message}`,
      };
    }

    // Check tarball size before writing to disk
    if (downloadResult.data.byteLength > MAX_TARBALL_SIZE) {
      await cleanupTempDir(tempDir);
      return {
        ok: false,
        error: 'size_exceeded',
        message: `Tarball for ${packageName} exceeds maximum allowed size of ${MAX_TARBALL_SIZE} bytes`,
      };
    }

    const tgzPath = join(tempDir, 'package.tgz');
    await writeFile(tgzPath, downloadResult.data);

    // Extract tarball
    const extractPath = join(tempDir, 'extracted');
    await mkdir(extractPath, { recursive: true });
    logger.debug(`Extracting tarball to ${extractPath}`);

    try {
      await tar.extract({
        file: tgzPath,
        cwd: extractPath,
        strip: 1, // Remove the top-level `package/` directory
        // Prevent path traversal
        filter: (path) => {
          const normalized = path.replace(/\\/g, '/');
          return !normalized.includes('..') && !normalized.startsWith('/');
        },
      });
    } catch (extractError: unknown) {
      await cleanupTempDir(tempDir);
      const message = extractError instanceof Error ? extractError.message : String(extractError);
      return {
        ok: false,
        error: 'extraction_failed',
        message: `Failed to extract tarball for ${packageName}: ${message}`,
      };
    }

    logger.debug(`Successfully extracted ${packageName} to ${extractPath}`);

    const capturedTempDir = tempDir;
    return {
      ok: true,
      extractedPath: extractPath,
      cleanup: async () => {
        logger.debug(`Cleaning up temp directory: ${capturedTempDir}`);
        await cleanupTempDir(capturedTempDir);
      },
    };
  } catch (error: unknown) {
    if (tempDir !== undefined) {
      await cleanupTempDir(tempDir);
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: 'io_error',
      message: `Unexpected error processing tarball for ${packageName}: ${message}`,
    };
  }
}
