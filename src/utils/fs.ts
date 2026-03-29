/**
 * Filesystem utilities for temp directory management and file operations.
 */

import { mkdtemp, rm, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ─── Analyzable File Extensions ───────────────────────────

const ANALYZABLE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts']);

/**
 * Check whether a file path has an analyzable JavaScript/TypeScript extension.
 */
export function isAnalyzableFile(filePath: string): boolean {
  const dotIdx = filePath.lastIndexOf('.');
  if (dotIdx === -1) return false;
  return ANALYZABLE_EXTENSIONS.has(filePath.slice(dotIdx));
}

// ─── Temp Directory ───────────────────────────────────────

const TEMP_PREFIX = 'mitnick-';

/**
 * Create a temporary directory for package extraction.
 * Returns the absolute path to the created directory.
 */
export async function createTempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), TEMP_PREFIX));
}

/**
 * Remove a temporary directory and all its contents.
 * Silently ignores errors (directory may already be cleaned up).
 */
export async function cleanupTempDir(dirPath: string): Promise<void> {
  try {
    await rm(dirPath, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup — ignore errors
  }
}

// ─── Directory Walking ────────────────────────────────────

/**
 * Recursively walk a directory, yielding absolute file paths.
 * Skips `node_modules` and hidden directories (starting with `.`).
 */
export async function* walkDirectory(dirPath: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
        continue;
      }
      yield* walkDirectory(fullPath);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}

// ─── Safe File Read ───────────────────────────────────────

/**
 * Read a file's contents as UTF-8 text.
 * Returns null if the file cannot be read (missing, permission denied, etc.).
 */
export async function readFileSafe(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8');
  } catch {
    return null;
  }
}
