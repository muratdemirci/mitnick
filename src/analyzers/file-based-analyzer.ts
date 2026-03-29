/**
 * Abstract base class for analyzers that walk source files in the extracted package.
 *
 * Subclasses only need to implement `analyzeFile()` — the file-walking boilerplate
 * (directory traversal, extension filtering, safe reads) is handled here.
 */

import type { Analyzer } from './analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding } from '../core/types.js';
import { walkDirectory, readFileSafe, isAnalyzableFile } from '../utils/fs.js';
import { logger } from '../utils/logger.js';
import { relative } from 'node:path';

export abstract class FileBasedAnalyzer implements Analyzer {
  abstract readonly name: string;
  abstract readonly description: string;

  /**
   * Analyze a single source file and return any findings.
   * @param source  The file contents as a UTF-8 string.
   * @param relativePath  The path relative to the extraction root.
   */
  protected abstract analyzeFile(source: string, relativePath: string): Finding[];

  async analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      for await (const filePath of walkDirectory(context.extractedPath)) {
        if (!isAnalyzableFile(filePath)) continue;

        const source = await readFileSafe(filePath);
        if (source === null || source.length === 0) continue;

        const relPath = relative(context.extractedPath, filePath);
        findings.push(...this.analyzeFile(source, relPath));
      }
    } catch (error: unknown) {
      logger.warn(
        `[${this.name}] Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    return {
      analyzer: this.name,
      findings,
      duration: performance.now() - start,
    };
  }
}
