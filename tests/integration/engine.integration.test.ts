/**
 * Integration tests for the full analysis pipeline.
 *
 * Downloads a real package from npm, runs all analyzers,
 * and verifies the end-to-end report structure.
 */

import { describe, it, expect } from 'vitest';
import { AnalysisEngine } from '../../src/core/engine.js';
import { createAnalyzers } from '../../src/analyzers/analyzer.registry.js';
import { fetchPackageMetadata } from '../../src/registry/client.js';
import { downloadAndExtract } from '../../src/registry/tarball.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

describe('Analysis Engine (integration)', () => {
  it('analyzes a real package end-to-end', async () => {
    // Use a small, well-known package for speed
    const registryResult = await fetchPackageMetadata('is-odd', '3.0.1');
    expect(registryResult.ok).toBe(true);
    if (!registryResult.ok) return;

    const { metadata, tarballUrl } = registryResult;

    const tarballResult = await downloadAndExtract(tarballUrl, metadata.name);
    expect(tarballResult.ok).toBe(true);
    if (!tarballResult.ok) return;

    try {
      const packageJsonRaw = await readFile(
        join(tarballResult.extractedPath, 'package.json'),
        'utf-8',
      );
      const packageJson = JSON.parse(packageJsonRaw) as Record<string, unknown>;

      const engine = new AnalysisEngine(createAnalyzers());
      const report = await engine.analyze({
        packageName: metadata.name,
        version: metadata.version,
        packageJson,
        extractedPath: tarballResult.extractedPath,
        registryMetadata: metadata,
      });

      // Verify report structure
      expect(report.packageName).toBe('is-odd');
      expect(report.version).toBe('3.0.1');
      expect(report.score).toBeGreaterThanOrEqual(0);
      expect(report.score).toBeLessThanOrEqual(100);
      expect(['A', 'B', 'C', 'D', 'F']).toContain(report.grade);
      expect(report.results.length).toBe(11); // All 11 analyzers
      expect(report.analyzedAt).toBeDefined();
      expect(report.duration).toBeGreaterThanOrEqual(0);

      // Verify each analyzer produced a result
      const analyzerNames = report.results.map((r) => r.analyzer);
      expect(analyzerNames).toContain('vulnerability-scanner');
      expect(analyzerNames).toContain('install-scripts');
      expect(analyzerNames).toContain('typosquatting');
      expect(analyzerNames).toContain('obfuscation');
      expect(analyzerNames).toContain('network-calls');
      expect(analyzerNames).toContain('sensitive-data');
      expect(analyzerNames).toContain('license');
      expect(analyzerNames).toContain('maintainer');
      expect(analyzerNames).toContain('dependency-confusion');
      expect(analyzerNames).toContain('dormant-package');
      expect(analyzerNames).toContain('prototype-pollution');

      // Verify findings structure
      for (const result of report.results) {
        expect(result.analyzer).toBeDefined();
        expect(Array.isArray(result.findings)).toBe(true);
        expect(result.duration).toBeGreaterThanOrEqual(0);

        for (const finding of result.findings) {
          expect(finding.analyzer).toBeDefined();
          expect(finding.severity).toBeDefined();
          expect(finding.title).toBeDefined();
          expect(finding.description).toBeDefined();
        }
      }
    } finally {
      await tarballResult.cleanup();
    }
  });
});
