/**
 * Maintainer Analyzer — evaluates package maintainer health using
 * registry metadata (bus factor, maintainer count).
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding } from '../../core/types.js';
import { logger } from '../../utils/logger.js';

// ─── Analyzer ─────────────────────────────────────────────

export class MaintainerAnalyzer implements Analyzer {
  readonly name = 'maintainer';
  readonly description = 'Evaluates package maintainer health and bus factor risk';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const { maintainers } = context.registryMetadata;

      if (maintainers.length === 0) {
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'No maintainers listed',
          description:
            'The package has no maintainers listed in the registry metadata. ' +
            'This could indicate an abandoned or improperly published package.',
          recommendation: 'Verify the package is actively maintained before relying on it.',
        });
      } else if (maintainers.length === 1) {
        const maintainer = maintainers[0];
        findings.push({
          analyzer: this.name,
          severity: 'low',
          title: 'Single maintainer (bus factor = 1)',
          description:
            `The package has only one maintainer: ${maintainer?.name ?? 'unknown'}. ` +
            'If this person becomes unavailable, the package may become unmaintained.',
          recommendation:
            'Consider the risk of depending on a single-maintainer package. ' +
            'Check if there are alternative packages with broader maintainer support.',
        });
      } else {
        findings.push({
          analyzer: this.name,
          severity: 'info',
          title: `${maintainers.length} maintainers`,
          description:
            `The package has ${maintainers.length} maintainers: ` +
            `${maintainers.map((m) => m.name).join(', ')}.`,
        });
      }

      // Check if the package was recently published (new package risk)
      const publishedAt = context.registryMetadata.publishedAt;
      if (publishedAt !== undefined && publishedAt !== '') {
        const publishDate = new Date(publishedAt);
        const now = new Date();
        const ageInDays = (now.getTime() - publishDate.getTime()) / (1000 * 60 * 60 * 24);

        if (ageInDays < 7) {
          findings.push({
            analyzer: this.name,
            severity: 'medium',
            title: 'Very recently published version',
            description:
              `This version was published ${Math.floor(ageInDays)} day(s) ago (${publishedAt}). ` +
              'Very new versions have had less community scrutiny.',
            recommendation:
              'Consider waiting for community feedback before adopting very new versions.',
          });
        } else if (ageInDays < 30) {
          findings.push({
            analyzer: this.name,
            severity: 'info',
            title: 'Recently published version',
            description: `This version was published ${Math.floor(ageInDays)} day(s) ago (${publishedAt}).`,
          });
        }
      }

      // Check total number of versions as a maturity signal
      const versionCount = context.registryMetadata.versions.length;
      if (versionCount === 1) {
        findings.push({
          analyzer: this.name,
          severity: 'low',
          title: 'First published version',
          description: 'This package has only one published version, indicating it is brand new.',
          recommendation: 'New packages have had less vetting. Review the code carefully.',
        });
      }
    } catch (error: unknown) {
      logger.warn(
        `[${this.name}] Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    return Promise.resolve({
      analyzer: this.name,
      findings,
      duration: performance.now() - start,
    });
  }
}
