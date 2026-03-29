/**
 * Dormant Package Analyzer — detects packages that were reactivated after
 * a long period of inactivity, which may indicate a hijacked or compromised package.
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding } from '../../core/types.js';
import { logger } from '../../utils/logger.js';

// ─── Types ────────────────────────────────────────────────

interface VersionDate {
  readonly version: string;
  readonly date: Date;
}

// ─── Constants ────────────────────────────────────────────

/** Minimum gap in days to consider a package dormant. */
const DORMANCY_THRESHOLD_DAYS = 365;

/** Milliseconds per day. */
const MS_PER_DAY = 1000 * 60 * 60 * 24;

// ─── Analyzer ─────────────────────────────────────────────

export class DormantPackageAnalyzer implements Analyzer {
  readonly name = 'dormant-package';
  readonly description = 'Detects packages reactivated after long periods of inactivity';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const { versions, timeMap, maintainers } = context.registryMetadata;

      if (versions.length < 2) {
        // Need at least 2 versions to check for dormancy gaps
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      // Build a sorted list of (version, date) pairs
      const versionDates = this.buildSortedVersionDates(versions, timeMap);

      if (versionDates.length < 2) {
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      // Check the gap between the latest version and the one before it
      const latest = versionDates[versionDates.length - 1];
      const previous = versionDates[versionDates.length - 2];

      if (!latest || !previous) {
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      const gapDays = Math.floor((latest.date.getTime() - previous.date.getTime()) / MS_PER_DAY);

      if (gapDays > DORMANCY_THRESHOLD_DAYS) {
        const gapMonths = Math.floor(gapDays / 30);
        const gapYears = (gapDays / 365).toFixed(1);

        // Check if we're looking at the current version
        const isCurrentVersion =
          latest.version === context.version ||
          latest.version === context.registryMetadata.distTags['latest'];

        if (isCurrentVersion) {
          findings.push({
            analyzer: this.name,
            severity: 'medium',
            title: `Package reactivated after ${gapMonths} months of dormancy`,
            description:
              `The latest version (${latest.version}) was published on ` +
              `${latest.date.toISOString().split('T')[0] ?? 'unknown'} after a gap of ${gapDays} days ` +
              `(~${gapYears} years) since the previous version (${previous.version}, ` +
              `published ${previous.date.toISOString().split('T')[0] ?? 'unknown'}). ` +
              'Reactivation after long dormancy can indicate a hijacked package.',
            recommendation:
              'Review the changelog and recent commits. Verify the maintainer identity ' +
              'and check for unexpected changes in package behavior.',
          });

          // Check if maintainer list looks different (heuristic: very few maintainers
          // combined with dormancy is extra suspicious)
          if (maintainers.length === 1) {
            findings.push({
              analyzer: this.name,
              severity: 'high',
              title: 'Dormant package reactivated by single maintainer',
              description:
                `The package was dormant for ${gapDays} days and is now maintained by a single person ` +
                `(${maintainers[0]?.name ?? 'unknown'}). This pattern is consistent with package takeover.`,
              recommendation:
                'Verify the maintainer identity. Compare with previous version maintainers ' +
                'if possible. Consider alternatives if the package seems compromised.',
            });
          }
        }

        // Also check for large gaps anywhere in the version history
        this.checkHistoricalGaps(versionDates, findings);
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

  private buildSortedVersionDates(
    versions: readonly string[],
    timeMap: Readonly<Record<string, string>>,
  ): readonly VersionDate[] {
    const result: VersionDate[] = [];

    for (const version of versions) {
      const timeStr = timeMap[version];
      if (timeStr === undefined || timeStr === '') continue;

      const date = new Date(timeStr);
      if (isNaN(date.getTime())) continue;

      result.push({ version, date });
    }

    // Sort by date ascending
    result.sort((a, b) => a.date.getTime() - b.date.getTime());
    return result;
  }

  private checkHistoricalGaps(versionDates: readonly VersionDate[], findings: Finding[]): void {
    // Find the largest historical gap (excluding the latest, already checked above)
    let maxGap = 0;
    let maxGapStart: VersionDate | undefined;
    let maxGapEnd: VersionDate | undefined;

    for (let i = 1; i < versionDates.length - 1; i++) {
      const prev = versionDates[i - 1];
      const curr = versionDates[i];
      if (!prev || !curr) continue;

      const gap = (curr.date.getTime() - prev.date.getTime()) / MS_PER_DAY;
      if (gap > maxGap) {
        maxGap = gap;
        maxGapStart = prev;
        maxGapEnd = curr;
      }
    }

    if (maxGap > DORMANCY_THRESHOLD_DAYS * 2 && maxGapStart && maxGapEnd) {
      findings.push({
        analyzer: this.name,
        severity: 'info',
        title: `Historical dormancy gap: ${Math.floor(maxGap)} days`,
        description:
          `Between versions ${maxGapStart.version} and ${maxGapEnd.version}, ` +
          `there was a gap of ${Math.floor(maxGap)} days.`,
      });
    }
  }
}
