/**
 * Dependency Confusion Analyzer — detects packages that may be exploiting
 * dependency confusion by mimicking internal/private package naming patterns.
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding } from '../../core/types.js';
import { logger } from '../../utils/logger.js';

// ─── Constants ────────────────────────────────────────────

/** Suffixes commonly used for internal packages. */
const INTERNAL_SUFFIXES: readonly string[] = [
  '-internal',
  '-private',
  '-corp',
  '-enterprise',
  '-dev',
  '-staging',
  '-infra',
  '-platform',
  '-core-internal',
  '-sdk-internal',
];

/** Prefixes commonly used for company/org internal packages. */
const ORG_PREFIXES: readonly string[] = [
  'company-',
  'corp-',
  'internal-',
  'private-',
  'enterprise-',
  'intranet-',
];

/** Maximum age in days for a "very recently published" package. */
const RECENT_PUBLISH_DAYS = 30;

// ─── Analyzer ─────────────────────────────────────────────

export class DependencyConfusionAnalyzer implements Analyzer {
  readonly name = 'dependency-confusion';
  readonly description = 'Detects packages that may exploit dependency confusion attacks';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const packageName = context.packageName;

      // Skip scoped packages — they're namespaced and less vulnerable to confusion
      if (packageName.startsWith('@')) {
        return Promise.resolve({
          analyzer: this.name,
          findings: [],
          duration: performance.now() - start,
        });
      }

      const lowerName = packageName.toLowerCase();

      // Check for internal-looking suffixes
      const matchedSuffix = INTERNAL_SUFFIXES.find((suffix) => lowerName.endsWith(suffix));
      if (matchedSuffix !== undefined) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: `Package name suggests internal origin: "${matchedSuffix}" suffix`,
          description:
            `The package name "${packageName}" ends with "${matchedSuffix}", ` +
            'which is commonly used for internal/private packages. ' +
            'This public package may be attempting a dependency confusion attack.',
          recommendation:
            'Verify this is the intended package and not a malicious squatter ' +
            'targeting your internal package name.',
        });
      }

      // Check for org-like prefixes
      const matchedPrefix = ORG_PREFIXES.find((prefix) => lowerName.startsWith(prefix));
      if (matchedPrefix !== undefined) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: `Package name suggests organizational origin: "${matchedPrefix}" prefix`,
          description:
            `The package name "${packageName}" starts with "${matchedPrefix}", ` +
            'which mimics organizational/internal naming conventions. ' +
            'A public package with this naming pattern may be a dependency confusion attempt.',
          recommendation:
            'Confirm this package is from a trusted source, not mimicking an internal dependency.',
        });
      }

      // Check for very recently published packages with organizational naming
      const isRecentlyPublished = this.isRecentlyPublished(context);
      const hasOrgNaming = matchedSuffix !== undefined || matchedPrefix !== undefined;

      if (isRecentlyPublished && hasOrgNaming) {
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: 'Recently published package with internal naming pattern',
          description:
            `The package "${packageName}" was recently published and uses naming conventions ` +
            'typical of internal packages. This strongly suggests a dependency confusion attack.',
          recommendation:
            'Do NOT install this package without verifying it is not targeting your internal dependencies.',
        });
      }

      // Check for recently published + few versions (suspicious new package)
      if (isRecentlyPublished && context.registryMetadata.versions.length <= 2 && !hasOrgNaming) {
        // Only flag if the name also looks somewhat organizational
        if (this.hasOrgLookingSegments(lowerName)) {
          findings.push({
            analyzer: this.name,
            severity: 'medium',
            title: 'New package with organizational naming segments',
            description:
              `The package "${packageName}" was recently published with few versions ` +
              'and contains segments that look like organizational identifiers.',
            recommendation:
              'Verify the package origin and ensure it is not a dependency confusion attempt.',
          });
        }
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

  private isRecentlyPublished(context: AnalysisContext): boolean {
    const { publishedAt, timeMap, version } = context.registryMetadata;

    // Try the specific version's publish time first
    const versionTime = timeMap[version];
    const timeStr = versionTime ?? publishedAt;
    if (timeStr === undefined || timeStr === '') return false;

    const publishDate = new Date(timeStr);
    const now = new Date();
    const ageInDays = (now.getTime() - publishDate.getTime()) / (1000 * 60 * 60 * 24);

    return ageInDays < RECENT_PUBLISH_DAYS;
  }

  private hasOrgLookingSegments(name: string): boolean {
    const segments = name.split('-');
    const orgIndicators = [
      'team',
      'org',
      'dept',
      'group',
      'division',
      'unit',
      'service',
      'svc',
      'api',
      'lib',
      'util',
      'utils',
      'common',
      'shared',
      'infra',
    ];

    return segments.some((segment) => orgIndicators.includes(segment));
  }
}
