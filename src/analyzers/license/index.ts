/**
 * License Analyzer — checks the package's license field for compliance
 * risks including copyleft, missing, and non-standard licenses.
 */

import type { Analyzer } from '../analyzer.interface.js';
import type { AnalysisContext, AnalyzerResult, Finding, Severity } from '../../core/types.js';
import { logger } from '../../utils/logger.js';

// ─── License classifications ─────────────────────────────

/** Permissive licenses that are generally safe for any use. */
const PERMISSIVE_LICENSES: readonly string[] = [
  'MIT',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  'Unlicense',
  'CC0-1.0',
  '0BSD',
  'Artistic-2.0',
  'Zlib',
  'BSL-1.0',
  'PostgreSQL',
  'BlueOak-1.0.0',
];

/** Copyleft licenses that impose distribution requirements. */
const COPYLEFT_LICENSES: readonly string[] = [
  'GPL-2.0',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'GPL-3.0',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'AGPL-3.0',
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',
  'LGPL-2.0',
  'LGPL-2.0-only',
  'LGPL-2.0-or-later',
  'LGPL-2.1',
  'LGPL-2.1-only',
  'LGPL-2.1-or-later',
  'LGPL-3.0',
  'LGPL-3.0-only',
  'LGPL-3.0-or-later',
  'MPL-2.0',
  'EUPL-1.1',
  'EUPL-1.2',
  'SSPL-1.0',
  'CPAL-1.0',
  'OSL-3.0',
  'CECILL-2.1',
];

// ─── Helpers ──────────────────────────────────────────────

function normalizeIdentifier(license: string): string {
  return license.trim().replace(/\s+/g, '-');
}

function isPermissive(identifier: string): boolean {
  const upper = identifier.toUpperCase();
  return PERMISSIVE_LICENSES.some((l) => l.toUpperCase() === upper);
}

function isCopyleft(identifier: string): boolean {
  const upper = identifier.toUpperCase();
  return COPYLEFT_LICENSES.some((l) => l.toUpperCase() === upper);
}

function isCopyleftPrefix(identifier: string): boolean {
  const upper = identifier.toUpperCase();
  return (
    upper.startsWith('GPL') ||
    upper.startsWith('AGPL') ||
    upper.startsWith('LGPL') ||
    upper.startsWith('MPL') ||
    upper.startsWith('EUPL') ||
    upper.startsWith('SSPL') ||
    upper.startsWith('CPAL')
  );
}

/**
 * Parse a simple SPDX expression (handles OR and AND but not complex nesting).
 * Returns individual identifiers.
 */
function parseSpdxIdentifiers(expression: string): readonly string[] {
  return expression
    .split(/\s+(?:OR|AND|WITH)\s+/i)
    .map((s) => s.replace(/[()]/g, '').trim())
    .filter((s) => s.length > 0);
}

// ─── Analyzer ─────────────────────────────────────────────

export class LicenseAnalyzer implements Analyzer {
  readonly name = 'license';
  readonly description =
    'Checks package license for compliance risks and missing license information';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    try {
      const licenseField = context.packageJson['license'];

      // Check for missing license
      if (licenseField === undefined || licenseField === null) {
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'Missing license',
          description:
            'The package does not declare a license in package.json. ' +
            'Without a license, default copyright laws apply and you may not have permission to use the code.',
          recommendation: 'Contact the maintainer to clarify the licensing terms.',
        });
        return Promise.resolve({
          analyzer: this.name,
          findings,
          duration: performance.now() - start,
        });
      }

      // Handle legacy "licenses" array format
      if (typeof licenseField !== 'string') {
        findings.push({
          analyzer: this.name,
          severity: 'low',
          title: 'Non-standard license format',
          description:
            'The license field is not a string. It may use a legacy format or be improperly defined.',
          recommendation: 'Review the package license manually.',
        });
        return Promise.resolve({
          analyzer: this.name,
          findings,
          duration: performance.now() - start,
        });
      }

      const licenseString = licenseField;

      // Check for common "no license" patterns
      if (
        licenseString === 'UNLICENSED' ||
        licenseString === 'SEE LICENSE IN LICENSE' ||
        licenseString.toUpperCase() === 'NONE'
      ) {
        const severity: Severity = licenseString === 'UNLICENSED' ? 'medium' : 'low';
        findings.push({
          analyzer: this.name,
          severity,
          title:
            licenseString === 'UNLICENSED'
              ? 'Proprietary/unlicensed package'
              : 'Custom license reference',
          description:
            `The package license is "${licenseString}". ` +
            (licenseString === 'UNLICENSED'
              ? 'This means it is proprietary and you may not have permission to use it.'
              : 'Review the referenced license file for terms.'),
          recommendation: 'Review the license terms before using this package.',
        });
        return Promise.resolve({
          analyzer: this.name,
          findings,
          duration: performance.now() - start,
        });
      }

      // Parse SPDX identifiers
      const identifiers = parseSpdxIdentifiers(licenseString);

      let hasCopyleft = false;
      let hasPermissive = false;
      let hasUnknown = false;

      for (const identifier of identifiers) {
        const normalized = normalizeIdentifier(identifier);

        if (isPermissive(normalized)) {
          hasPermissive = true;
        } else if (isCopyleft(normalized) || isCopyleftPrefix(normalized)) {
          hasCopyleft = true;
          findings.push({
            analyzer: this.name,
            severity: 'medium',
            title: `Copyleft license: ${normalized}`,
            description:
              `The package uses the ${normalized} license, which requires derivative works ` +
              'to be distributed under the same license terms.',
            recommendation:
              'Ensure your project complies with copyleft requirements, or choose an alternative package.',
          });
        } else {
          hasUnknown = true;
          findings.push({
            analyzer: this.name,
            severity: 'low',
            title: `Non-standard license: ${normalized}`,
            description: `The license identifier "${normalized}" is not a commonly recognized SPDX identifier.`,
            recommendation: 'Review the license terms manually to understand your obligations.',
          });
        }
      }

      // Info finding for permissive-only licenses
      if (hasPermissive && !hasCopyleft && !hasUnknown) {
        findings.push({
          analyzer: this.name,
          severity: 'info',
          title: `Permissive license: ${licenseString}`,
          description: `The package uses the permissive ${licenseString} license.`,
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
