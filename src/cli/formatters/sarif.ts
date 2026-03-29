/**
 * SARIF v2.1.0 formatter — outputs SecurityReport in Static Analysis
 * Results Interchange Format for CI/CD integration (e.g., GitHub Security tab).
 *
 * Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import { createRequire } from 'node:module';
import type { Formatter } from './formatter.interface.js';
import type { Finding, SecurityReport, Severity } from '../../core/types.js';

const require = createRequire(import.meta.url);
const pkg = require('../../../package.json') as { version: string };

// ─── SARIF Types ─────────────────────────────────────────

interface SarifMessage {
  readonly text: string;
}

interface SarifArtifactLocation {
  readonly uri: string;
}

interface SarifPhysicalLocation {
  readonly artifactLocation: SarifArtifactLocation;
  readonly region?: {
    readonly startLine: number;
  };
}

interface SarifLocation {
  readonly physicalLocation: SarifPhysicalLocation;
}

interface SarifResult {
  readonly ruleId: string;
  readonly level: 'error' | 'warning' | 'note' | 'none';
  readonly message: SarifMessage;
  readonly locations?: readonly SarifLocation[];
}

interface SarifReportingDescriptor {
  readonly id: string;
  readonly shortDescription: SarifMessage;
  readonly fullDescription?: SarifMessage;
  readonly defaultConfiguration?: {
    readonly level: 'error' | 'warning' | 'note' | 'none';
  };
  readonly helpUri?: string;
}

interface SarifToolDriver {
  readonly name: string;
  readonly version: string;
  readonly informationUri: string;
  readonly rules: readonly SarifReportingDescriptor[];
}

interface SarifTool {
  readonly driver: SarifToolDriver;
}

interface SarifRun {
  readonly tool: SarifTool;
  readonly results: readonly SarifResult[];
}

interface SarifLog {
  readonly $schema: string;
  readonly version: string;
  readonly runs: readonly SarifRun[];
}

// ─── Severity Mapping ────────────────────────────────────

const SEVERITY_TO_SARIF_LEVEL: Readonly<Record<Severity, SarifResult['level']>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

// ─── Helpers ─────────────────────────────────────────────

function buildRuleId(finding: Finding): string {
  const sanitized = finding.analyzer.replace(/[^a-zA-Z0-9-]/g, '-');
  const titleSlug = finding.title.replace(/[^a-zA-Z0-9-]/g, '-').substring(0, 50);
  return `${sanitized}/${titleSlug}`;
}

function buildRules(findings: readonly Finding[]): readonly SarifReportingDescriptor[] {
  const ruleMap = new Map<string, SarifReportingDescriptor>();

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    if (!finding) continue;
    const ruleId = buildRuleId(finding);

    const rule: SarifReportingDescriptor = {
      id: ruleId,
      shortDescription: { text: finding.title },
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
      },
    };

    if (finding.description !== '') {
      ruleMap.set(ruleId, {
        ...rule,
        fullDescription: { text: finding.description },
      });
    } else {
      ruleMap.set(ruleId, rule);
    }
  }

  return [...ruleMap.values()];
}

function buildResults(findings: readonly Finding[]): readonly SarifResult[] {
  return findings.map((finding) => {
    const ruleId = buildRuleId(finding);
    const level = SEVERITY_TO_SARIF_LEVEL[finding.severity];

    const result: SarifResult = {
      ruleId,
      level,
      message: {
        text: finding.description !== '' ? finding.description : finding.title,
      },
      ...(finding.file !== undefined
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: finding.file },
                  ...(finding.line !== undefined ? { region: { startLine: finding.line } } : {}),
                },
              },
            ],
          }
        : {}),
    };

    return result;
  });
}

// ─── Formatter ───────────────────────────────────────────

export class SarifFormatter implements Formatter {
  readonly name = 'sarif' as const;

  format(report: SecurityReport): string {
    const allFindings = report.results.flatMap((r) => r.findings);

    const sarifLog: SarifLog = {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'mitnick',
              version: pkg.version,
              informationUri: 'https://github.com/mitnick-cli/mitnick',
              rules: buildRules(allFindings),
            },
          },
          results: buildResults(allFindings),
        },
      ],
    };

    return JSON.stringify(sarifLog, null, 2);
  }
}
