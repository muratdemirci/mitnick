import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { SarifFormatter } from '../../../src/cli/formatters/sarif.js';
import type { SecurityReport } from '../../../src/core/types.js';

const require = createRequire(import.meta.url);
const packageJson = require('../../../package.json') as { version: string };

// ─── Fixtures ─────────────────────────────────────────────

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    packageName: 'test-pkg',
    version: '1.0.0',
    score: 75,
    grade: 'C',
    results: [],
    totalFindings: 0,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    analyzedAt: '2024-01-01T00:00:00.000Z',
    duration: 100,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────

describe('SarifFormatter', () => {
  const formatter = new SarifFormatter();

  it('has the name "sarif"', () => {
    expect(formatter.name).toBe('sarif');
  });

  it('produces valid JSON', () => {
    const output = formatter.format(makeReport());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  // ─── SARIF v2.1.0 schema compliance ─────────────────────

  it('includes $schema pointing to SARIF v2.1.0', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
  });

  it('sets version to "2.1.0"', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.version).toBe('2.1.0');
  });

  it('contains a runs array with exactly one run', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.runs).toHaveLength(1);
  });

  it('run includes tool driver with name, version, and informationUri', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    const driver = parsed.runs[0].tool.driver;
    expect(driver.name).toBe('mitnick');
    expect(driver.version).toBe(packageJson.version);
    expect(driver.informationUri).toBeTruthy();
  });

  // ─── Empty findings ─────────────────────────────────────

  it('produces empty results array when there are no findings', () => {
    const output = formatter.format(makeReport());
    const parsed = JSON.parse(output);

    expect(parsed.runs[0].results).toEqual([]);
    expect(parsed.runs[0].tool.driver.rules).toEqual([]);
  });

  // ─── Severity mapping ──────────────────────────────────

  it('maps critical severity to "error"', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'critical', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].level).toBe('error');
  });

  it('maps high severity to "error"', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'high', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].level).toBe('error');
  });

  it('maps medium severity to "warning"', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'medium', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].level).toBe('warning');
  });

  it('maps low severity to "note"', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'low', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].level).toBe('note');
  });

  it('maps info severity to "none"', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'info', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].level).toBe('none');
  });

  // ─── Results structure ──────────────────────────────────

  it('creates results with ruleId and message', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'code scanner',
          findings: [
            {
              analyzer: 'code scanner',
              severity: 'high',
              title: 'eval usage',
              description: 'Dangerous eval() call detected',
            },
          ],
          duration: 10,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    const result = parsed.runs[0].results[0];

    expect(result.ruleId).toBe('code-scanner/eval-usage');
    expect(result.message.text).toBe('Dangerous eval() call detected');
  });

  it('uses title as message when description is empty', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            { analyzer: 'scanner', severity: 'low', title: 'Some title', description: '' },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    // Empty description => falsy => falls back to title
    expect(parsed.runs[0].results[0].message.text).toBe('Some title');
  });

  // ─── Location info ─────────────────────────────────────

  it('includes file location when file is provided', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            {
              analyzer: 'scanner',
              severity: 'medium',
              title: 't',
              description: 'd',
              file: 'src/index.js',
            },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    const locations = parsed.runs[0].results[0].locations;

    expect(locations).toHaveLength(1);
    expect(locations[0].physicalLocation.artifactLocation.uri).toBe('src/index.js');
  });

  it('includes line number in region when both file and line are provided', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            {
              analyzer: 'scanner',
              severity: 'critical',
              title: 't',
              description: 'd',
              file: 'lib/util.js',
              line: 99,
            },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    const location = parsed.runs[0].results[0].locations[0];

    expect(location.physicalLocation.artifactLocation.uri).toBe('lib/util.js');
    expect(location.physicalLocation.region.startLine).toBe(99);
  });

  it('omits locations when file is not provided', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [{ analyzer: 'scanner', severity: 'low', title: 't', description: 'd' }],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].locations).toBeUndefined();
  });

  it('omits region when file is present but line is not', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            {
              analyzer: 'scanner',
              severity: 'medium',
              title: 't',
              description: 'd',
              file: 'foo.js',
            },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    const location = parsed.runs[0].results[0].locations[0];
    expect(location.physicalLocation.region).toBeUndefined();
  });

  // ─── Rules ─────────────────────────────────────────────

  it('generates rules matching the results', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'scanner',
          findings: [
            {
              analyzer: 'scanner',
              severity: 'high',
              title: 'Rule Title',
              description: 'Rule Desc',
            },
            { analyzer: 'scanner', severity: 'low', title: 'Another', description: 'Another desc' },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    const rules = parsed.runs[0].tool.driver.rules;

    expect(rules).toHaveLength(2);
    expect(rules[0].id).toBe('scanner/Rule-Title');
    expect(rules[0].shortDescription.text).toBe('Rule Title');
    expect(rules[0].fullDescription.text).toBe('Rule Desc');
    expect(rules[0].defaultConfiguration.level).toBe('error');

    expect(rules[1].id).toBe('scanner/Another');
    expect(rules[1].shortDescription.text).toBe('Another');
    expect(rules[1].defaultConfiguration.level).toBe('note');
  });

  it('handles multiple analyzers with findings', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'a1',
          findings: [{ analyzer: 'a1', severity: 'critical', title: 'f1', description: 'd1' }],
          duration: 5,
        },
        {
          analyzer: 'a2',
          findings: [{ analyzer: 'a2', severity: 'info', title: 'f2', description: 'd2' }],
          duration: 3,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));

    expect(parsed.runs[0].results).toHaveLength(2);
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(2);
  });

  it('sanitizes analyzer names with spaces in rule IDs', () => {
    const report = makeReport({
      results: [
        {
          analyzer: 'Code Quality Scanner',
          findings: [
            {
              analyzer: 'Code Quality Scanner',
              severity: 'medium',
              title: 'test',
              description: 'test desc',
            },
          ],
          duration: 5,
        },
      ],
    });

    const parsed = JSON.parse(formatter.format(report));
    expect(parsed.runs[0].results[0].ruleId).toBe('Code-Quality-Scanner/test');
  });
});
