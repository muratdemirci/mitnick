import { LicenseAnalyzer } from '../../../src/analyzers/license/index.js';
import { createMockContext } from '../../helpers.js';

describe('LicenseAnalyzer', () => {
  let analyzer: LicenseAnalyzer;

  beforeEach(() => {
    analyzer = new LicenseAnalyzer();
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('license');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns info finding for MIT license (permissive)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'MIT' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('info');
    expect(result.findings[0]!.title).toContain('Permissive');
    expect(result.findings[0]!.title).toContain('MIT');
  });

  it('returns info finding for Apache-2.0 license (permissive)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'Apache-2.0' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('info');
  });

  it('returns info finding for ISC license (permissive)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'ISC' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('info');
  });

  it('flags GPL-3.0 as copyleft (medium severity)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'GPL-3.0' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const copyleft = result.findings.find((f) => f.title.includes('Copyleft'));
    expect(copyleft).toBeDefined();
    expect(copyleft!.severity).toBe('medium');
    expect(copyleft!.description).toContain('derivative works');
  });

  it('flags AGPL-3.0 as copyleft', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'AGPL-3.0' },
    });
    const result = await analyzer.analyze(ctx);

    const copyleft = result.findings.find((f) => f.title.includes('Copyleft'));
    expect(copyleft).toBeDefined();
    expect(copyleft!.severity).toBe('medium');
  });

  it('flags LGPL-2.1 as copyleft', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'LGPL-2.1' },
    });
    const result = await analyzer.analyze(ctx);

    const copyleft = result.findings.find((f) => f.title.includes('Copyleft'));
    expect(copyleft).toBeDefined();
  });

  it('flags MPL-2.0 as copyleft', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'MPL-2.0' },
    });
    const result = await analyzer.analyze(ctx);

    const copyleft = result.findings.find((f) => f.title.includes('Copyleft'));
    expect(copyleft).toBeDefined();
  });

  it('flags missing license (medium severity)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('medium');
    expect(result.findings[0]!.title).toBe('Missing license');
  });

  it('flags null license as missing', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: null },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings[0]!.title).toBe('Missing license');
  });

  it('flags unknown/non-standard license (low severity)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'WTFPL' },
    });
    const result = await analyzer.analyze(ctx);

    const unknown = result.findings.find((f) => f.title.includes('Non-standard'));
    expect(unknown).toBeDefined();
    expect(unknown!.severity).toBe('low');
  });

  it('flags UNLICENSED as proprietary (medium severity)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'UNLICENSED' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings[0]!.severity).toBe('medium');
    expect(result.findings[0]!.title).toContain('Proprietary');
  });

  it('flags SEE LICENSE IN LICENSE as custom reference (low severity)', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'SEE LICENSE IN LICENSE' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings[0]!.severity).toBe('low');
    expect(result.findings[0]!.title).toContain('Custom license reference');
  });

  it('flags NONE as custom reference', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'NONE' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings[0]!.severity).toBe('low');
  });

  it('handles SPDX OR expressions', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'MIT OR Apache-2.0' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('info');
  });

  it('handles SPDX AND expressions with mixed licenses', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'MIT AND GPL-3.0' },
    });
    const result = await analyzer.analyze(ctx);

    const copyleft = result.findings.find((f) => f.title.includes('Copyleft'));
    expect(copyleft).toBeDefined();
  });

  it('handles non-string license field (legacy format)', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        license: { type: 'MIT', url: 'https://opensource.org/licenses/MIT' },
      },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.title).toContain('Non-standard license format');
    expect(result.findings[0]!.severity).toBe('low');
  });

  it('returns duration', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 'MIT' },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('never throws an error', async () => {
    const ctx = createMockContext({
      packageJson: { name: 'test', license: 12345 },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.analyzer).toBe('license');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
