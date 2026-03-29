import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ObfuscationAnalyzer } from '../../../src/analyzers/obfuscation/index.js';
import { createMockContext } from '../../helpers.js';

describe('ObfuscationAnalyzer', () => {
  let analyzer: ObfuscationAnalyzer;
  let tempDir: string;

  beforeEach(async () => {
    analyzer = new ObfuscationAnalyzer();
    tempDir = await mkdtemp(join(tmpdir(), 'mitnick-obfuscation-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('obfuscation');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns no findings for clean code', async () => {
    await writeFile(
      join(tempDir, 'clean.js'),
      `
const add = (a, b) => a + b;
module.exports = { add };
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(0);
    expect(result.analyzer).toBe('obfuscation');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('detects eval() usage', async () => {
    await writeFile(
      join(tempDir, 'evil.js'),
      `
const code = "console.log('hi')";
eval(code);
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const evalFinding = result.findings.find((f) => f.title.includes('eval()'));
    expect(evalFinding).toBeDefined();
    expect(evalFinding!.severity).toBe('high');
    expect(evalFinding!.file).toBe('evil.js');
  });

  it('detects new Function() usage', async () => {
    await writeFile(
      join(tempDir, 'dynamic.js'),
      `
const fn = new Function("return 42");
fn();
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const fnFinding = result.findings.find((f) => f.title.includes('new Function()'));
    expect(fnFinding).toBeDefined();
    expect(fnFinding!.severity).toBe('high');
  });

  it('detects Buffer.from with base64 encoding', async () => {
    await writeFile(
      join(tempDir, 'b64.js'),
      `
const data = Buffer.from("aGVsbG8=", "base64");
console.log(data.toString());
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const b64Finding = result.findings.find((f) => f.title.includes('Buffer.from() with base64'));
    expect(b64Finding).toBeDefined();
    expect(b64Finding!.severity).toBe('high');
  });

  it('detects high-entropy strings', async () => {
    // Generate a high-entropy string (random-looking chars)
    const highEntropy = 'aB3$cD5^eF7*gH9!jK1@lM3#nO5%pQ7&rS9(tU1)vW3+xY5=zA7';
    await writeFile(join(tempDir, 'entropy.js'), `const secret = "${highEntropy}";\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const entropyFinding = result.findings.find((f) => f.title.includes('High-entropy string'));
    expect(entropyFinding).toBeDefined();
    expect(entropyFinding!.severity).toBe('high');
  });

  it('does not flag low-entropy strings', async () => {
    await writeFile(
      join(tempDir, 'normal.js'),
      `const msg = "hello world this is a test message";\n`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const entropyFinding = result.findings.find((f) => f.title.includes('High-entropy string'));
    expect(entropyFinding).toBeUndefined();
  });

  it('detects hex-encoded strings', async () => {
    await writeFile(
      join(tempDir, 'hex.js'),
      `const data = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x21";\n`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const hexFinding = result.findings.find((f) => f.title.includes('Hex-encoded'));
    expect(hexFinding).toBeDefined();
    expect(hexFinding!.severity).toBe('high');
  });

  it('detects large base64 blobs', async () => {
    const base64Blob = 'A'.repeat(300);
    await writeFile(join(tempDir, 'blob.js'), `const payload = "${base64Blob}";\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const blobFinding = result.findings.find((f) => f.title.includes('Large Base64 blob'));
    expect(blobFinding).toBeDefined();
    expect(blobFinding!.severity).toBe('high');
  });

  it('escalates when eval + obfuscation signals are both present', async () => {
    const base64Blob = 'A'.repeat(300);
    await writeFile(
      join(tempDir, 'malicious.js'),
      `
const payload = "${base64Blob}";
eval(atob(payload));
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const escalated = result.findings.find((f) =>
      f.title.includes('Eval combined with obfuscation'),
    );
    expect(escalated).toBeDefined();
    expect(escalated!.severity).toBe('critical');
  });

  it('limits high-entropy string reports to 5 per file', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 10; i++) {
      const highEntropy =
        Array.from({ length: 40 }, () => String.fromCharCode(33 + ((i * 7 + i * i) % 94))).join(
          '',
        ) +
        `_unique_${i}_` +
        Math.random().toString(36).slice(2, 20);
      lines.push(`const s${i} = "${highEntropy}";`);
    }
    await writeFile(join(tempDir, 'many-entropy.js'), lines.join('\n'));

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const entropyFindings = result.findings.filter((f) => f.title.includes('High-entropy string'));
    // At most 5 individual + 1 "omitted" message
    expect(entropyFindings.length).toBeLessThanOrEqual(5);
  });

  it('analyzes files in subdirectories', async () => {
    const subDir = join(tempDir, 'lib');
    await mkdir(subDir, { recursive: true });
    await writeFile(join(subDir, 'deep.js'), `eval("console.log('deep')");\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('eval()'));
    expect(finding).toBeDefined();
    expect(finding!.file).toBe(join('lib', 'deep.js'));
  });

  it('skips non-analyzable file extensions', async () => {
    await writeFile(join(tempDir, 'data.json'), '{"eval": "this is not code"}');

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles .ts files', async () => {
    await writeFile(join(tempDir, 'code.ts'), `const x: string = "test";\neval(x);\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('eval()'));
    expect(finding).toBeDefined();
  });

  it('handles .mjs files', async () => {
    await writeFile(join(tempDir, 'code.mjs'), `eval("test");\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('eval()'));
    expect(finding).toBeDefined();
  });

  it('returns no findings for an empty directory', async () => {
    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles empty files gracefully', async () => {
    await writeFile(join(tempDir, 'empty.js'), '');

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles non-existent extractedPath gracefully', async () => {
    const ctx = createMockContext({ extractedPath: '/tmp/nonexistent-dir-xyz' });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(0);
    expect(result.analyzer).toBe('obfuscation');
  });

  it('handles files with syntax errors gracefully', async () => {
    await writeFile(join(tempDir, 'broken.js'), `const x = {{{{{ this is not valid javascript`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    // Should not throw
    expect(result.analyzer).toBe('obfuscation');
  });
});
