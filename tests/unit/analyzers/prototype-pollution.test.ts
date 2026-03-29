import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PrototypePollutionAnalyzer } from '../../../src/analyzers/prototype-pollution/index.js';
import { createMockContext } from '../../helpers.js';

describe('PrototypePollutionAnalyzer', () => {
  let analyzer: PrototypePollutionAnalyzer;
  let tempDir: string;

  beforeEach(async () => {
    analyzer = new PrototypePollutionAnalyzer();
    tempDir = await mkdtemp(join(tmpdir(), 'mitnick-proto-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('prototype-pollution');
    expect(analyzer.description).toBeTruthy();
  });

  it('returns no findings for clean code', async () => {
    await writeFile(
      join(tempDir, 'clean.js'),
      `
const obj = { a: 1, b: 2 };
const merged = Object.assign({}, obj, { c: 3 });
module.exports = merged;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    expect(result.findings).toHaveLength(0);
  });

  it('detects __proto__ property access via dot notation', async () => {
    await writeFile(
      join(tempDir, 'proto.js'),
      `
const obj = {};
obj.__proto__.polluted = true;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const protoFinding = result.findings.find((f) => f.title.includes('__proto__ property access'));
    expect(protoFinding).toBeDefined();
    expect(protoFinding!.severity).toBe('high');
    expect(protoFinding!.file).toBe('proto.js');
  });

  it('detects __proto__ computed property access via bracket notation', async () => {
    await writeFile(
      join(tempDir, 'computed.js'),
      `
const obj = {};
obj["__proto__"]["polluted"] = true;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const computedFinding = result.findings.find((f) =>
      f.title.includes('__proto__ computed property access'),
    );
    expect(computedFinding).toBeDefined();
    expect(computedFinding!.severity).toBe('high');
  });

  it('detects __proto__ property definition in object literal', async () => {
    await writeFile(
      join(tempDir, 'objlit.js'),
      `
const malicious = { "__proto__": { polluted: true } };
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const defFinding = result.findings.find((f) =>
      f.title.includes('__proto__ property definition'),
    );
    expect(defFinding).toBeDefined();
    expect(defFinding!.severity).toBe('high');
  });

  it('detects Object.prototype mutation', async () => {
    await writeFile(
      join(tempDir, 'objproto.js'),
      `
Object.prototype.malicious = function() { return "pwned"; };
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mutationFinding = result.findings.find((f) =>
      f.title.includes('Object.prototype mutation'),
    );
    expect(mutationFinding).toBeDefined();
    expect(mutationFinding!.severity).toBe('high');
  });

  it('detects Array.prototype mutation', async () => {
    await writeFile(
      join(tempDir, 'arrproto.js'),
      `
Array.prototype.customMethod = function() { return this; };
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mutationFinding = result.findings.find((f) =>
      f.title.includes('Array.prototype mutation'),
    );
    expect(mutationFinding).toBeDefined();
    expect(mutationFinding!.severity).toBe('high');
  });

  it('detects constructor.prototype access pattern', async () => {
    await writeFile(
      join(tempDir, 'ctor.js'),
      `
function pollute(obj, key, value) {
  obj.constructor.prototype[key] = value;
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ctorFinding = result.findings.find((f) =>
      f.title.includes('constructor.prototype access'),
    );
    expect(ctorFinding).toBeDefined();
    expect(ctorFinding!.severity).toBe('medium');
  });

  it('detects unsafe merge function (function declaration without hasOwnProperty)', async () => {
    await writeFile(
      join(tempDir, 'unsafeMerge.js'),
      `
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mergeFinding = result.findings.find((f) => f.title.includes('unsafe merge function'));
    expect(mergeFinding).toBeDefined();
    expect(mergeFinding!.severity).toBe('medium');
  });

  it('does not flag merge function with hasOwnProperty guard', async () => {
    await writeFile(
      join(tempDir, 'safeMerge.js'),
      `
function merge(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      target[key] = source[key];
    }
  }
  return target;
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mergeFinding = result.findings.find((f) => f.title.includes('unsafe merge function'));
    expect(mergeFinding).toBeUndefined();
  });

  it('does not flag merge function with Object.keys guard', async () => {
    await writeFile(
      join(tempDir, 'safeMerge2.js'),
      `
function merge(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
  return target;
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mergeFinding = result.findings.find((f) => f.title.includes('unsafe merge function'));
    expect(mergeFinding).toBeUndefined();
  });

  it('detects unsafe merge as arrow function assigned to variable', async () => {
    await writeFile(
      join(tempDir, 'arrowMerge.js'),
      `
const deepMerge = (target, source) => {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
};
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const mergeFinding = result.findings.find((f) =>
      f.title.includes('unsafe merge function: deepMerge'),
    );
    expect(mergeFinding).toBeDefined();
  });

  it('detects unsafe extend function', async () => {
    await writeFile(
      join(tempDir, 'extend.js'),
      `
function extend(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('unsafe merge function: extend'));
    expect(finding).toBeDefined();
  });

  it('analyzes files in subdirectories', async () => {
    const subDir = join(tempDir, 'lib');
    await mkdir(subDir, { recursive: true });
    await writeFile(
      join(subDir, 'util.js'),
      `
const obj = {};
obj.__proto__.bad = true;
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('__proto__'));
    expect(finding).toBeDefined();
    expect(finding!.file).toBe(join('lib', 'util.js'));
  });

  it('skips non-analyzable file extensions', async () => {
    await writeFile(join(tempDir, 'data.json'), '{"__proto__": "not code"}');

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
    const ctx = createMockContext({ extractedPath: '/tmp/nonexistent-dir-proto' });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
    expect(result.analyzer).toBe('prototype-pollution');
  });

  it('handles files with syntax errors gracefully', async () => {
    await writeFile(join(tempDir, 'broken.js'), `const x = {{{{{ not valid`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('prototype-pollution');
  });

  it('handles empty files gracefully', async () => {
    await writeFile(join(tempDir, 'empty.js'), '');

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('returns duration', async () => {
    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
