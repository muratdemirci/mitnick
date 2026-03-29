import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NetworkCallsAnalyzer } from '../../../src/analyzers/network-calls/index.js';
import { createMockContext } from '../../helpers.js';

describe('NetworkCallsAnalyzer', () => {
  let analyzer: NetworkCallsAnalyzer;
  let tempDir: string;

  beforeEach(async () => {
    analyzer = new NetworkCallsAnalyzer();
    tempDir = await mkdtemp(join(tmpdir(), 'mitnick-network-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('has correct name and description', () => {
    expect(analyzer.name).toBe('network-calls');
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

  it('detects fetch() calls', async () => {
    await writeFile(
      join(tempDir, 'network.js'),
      `
async function getData() {
  const res = await fetch("https://api.example.com/data");
  return res.json();
}
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const fetchFinding = result.findings.find((f) => f.title.includes('fetch()'));
    expect(fetchFinding).toBeDefined();
    expect(fetchFinding!.severity).toBe('medium');
    expect(fetchFinding!.file).toBe('network.js');
  });

  it('detects http.request() calls', async () => {
    await writeFile(
      join(tempDir, 'httpreq.js'),
      `
const http = require("http");
http.request({ hostname: "example.com" });
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const httpFinding = result.findings.find((f) => f.title.includes('http.request()'));
    expect(httpFinding).toBeDefined();
    expect(httpFinding!.severity).toBe('medium');
  });

  it('detects https.get() calls', async () => {
    await writeFile(
      join(tempDir, 'httpsget.js'),
      `
const https = require("https");
https.get("https://example.com");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const httpsFinding = result.findings.find((f) => f.title.includes('https.get()'));
    expect(httpsFinding).toBeDefined();
  });

  it('detects XMLHttpRequest usage', async () => {
    await writeFile(
      join(tempDir, 'xhr.js'),
      `
const xhr = new XMLHttpRequest();
xhr.open("GET", "https://example.com");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const xhrFinding = result.findings.find((f) => f.title.includes('XMLHttpRequest'));
    expect(xhrFinding).toBeDefined();
    expect(xhrFinding!.severity).toBe('medium');
  });

  it('detects WebSocket connections', async () => {
    await writeFile(
      join(tempDir, 'ws.js'),
      `
const ws = new WebSocket("wss://example.com/socket");
ws.onmessage = (event) => console.log(event.data);
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const wsFinding = result.findings.find((f) => f.title.includes('WebSocket'));
    expect(wsFinding).toBeDefined();
    expect(wsFinding!.severity).toBe('medium');
  });

  it('detects networking library imports (axios)', async () => {
    await writeFile(
      join(tempDir, 'axiosimport.js'),
      `
import axios from "axios";
axios.get("https://api.example.com");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const axiosFinding = result.findings.find((f) =>
      f.title.includes('Networking library imported: axios'),
    );
    expect(axiosFinding).toBeDefined();
    expect(axiosFinding!.severity).toBe('medium');
  });

  it('detects networking library require (got)', async () => {
    await writeFile(
      join(tempDir, 'gotrequire.js'),
      `
const got = require("got");
got("https://api.example.com");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const gotFinding = result.findings.find((f) =>
      f.title.includes('Networking library required: got'),
    );
    expect(gotFinding).toBeDefined();
  });

  it('detects hardcoded IP addresses', async () => {
    await writeFile(
      join(tempDir, 'ips.js'),
      `
const server = "192.168.1.100";
const api = "10.0.0.5";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ipFindings = result.findings.filter((f) => f.title.includes('Hardcoded IP'));
    expect(ipFindings.length).toBeGreaterThanOrEqual(2);
    expect(ipFindings[0]!.severity).toBe('high');
  });

  it('ignores safe IPs (127.0.0.1, 0.0.0.0, 255.255.255.255)', async () => {
    await writeFile(
      join(tempDir, 'safe-ips.js'),
      `
const localhost = "127.0.0.1";
const any = "0.0.0.0";
const broadcast = "255.255.255.255";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ipFindings = result.findings.filter((f) => f.title.includes('Hardcoded IP'));
    expect(ipFindings).toHaveLength(0);
  });

  it('ignores invalid IP octets (>255)', async () => {
    await writeFile(
      join(tempDir, 'invalid-ip.js'),
      `
const notAnIp = "999.999.999.999";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ipFindings = result.findings.filter((f) => f.title.includes('Hardcoded IP'));
    expect(ipFindings).toHaveLength(0);
  });

  it('does not duplicate findings for the same API in one file', async () => {
    await writeFile(
      join(tempDir, 'multi-fetch.js'),
      `
fetch("https://a.com");
fetch("https://b.com");
fetch("https://c.com");
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const fetchFindings = result.findings.filter((f) => f.title.includes('fetch()'));
    expect(fetchFindings).toHaveLength(1);
  });

  it('does not duplicate IP findings for the same IP', async () => {
    await writeFile(
      join(tempDir, 'dup-ip.js'),
      `
const a = "10.0.0.1";
const b = "10.0.0.1";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ipFindings = result.findings.filter((f) => f.title.includes('10.0.0.1'));
    expect(ipFindings).toHaveLength(1);
  });

  it('analyzes files in subdirectories', async () => {
    const subDir = join(tempDir, 'lib');
    await mkdir(subDir, { recursive: true });
    await writeFile(join(subDir, 'api.js'), `fetch("https://example.com");\n`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const finding = result.findings.find((f) => f.title.includes('fetch()'));
    expect(finding).toBeDefined();
    expect(finding!.file).toBe(join('lib', 'api.js'));
  });

  it('skips non-analyzable file extensions', async () => {
    await writeFile(join(tempDir, 'data.json'), '{"fetch": "not code"}');

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
    const ctx = createMockContext({ extractedPath: '/tmp/nonexistent-dir-network' });
    const result = await analyzer.analyze(ctx);
    expect(result.findings).toHaveLength(0);
    expect(result.analyzer).toBe('network-calls');
  });

  it('handles files with syntax errors gracefully', async () => {
    await writeFile(join(tempDir, 'broken.js'), `const x = {{{{{ this is not valid`);

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);
    expect(result.analyzer).toBe('network-calls');
  });

  it('provides line numbers for IP findings', async () => {
    await writeFile(
      join(tempDir, 'lined.js'),
      `// line 1
// line 2
const ip = "10.0.0.42";
`,
    );

    const ctx = createMockContext({ extractedPath: tempDir });
    const result = await analyzer.analyze(ctx);

    const ipFinding = result.findings.find((f) => f.title.includes('10.0.0.42'));
    expect(ipFinding).toBeDefined();
    expect(ipFinding!.line).toBe(3);
  });
});
