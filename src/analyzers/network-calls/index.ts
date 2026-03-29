/**
 * Network Call Analyzer — detects outbound HTTP requests, WebSocket
 * connections, hardcoded IPs, and imports of networking libraries.
 */

import type { Finding } from '../../core/types.js';
import { parseSource, walkAST, getNodeLine, isCallTo, optionalLine } from '../../utils/ast.js';
import { FileBasedAnalyzer } from '../file-based-analyzer.js';

// ─── Constants ────────────────────────────────────────────

const NETWORKING_MODULES = new Set([
  'axios',
  'got',
  'node-fetch',
  'request',
  'superagent',
  'urllib',
  'undici',
  'ky',
  'bent',
  'phin',
]);

const HARDCODED_IP_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

/** IPs that are generally safe / not suspicious. */
const SAFE_IPS = new Set(['127.0.0.1', '0.0.0.0', '255.255.255.255']);

// ─── Analyzer ─────────────────────────────────────────────

export class NetworkCallsAnalyzer extends FileBasedAnalyzer {
  readonly name = 'network-calls';
  readonly description =
    'Detects outbound network requests, hardcoded IPs, and networking library imports';

  protected analyzeFile(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    findings.push(...this.detectNetworkAPIs(source, relPath));
    findings.push(...this.detectNetworkImports(source, relPath));
    findings.push(...this.detectHardcodedIPs(source, relPath));

    return findings;
  }

  private detectNetworkAPIs(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    const seenAPIs = new Set<string>();

    walkAST(parsed.ast, (node) => {
      // fetch()
      if (isCallTo(node, 'fetch') && !seenAPIs.has('fetch')) {
        seenAPIs.add('fetch');
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'fetch() call detected',
          description: 'The package makes outbound HTTP requests using the fetch API.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Verify the fetch targets are expected and not exfiltrating data.',
        });
      }

      // http.request(), http.get(), https.request(), https.get()
      if (node.type === 'CallExpression') {
        const callee = node['callee'];
        if (typeof callee === 'object' && callee !== null) {
          const calleeNode = callee as Record<string, unknown>;
          if (calleeNode['type'] === 'MemberExpression') {
            const obj = calleeNode['object'] as Record<string, unknown> | undefined;
            const prop = calleeNode['property'] as Record<string, unknown> | undefined;
            if (
              obj?.['type'] === 'Identifier' &&
              (obj['name'] === 'http' || obj['name'] === 'https') &&
              prop?.['type'] === 'Identifier' &&
              (prop['name'] === 'request' || prop['name'] === 'get')
            ) {
              const apiName = `${obj['name'] as string}.${prop['name'] as string}`;
              if (!seenAPIs.has(apiName)) {
                seenAPIs.add(apiName);
                findings.push({
                  analyzer: this.name,
                  severity: 'medium',
                  title: `${apiName}() call detected`,
                  description: `The package uses Node.js ${apiName}() for outbound HTTP requests.`,
                  file: relPath,
                  ...optionalLine(getNodeLine(node)),
                  recommendation: 'Verify that the HTTP targets are expected endpoints.',
                });
              }
            }
          }
        }
      }

      // XMLHttpRequest
      if (
        node.type === 'NewExpression' &&
        typeof node['callee'] === 'object' &&
        node['callee'] !== null &&
        (node['callee'] as Record<string, unknown>)['type'] === 'Identifier' &&
        (node['callee'] as Record<string, unknown>)['name'] === 'XMLHttpRequest' &&
        !seenAPIs.has('XMLHttpRequest')
      ) {
        seenAPIs.add('XMLHttpRequest');
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'XMLHttpRequest usage detected',
          description: 'The package creates XMLHttpRequest instances for HTTP communication.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Review the network communication targets.',
        });
      }

      // new WebSocket(...)
      if (
        node.type === 'NewExpression' &&
        typeof node['callee'] === 'object' &&
        node['callee'] !== null &&
        (node['callee'] as Record<string, unknown>)['type'] === 'Identifier' &&
        (node['callee'] as Record<string, unknown>)['name'] === 'WebSocket' &&
        !seenAPIs.has('WebSocket')
      ) {
        seenAPIs.add('WebSocket');
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'WebSocket connection detected',
          description: 'The package creates WebSocket connections for real-time communication.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Verify the WebSocket server URL and intended use.',
        });
      }
    });

    return findings;
  }

  private detectNetworkImports(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    const seenImports = new Set<string>();

    walkAST(parsed.ast, (node) => {
      // import declarations: import axios from 'axios'
      if (node.type === 'ImportDeclaration') {
        const moduleSource = node['source'];
        if (typeof moduleSource === 'object' && moduleSource !== null) {
          const value = (moduleSource as Record<string, unknown>)['value'];
          if (
            typeof value === 'string' &&
            NETWORKING_MODULES.has(value) &&
            !seenImports.has(value)
          ) {
            seenImports.add(value);
            findings.push({
              analyzer: this.name,
              severity: 'medium',
              title: `Networking library imported: ${value}`,
              description: `The package imports "${value}", an HTTP networking library.`,
              file: relPath,
              ...optionalLine(getNodeLine(node)),
              recommendation: 'Review how this library is used in the package.',
            });
          }
        }
      }

      // require() calls: const axios = require('axios')
      if (isCallTo(node, 'require')) {
        const args = node['arguments'];
        if (Array.isArray(args) && args.length > 0) {
          const firstArg = args[0] as Record<string, unknown> | undefined;
          if (firstArg?.['type'] === 'Literal' && typeof firstArg['value'] === 'string') {
            const moduleName = firstArg['value'];
            if (NETWORKING_MODULES.has(moduleName) && !seenImports.has(moduleName)) {
              seenImports.add(moduleName);
              findings.push({
                analyzer: this.name,
                severity: 'medium',
                title: `Networking library required: ${moduleName}`,
                description: `The package requires "${moduleName}", an HTTP networking library.`,
                file: relPath,
                ...optionalLine(getNodeLine(node)),
                recommendation: 'Review how this library is used in the package.',
              });
            }
          }
        }
      }
    });

    return findings;
  }

  private detectHardcodedIPs(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const seenIPs = new Set<string>();

    const lines = source.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line === undefined) continue;
      let match: RegExpExecArray | null;
      HARDCODED_IP_REGEX.lastIndex = 0;
      while ((match = HARDCODED_IP_REGEX.exec(line)) !== null) {
        const ip = match[1];
        if (ip === undefined || SAFE_IPS.has(ip) || seenIPs.has(ip)) continue;

        const octets = ip.split('.');
        const isValidIP = octets.every((o) => {
          const n = parseInt(o, 10);
          return n >= 0 && n <= 255;
        });
        if (!isValidIP) continue;

        seenIPs.add(ip);
        findings.push({
          analyzer: this.name,
          severity: 'high',
          title: `Hardcoded IP address: ${ip}`,
          description:
            `A hardcoded IP address (${ip}) was found. ` +
            'Hardcoded IPs in packages may indicate data exfiltration or C2 communication.',
          file: relPath,
          line: i + 1,
          recommendation: 'Investigate what this IP address is used for.',
        });
      }
    }

    return findings;
  }
}
