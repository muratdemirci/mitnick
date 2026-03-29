/**
 * Prototype Pollution Analyzer — detects __proto__ access, Object.prototype
 * mutation, constructor.prototype patterns, and recursive merge/extend
 * functions without hasOwnProperty guards.
 */

import type { Finding } from '../../core/types.js';
import { parseSource, walkAST, getNodeLine, optionalLine } from '../../utils/ast.js';
import { FileBasedAnalyzer } from '../file-based-analyzer.js';

// ─── Constants ────────────────────────────────────────────

/** Names commonly used for recursive merge/extend/assign functions. */
const MERGE_FUNCTION_NAMES = new Set([
  'merge',
  'deepMerge',
  'deep_merge',
  'deepmerge',
  'extend',
  'deepExtend',
  'deep_extend',
  'assign',
  'deepAssign',
  'deep_assign',
  'mixin',
  'defaults',
  'deepDefaults',
  'setPath',
  'setNested',
  'set',
]);

// ─── Analyzer ─────────────────────────────────────────────

export class PrototypePollutionAnalyzer extends FileBasedAnalyzer {
  readonly name = 'prototype-pollution';
  readonly description =
    'Detects prototype pollution vectors including __proto__ access and unsafe merge patterns';

  protected analyzeFile(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];

    findings.push(...this.detectProtoAccess(source, relPath));
    findings.push(...this.detectPrototypeMutation(source, relPath));
    findings.push(...this.detectConstructorPrototype(source, relPath));
    findings.push(...this.detectUnsafeMerge(source, relPath));

    return findings;
  }

  private detectProtoAccess(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (node.type === 'MemberExpression') {
        const property = node['property'] as Record<string, unknown> | undefined;
        if (property?.['type'] === 'Identifier' && property['name'] === '__proto__') {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: '__proto__ property access',
            description: 'Direct access to __proto__ can be used for prototype pollution attacks.',
            file: relPath,
            ...optionalLine(getNodeLine(node)),
            recommendation:
              'Avoid __proto__ usage. Use Object.getPrototypeOf() / Object.setPrototypeOf() if needed.',
          });
        }

        if (
          node['computed'] === true &&
          property?.['type'] === 'Literal' &&
          property['value'] === '__proto__'
        ) {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: '__proto__ computed property access',
            description:
              'Computed access to "__proto__" via bracket notation, a common prototype pollution vector.',
            file: relPath,
            ...optionalLine(getNodeLine(node)),
            recommendation: 'Sanitize property keys to exclude "__proto__".',
          });
        }
      }

      if (node.type === 'Property') {
        const key = node['key'] as Record<string, unknown> | undefined;
        if (
          (key?.['type'] === 'Identifier' && key['name'] === '__proto__') ||
          (key?.['type'] === 'Literal' && key['value'] === '__proto__')
        ) {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: '__proto__ property definition',
            description:
              'An object literal defines a "__proto__" property, which can pollute the prototype chain.',
            file: relPath,
            ...optionalLine(getNodeLine(node)),
            recommendation: 'Avoid defining __proto__ in object literals.',
          });
        }
      }
    });

    return findings;
  }

  private detectPrototypeMutation(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (node.type !== 'AssignmentExpression') return;

      const left = node['left'] as Record<string, unknown> | undefined;
      if (left?.['type'] !== 'MemberExpression') return;

      const object = left['object'] as Record<string, unknown> | undefined;
      if (object?.['type'] !== 'MemberExpression') return;

      const outerObj = object['object'] as Record<string, unknown> | undefined;
      const outerProp = object['property'] as Record<string, unknown> | undefined;

      if (
        outerObj?.['type'] === 'Identifier' &&
        outerProp?.['type'] === 'Identifier' &&
        outerProp['name'] === 'prototype'
      ) {
        const targetName = outerObj['name'] as string;
        if (targetName === 'Object' || targetName === 'Array') {
          findings.push({
            analyzer: this.name,
            severity: 'high',
            title: `${targetName}.prototype mutation detected`,
            description:
              `Assignment to ${targetName}.prototype modifies the prototype of all ${targetName} instances, ` +
              'which can lead to prototype pollution affecting the entire runtime.',
            file: relPath,
            ...optionalLine(getNodeLine(node)),
            recommendation: `Avoid modifying ${targetName}.prototype. Use utility functions or classes instead.`,
          });
        }
      }
    });

    return findings;
  }

  private detectConstructorPrototype(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (node.type !== 'MemberExpression') return;

      const property = node['property'] as Record<string, unknown> | undefined;
      if (property?.['type'] !== 'Identifier' || property['name'] !== 'prototype') return;

      const object = node['object'] as Record<string, unknown> | undefined;
      if (object?.['type'] !== 'MemberExpression') return;

      const innerProp = object['property'] as Record<string, unknown> | undefined;
      if (innerProp?.['type'] === 'Identifier' && innerProp['name'] === 'constructor') {
        findings.push({
          analyzer: this.name,
          severity: 'medium',
          title: 'constructor.prototype access pattern',
          description:
            'Access to constructor.prototype can be used to traverse and mutate the prototype chain.',
          file: relPath,
          ...optionalLine(getNodeLine(node)),
          recommendation: 'Review whether this pattern is used safely.',
        });
      }
    });

    return findings;
  }

  private detectUnsafeMerge(source: string, relPath: string): Finding[] {
    const findings: Finding[] = [];
    const parsed = parseSource(source, relPath);
    if (!parsed.ok) return findings;

    walkAST(parsed.ast, (node) => {
      if (node.type === 'FunctionDeclaration') {
        const id = node['id'] as Record<string, unknown> | undefined;
        if (id?.['type'] === 'Identifier' && typeof id['name'] === 'string') {
          const fnName = id['name'];
          if (MERGE_FUNCTION_NAMES.has(fnName)) {
            const hasGuard = this.bodyHasOwnPropertyGuard(node['body']);
            if (!hasGuard) {
              findings.push({
                analyzer: this.name,
                severity: 'medium',
                title: `Potentially unsafe merge function: ${fnName}()`,
                description:
                  `Function "${fnName}" is a merge/extend function without a hasOwnProperty check. ` +
                  'This may allow prototype pollution through attacker-controlled input.',
                file: relPath,
                ...optionalLine(getNodeLine(node)),
                recommendation:
                  'Add hasOwnProperty checks or use Object.keys()/Object.entries() to iterate safely. ' +
                  'Also filter out "__proto__", "constructor", and "prototype" keys.',
              });
            }
          }
        }
      }

      if (node.type === 'VariableDeclaration') {
        const declarations = node['declarations'];
        if (!Array.isArray(declarations)) return;

        for (const decl of declarations) {
          const declNode = decl as Record<string, unknown>;
          if (declNode['type'] !== 'VariableDeclarator') continue;

          const id = declNode['id'] as Record<string, unknown> | undefined;
          const init = declNode['init'] as Record<string, unknown> | undefined;

          if (
            id?.['type'] === 'Identifier' &&
            typeof id['name'] === 'string' &&
            MERGE_FUNCTION_NAMES.has(id['name']) &&
            init !== undefined &&
            (init['type'] === 'ArrowFunctionExpression' || init['type'] === 'FunctionExpression')
          ) {
            const hasGuard = this.bodyHasOwnPropertyGuard(init['body']);
            if (!hasGuard) {
              findings.push({
                analyzer: this.name,
                severity: 'medium',
                title: `Potentially unsafe merge function: ${String(id['name'])}()`,
                description:
                  `Function "${String(id['name'])}" appears to be a merge/extend function without ` +
                  'a hasOwnProperty check, which may allow prototype pollution.',
                file: relPath,
                ...optionalLine(getNodeLine(node)),
                recommendation:
                  'Add hasOwnProperty checks and filter dangerous keys like "__proto__".',
              });
            }
          }
        }
      }
    });

    return findings;
  }

  private bodyHasOwnPropertyGuard(body: unknown): boolean {
    if (typeof body !== 'object' || body === null) return false;

    let found = false;
    walkAST(body, (node) => {
      if (found) return false;

      if (node.type === 'CallExpression') {
        const callee = node['callee'] as Record<string, unknown> | undefined;
        if (callee?.['type'] === 'MemberExpression') {
          const prop = callee['property'] as Record<string, unknown> | undefined;
          if (prop?.['type'] === 'Identifier' && prop['name'] === 'hasOwnProperty') {
            found = true;
            return false;
          }

          // Object.hasOwn()
          const obj = callee['object'] as Record<string, unknown> | undefined;
          if (
            obj?.['type'] === 'Identifier' &&
            obj['name'] === 'Object' &&
            prop?.['type'] === 'Identifier' &&
            prop['name'] === 'hasOwn'
          ) {
            found = true;
            return false;
          }

          // Object.keys() / Object.entries()
          if (
            obj?.['type'] === 'Identifier' &&
            obj['name'] === 'Object' &&
            prop?.['type'] === 'Identifier' &&
            (prop['name'] === 'keys' || prop['name'] === 'entries')
          ) {
            found = true;
            return false;
          }
        }
      }

      return undefined;
    });

    return found;
  }
}
