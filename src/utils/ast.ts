/**
 * AST parsing and traversal helpers using @typescript-eslint/typescript-estree.
 *
 * All functions handle parse errors gracefully — they return empty results
 * rather than throwing, since malformed files should not crash analysis.
 */

import { parse, type AST } from '@typescript-eslint/typescript-estree';

// ─── Types ────────────────────────────────────────────────

type TSESTreeNode = AST<{ range: true; loc: true }>;

/** A generic AST node — we use Record to avoid `any`. */
type ASTNode = Record<string, unknown> & {
  readonly type: string;
  readonly loc?: {
    readonly start: { readonly line: number; readonly column: number };
    readonly end: { readonly line: number; readonly column: number };
  };
};

/** Callback for the AST walker. Return `false` to skip children. */
// eslint-disable-next-line @typescript-eslint/no-invalid-void-type
type WalkCallback = (node: ASTNode) => boolean | void;

// ─── Parse ────────────────────────────────────────────────

interface ParseResult {
  readonly ok: true;
  readonly ast: TSESTreeNode;
}

interface ParseFailure {
  readonly ok: false;
  readonly error: string;
}

type ParseOutcome = ParseResult | ParseFailure;

/**
 * Parse JavaScript or TypeScript source code into an AST.
 * Returns a discriminated union so callers can check `ok` before using the AST.
 */
export function parseSource(source: string, filePath?: string): ParseOutcome {
  try {
    const ast = parse(source, {
      range: true,
      loc: true,
      jsx: true,
      // Allow any syntax — we're analyzing, not compiling
      allowInvalidAST: true,
      suppressDeprecatedPropertyWarnings: true,
    });
    return { ok: true, ast };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: `Parse error${filePath !== undefined ? ` in ${filePath}` : ''}: ${message}`,
    };
  }
}

// ─── Walk ─────────────────────────────────────────────────

/**
 * Recursively walk all nodes in an AST, calling the visitor for each.
 * If the visitor returns `false`, children of that node are skipped.
 */
export function walkAST(node: unknown, visitor: WalkCallback): void {
  if (!isASTNode(node)) return;

  const shouldDescend = visitor(node);
  if (shouldDescend === false) return;

  for (const key of Object.keys(node)) {
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        walkAST(child, visitor);
      }
    } else if (isASTNode(value)) {
      walkAST(value, visitor);
    }
  }
}

// ─── String Extraction ───────────────────────────────────

/**
 * Extract all string literal values from source code.
 * Includes regular string literals and template literal quasis.
 * Returns an empty array on parse failure.
 */
export function extractStringLiterals(source: string, filePath?: string): readonly string[] {
  const result = parseSource(source, filePath);
  if (!result.ok) return [];

  const strings: string[] = [];

  walkAST(result.ast, (node) => {
    if (node.type === 'Literal' && typeof node['value'] === 'string') {
      strings.push(node['value']);
    }

    if (node.type === 'TemplateLiteral') {
      const quasis = node['quasis'];
      if (Array.isArray(quasis)) {
        for (const quasi of quasis) {
          if (isASTNode(quasi)) {
            const value = quasi['value'];
            if (value !== null && typeof value === 'object') {
              const raw = (value as Record<string, unknown>)['raw'];
              if (typeof raw === 'string' && raw.length > 0) {
                strings.push(raw);
              }
            }
          }
        }
      }
    }
  });

  return strings;
}

// ─── Utilities ────────────────────────────────────────────

/**
 * Check whether a value looks like an AST node (has a `type` string property).
 */
function isASTNode(value: unknown): value is ASTNode {
  return (
    value !== null &&
    typeof value === 'object' &&
    'type' in (value as Record<string, unknown>) &&
    typeof (value as Record<string, unknown>)['type'] === 'string'
  );
}

/**
 * Get the line number of an AST node, or undefined if location info is missing.
 */
export function getNodeLine(node: ASTNode): number | undefined {
  return node.loc?.start.line;
}

/**
 * Check if a node is a call expression calling a specific function name.
 * Handles both simple calls (`eval(...)`) and member calls (`process.exit(...)`).
 */
export function isCallTo(node: ASTNode, name: string): boolean {
  if (node.type !== 'CallExpression') return false;

  const callee = node['callee'];
  if (!isASTNode(callee)) return false;

  // Simple identifier: eval(...)
  if (callee.type === 'Identifier' && callee['name'] === name) {
    return true;
  }

  // Member expression: obj.method(...)
  if (callee.type === 'MemberExpression') {
    const property = callee['property'];
    if (isASTNode(property) && property.type === 'Identifier' && property['name'] === name) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a node is a member expression accessing a specific property.
 * E.g., `process.env` where property name is "env".
 */
/**
 * Build an optional line property for a Finding, omitting it when undefined.
 */
export function optionalLine(
  line: number | undefined,
): { readonly line: number } | Record<string, never> {
  return line !== undefined ? { line } : {};
}

export function isMemberAccess(node: ASTNode, objectName: string, propertyName: string): boolean {
  if (node.type !== 'MemberExpression') return false;

  const object = node['object'];
  const property = node['property'];

  if (!isASTNode(object) || !isASTNode(property)) return false;

  return (
    object.type === 'Identifier' &&
    object['name'] === objectName &&
    property.type === 'Identifier' &&
    property['name'] === propertyName
  );
}
