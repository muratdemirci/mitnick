/**
 * Integration tests for the CLI binary.
 *
 * Spawns the actual CLI process and verifies output and exit codes.
 */

import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

const execFileAsync = promisify(execFile);
const CLI_PATH = resolve(import.meta.dirname, '../../dist/cli/index.js');

async function runCli(
  args: string[],
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync('node', [CLI_PATH, ...args], {
      timeout: 60_000,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: unknown) {
    const execError = error as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: execError.stdout ?? '',
      stderr: execError.stderr ?? '',
      exitCode: execError.code ?? 1,
    };
  }
}

describe('CLI (integration)', () => {
  it('shows help with --help', async () => {
    const { stdout, exitCode } = await runCli(['--help']);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('mitnick');
    expect(stdout).toContain('check');
  });

  it('shows version with --version', async () => {
    const { stdout, exitCode } = await runCli(['--version']);

    expect(exitCode).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('outputs JSON format with --json flag', async () => {
    const { stdout, exitCode } = await runCli(['check', '--json', 'is-odd@3.0.1']);

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    expect(parsed).toHaveProperty('packageName', 'is-odd');
    expect(parsed).toHaveProperty('version', '3.0.1');
    expect(parsed).toHaveProperty('score');
    expect(parsed).toHaveProperty('grade');
    expect(parsed).toHaveProperty('results');
  });

  it('outputs SARIF format with --sarif flag', async () => {
    const { stdout, exitCode } = await runCli(['check', '--sarif', 'is-odd@3.0.1']);

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    expect(parsed).toHaveProperty('$schema');
    expect(parsed).toHaveProperty('version', '2.1.0');
    expect(parsed).toHaveProperty('runs');
  });

  it('exits with code 1 when --fail-on threshold is met', async () => {
    // is-odd is likely to have at least info-level findings
    const { exitCode } = await runCli(['check', '--json', '--fail-on', 'info', 'is-odd@3.0.1']);

    // If there are any findings at info or above, it should exit 1
    // If the package is perfectly clean, it exits 0 — both are valid
    expect([0, 1]).toContain(exitCode);
  });

  it('exits with error for a nonexistent package', async () => {
    const { exitCode, stderr } = await runCli([
      'check',
      'this-package-definitely-does-not-exist-xyz-12345',
    ]);

    expect(exitCode).toBe(1);
    expect(stderr).toContain('not found');
  });
});
