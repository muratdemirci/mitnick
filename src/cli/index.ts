#!/usr/bin/env node

/**
 * Mitnick CLI entry point.
 *
 * Uses Commander.js to define the program structure, commands,
 * and options. Handles errors with user-friendly messages.
 */

import { Command } from 'commander';
import { createRequire } from 'node:module';
import { executeCheck } from './commands/check.js';
import {
  SEVERITY_LEVELS,
  type CheckOptions,
  type OutputFormat,
  type Severity,
} from '../core/types.js';

// ─── Version ─────────────────────────────────────────────

const require = createRequire(import.meta.url);
const packageJson = require('../../package.json') as { version: string };

// ─── Validation ──────────────────────────────────────────

function isValidSeverity(value: string): value is Severity {
  return (SEVERITY_LEVELS as readonly string[]).includes(value);
}

function parseSeverity(value: string): Severity {
  const lower = value.toLowerCase();
  if (!isValidSeverity(lower)) {
    throw new Error(`Invalid severity "${value}". Must be one of: ${SEVERITY_LEVELS.join(', ')}`);
  }
  return lower;
}

// ─── Program ─────────────────────────────────────────────

const program = new Command();

program
  .name('mitnick')
  .description('Pre-install security analysis CLI for npm packages')
  .version(packageJson.version);

program
  .command('check')
  .description('Analyze npm packages for security issues before installation')
  .argument('<packages...>', 'Package specifiers (e.g., express, lodash@4.17.21)')
  .option('--json', 'Output results as JSON', false)
  .option('--sarif', 'Output results in SARIF v2.1.0 format', false)
  .option(
    '--fail-on <severity>',
    'Exit with code 1 if findings at or above severity (critical, high, medium, low, info)',
  )
  .option('--verbose', 'Show additional analysis details', false)
  .action(
    async (
      packages: string[],
      cmdOptions: {
        json: boolean;
        sarif: boolean;
        failOn?: string;
        verbose: boolean;
      },
    ) => {
      // Determine output format
      let format: OutputFormat = 'terminal';
      if (cmdOptions.json) {
        format = 'json';
      } else if (cmdOptions.sarif) {
        format = 'sarif';
      }

      // Parse --fail-on
      let failOn: Severity | undefined;
      if (cmdOptions.failOn !== undefined) {
        failOn = parseSeverity(cmdOptions.failOn);
      }

      const baseOptions = {
        packages,
        format,
        verbose: cmdOptions.verbose,
      };

      const options: CheckOptions = failOn !== undefined ? { ...baseOptions, failOn } : baseOptions;

      const passed = await executeCheck(options);

      if (!passed) {
        process.exit(1);
      }
    },
  );

// ─── Error Handling ──────────────────────────────────────

program.exitOverride();

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (error: unknown) {
    // Commander throws for --help and --version, which is expected
    if (error instanceof Error && 'code' in error) {
      const code = (error as Error & { code: string }).code;
      if (code === 'commander.helpDisplayed' || code === 'commander.version') {
        return;
      }
    }

    const message = error instanceof Error ? error.message : String(error);
    console.error(`\nError: ${message}\n`);
    console.error('Run "mitnick --help" for usage information.\n');
    process.exit(1);
  }
}

void main();
