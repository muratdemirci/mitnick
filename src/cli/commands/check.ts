/**
 * "check" command handler.
 *
 * Parses package specifiers, fetches metadata and tarballs from the
 * npm registry, runs the analysis engine, and outputs formatted results.
 */

import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import ora from 'ora';
import type { Formatter } from '../formatters/formatter.interface.js';
import { TerminalFormatter } from '../formatters/terminal.js';
import { JsonFormatter } from '../formatters/json.js';
import { SarifFormatter } from '../formatters/sarif.js';
import { AnalysisEngine } from '../../core/engine.js';
import { hasFindsAtOrAbove } from '../../core/scorer.js';
import { createAnalyzers } from '../../analyzers/analyzer.registry.js';
import { fetchPackageMetadata } from '../../registry/client.js';
import { downloadAndExtract } from '../../registry/tarball.js';
import { logger } from '../../utils/logger.js';
import type {
  AnalysisContext,
  CheckOptions,
  OutputFormat,
  PackageSpecifier,
  SecurityReport,
} from '../../core/types.js';

const MAX_PACKAGE_JSON_SIZE = 5 * 1024 * 1024; // 5MB

// ─── Package Specifier Parsing ───────────────────────────

/**
 * Parse a package specifier string into name and optional version.
 *
 * Handles:
 * - "express"          -> { name: "express" }
 * - "express@4.19.2"   -> { name: "express", version: "4.19.2" }
 * - "@scope/pkg"       -> { name: "@scope/pkg" }
 * - "@scope/pkg@1.0.0" -> { name: "@scope/pkg", version: "1.0.0" }
 */
function parsePackageSpecifier(specifier: string): PackageSpecifier {
  const trimmed = specifier.trim();

  if (trimmed.startsWith('@')) {
    // Scoped package: @scope/name or @scope/name@version
    const slashIndex = trimmed.indexOf('/');
    if (slashIndex === -1) {
      return { name: trimmed };
    }

    const afterSlash = trimmed.slice(slashIndex + 1);
    const atIndex = afterSlash.indexOf('@');

    if (atIndex === -1) {
      return { name: trimmed };
    }

    const name = trimmed.slice(0, slashIndex + 1 + atIndex);
    const version = afterSlash.slice(atIndex + 1);

    if (version === '') {
      logger.warn(`Trailing "@" in specifier "${trimmed}" — defaulting to latest version`);
      return { name };
    }
    return { name, version };
  }

  // Unscoped package: name or name@version
  const atIndex = trimmed.indexOf('@');

  if (atIndex <= 0) {
    return { name: trimmed };
  }

  const name = trimmed.slice(0, atIndex);
  const version = trimmed.slice(atIndex + 1);

  if (version === '') {
    logger.warn(`Trailing "@" in specifier "${trimmed}" — defaulting to latest version`);
    return { name };
  }
  return { name, version };
}

// ─── Formatter Factory ───────────────────────────────────

function createFormatter(format: OutputFormat): Formatter {
  switch (format) {
    case 'json':
      return new JsonFormatter();
    case 'sarif':
      return new SarifFormatter();
    case 'terminal':
      return new TerminalFormatter();
  }
}

// ─── Command Handler ────────────────────────────────────

/**
 * Execute the "check" command for one or more packages.
 *
 * For each package:
 * 1. Fetch metadata from npm registry
 * 2. Download and extract tarball to temp directory
 * 3. Run all analyzers via the engine
 * 4. Format and output results
 *
 * Returns true if all packages pass (no findings at or above --fail-on),
 * false if any package fails the threshold check.
 */
export async function executeCheck(options: CheckOptions): Promise<boolean> {
  const { packages, format, failOn, verbose } = options;
  const formatter = createFormatter(format);
  const analyzers = createAnalyzers();
  const engine = new AnalysisEngine(analyzers);
  const isTerminal = format === 'terminal';

  let allPassed = true;

  for (const specifier of packages) {
    const parsed = parsePackageSpecifier(specifier);
    let tarballCleanup: (() => Promise<void>) | undefined;

    try {
      // Fetch metadata
      const metadataSpinner = isTerminal
        ? ora(`Fetching metadata for ${parsed.name}...`).start()
        : undefined;

      const registryResult = await fetchPackageMetadata(parsed.name, parsed.version);

      if (!registryResult.ok) {
        metadataSpinner?.fail(`Failed to fetch metadata for ${parsed.name}`);
        const pkg = parsed.version !== undefined ? `${parsed.name}@${parsed.version}` : parsed.name;
        console.error(`\n  Error: ${registryResult.message} (${pkg})\n`);
        allPassed = false;
        continue;
      }

      const { metadata, tarballUrl } = registryResult;
      metadataSpinner?.succeed(`Fetched metadata for ${metadata.name}@${metadata.version}`);

      // Download and extract tarball
      const tarballSpinner = isTerminal
        ? ora(`Downloading ${metadata.name}@${metadata.version}...`).start()
        : undefined;

      const tarballResult = await downloadAndExtract(tarballUrl, metadata.name);

      if (!tarballResult.ok) {
        tarballSpinner?.fail(`Failed to download ${metadata.name}@${metadata.version}`);
        console.error(`\n  Error: ${tarballResult.message}\n`);
        allPassed = false;
        continue;
      }

      tarballCleanup = tarballResult.cleanup;
      tarballSpinner?.succeed(`Extracted ${metadata.name}@${metadata.version}`);

      // Read package.json from extracted tarball
      const packageJsonPath = join(tarballResult.extractedPath, 'package.json');

      let packageJsonRaw: string;
      try {
        const packageJsonStat = await stat(packageJsonPath);
        if (packageJsonStat.size > MAX_PACKAGE_JSON_SIZE) {
          const pkg = `${metadata.name}@${metadata.version}`;
          console.error(
            `\n  Error: package.json for ${pkg} exceeds maximum allowed size of ${MAX_PACKAGE_JSON_SIZE} bytes\n`,
          );
          allPassed = false;
          continue;
        }
        packageJsonRaw = await readFile(packageJsonPath, 'utf-8');
      } catch (readError: unknown) {
        const pkg = `${metadata.name}@${metadata.version}`;
        const msg = readError instanceof Error ? readError.message : String(readError);
        console.error(`\n  Error: Failed to read package.json for ${pkg}: ${msg}\n`);
        allPassed = false;
        continue;
      }

      let packageJson: Record<string, unknown>;
      try {
        packageJson = JSON.parse(packageJsonRaw) as Record<string, unknown>;
      } catch {
        const pkg = `${metadata.name}@${metadata.version}`;
        console.error(`\n  Error: Malformed package.json for ${pkg}\n`);
        allPassed = false;
        continue;
      }

      // Build analysis context
      const context: AnalysisContext = {
        packageName: metadata.name,
        version: metadata.version,
        packageJson,
        extractedPath: tarballResult.extractedPath,
        registryMetadata: metadata,
      };

      // Run analysis
      const analysisSpinner = isTerminal ? ora('Running security analysis...').start() : undefined;

      const report: SecurityReport = await engine.analyze(context);
      analysisSpinner?.stop();

      // Output results
      const output = formatter.format(report);
      console.log(output);

      // Check fail-on threshold
      if (failOn !== undefined && hasFindsAtOrAbove(report.results, failOn)) {
        allPassed = false;

        if (isTerminal) {
          console.error(`\n  Findings at or above "${failOn}" severity detected. Failing.\n`);
        }
      }

      // Log verbose info
      if (verbose && isTerminal) {
        console.log(`  Analyzers run: ${report.results.length}`);
        console.log(`  Total findings: ${report.totalFindings}`);
        console.log(`  Analysis duration: ${report.duration}ms\n`);
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      const pkg = parsed.version !== undefined ? `${parsed.name}@${parsed.version}` : parsed.name;

      if (isTerminal) {
        console.error(`\n  Error analyzing ${pkg}: ${message}\n`);
      } else {
        console.error(JSON.stringify({ error: message, package: pkg }));
      }

      allPassed = false;
    } finally {
      if (tarballCleanup) {
        await tarballCleanup();
      }
    }
  }

  return allPassed;
}
