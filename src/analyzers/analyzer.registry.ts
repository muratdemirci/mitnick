/**
 * Analyzer registry — factory that creates all analyzer instances.
 *
 * Each analyzer is imported from its own directory and instantiated
 * with a no-arg constructor. Adding a new analyzer requires only
 * adding an import and appending to the array (Open/Closed Principle).
 */

import type { Analyzer } from './analyzer.interface.js';
import { VulnerabilityAnalyzer } from './vulnerability/index.js';
import { InstallScriptAnalyzer } from './install-scripts/index.js';
import { TyposquattingAnalyzer } from './typosquatting/index.js';
import { ObfuscationAnalyzer } from './obfuscation/index.js';
import { NetworkCallsAnalyzer } from './network-calls/index.js';
import { SensitiveDataAnalyzer } from './sensitive-data/index.js';
import { LicenseAnalyzer } from './license/index.js';
import { MaintainerAnalyzer } from './maintainer/index.js';
import { DependencyConfusionAnalyzer } from './dependency-confusion/index.js';
import { DormantPackageAnalyzer } from './dormant-package/index.js';
import { PrototypePollutionAnalyzer } from './prototype-pollution/index.js';

/**
 * Create and return all registered analyzer instances.
 *
 * Returns a readonly array to prevent mutation of the registry
 * after creation. The engine receives this array via DI.
 */
export function createAnalyzers(): readonly Analyzer[] {
  return [
    new VulnerabilityAnalyzer(),
    new InstallScriptAnalyzer(),
    new TyposquattingAnalyzer(),
    new ObfuscationAnalyzer(),
    new NetworkCallsAnalyzer(),
    new SensitiveDataAnalyzer(),
    new LicenseAnalyzer(),
    new MaintainerAnalyzer(),
    new DependencyConfusionAnalyzer(),
    new DormantPackageAnalyzer(),
    new PrototypePollutionAnalyzer(),
  ] as const;
}
