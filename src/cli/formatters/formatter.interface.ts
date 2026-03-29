import type { SecurityReport } from '../../core/types.js';

/**
 * Contract for output formatters.
 *
 * Formatters transform a SecurityReport into a string representation
 * suitable for a specific output target (terminal, JSON file, CI system).
 */
export interface Formatter {
  /** Format identifier */
  readonly name: string;

  /** Transform a security report into formatted string output */
  format(report: SecurityReport): string;
}
