/**
 * JSON formatter — outputs SecurityReport as pretty-printed JSON.
 *
 * Suitable for programmatic consumption and piping to other tools.
 */

import type { Formatter } from './formatter.interface.js';
import type { SecurityReport } from '../../core/types.js';

export class JsonFormatter implements Formatter {
  readonly name = 'json' as const;

  format(report: SecurityReport): string {
    return JSON.stringify(report, null, 2);
  }
}
