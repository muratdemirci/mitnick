/**
 * Structured logger with colored output and verbosity control.
 *
 * Respects the --verbose flag: debug messages are suppressed
 * unless verbose mode is enabled.
 */

import chalk from 'chalk';

// ─── Types ────────────────────────────────────────────────

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVEL_PRIORITY: Readonly<Record<LogLevel, number>> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
} as const;

interface LoggerConfig {
  readonly verbose: boolean;
  readonly silent: boolean;
}

// ─── Logger ───────────────────────────────────────────────

class Logger {
  private config: LoggerConfig = { verbose: false, silent: false };

  /**
   * Configure the logger. Call once during CLI initialization.
   */
  configure(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current verbosity setting.
   */
  get isVerbose(): boolean {
    return this.config.verbose;
  }

  /**
   * Log a debug message. Only shown when --verbose is set.
   */
  debug(message: string, context?: Readonly<Record<string, unknown>>): void {
    this.log('debug', message, context);
  }

  /**
   * Log an informational message.
   */
  info(message: string, context?: Readonly<Record<string, unknown>>): void {
    this.log('info', message, context);
  }

  /**
   * Log a warning message.
   */
  warn(message: string, context?: Readonly<Record<string, unknown>>): void {
    this.log('warn', message, context);
  }

  /**
   * Log an error message.
   */
  error(message: string, context?: Readonly<Record<string, unknown>>): void {
    this.log('error', message, context);
  }

  private log(level: LogLevel, message: string, context?: Readonly<Record<string, unknown>>): void {
    if (this.config.silent) return;

    const minLevel = this.config.verbose ? 'debug' : 'info';
    if (LOG_LEVEL_PRIORITY[level] < LOG_LEVEL_PRIORITY[minLevel]) return;

    const prefix = this.formatPrefix(level);
    const contextStr = context !== undefined ? ` ${chalk.gray(JSON.stringify(context))}` : '';
    const output = `${prefix} ${message}${contextStr}`;

    if (level === 'error') {
      console.error(output);
    } else if (level === 'warn') {
      console.warn(output);
    } else {
      console.log(output);
    }
  }

  private formatPrefix(level: LogLevel): string {
    switch (level) {
      case 'debug':
        return chalk.gray('[DEBUG]');
      case 'info':
        return chalk.blue('[INFO]');
      case 'warn':
        return chalk.yellow('[WARN]');
      case 'error':
        return chalk.red('[ERROR]');
    }
  }
}

// ─── Singleton Export ─────────────────────────────────────

/**
 * Global logger instance. Configure once with `logger.configure({ verbose: true })`
 * then use throughout the application.
 */
export const logger = new Logger();
