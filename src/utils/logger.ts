import chalk from 'chalk';

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export interface LoggerOptions {
  verbose?: boolean;
  silent?: boolean;
}

export class Logger {
  private options: LoggerOptions;

  constructor(options: LoggerOptions = {}) {
    this.options = options;
  }

  private log(level: LogLevel, message: string, data?: unknown): void {
    if (this.options.silent) return;
    
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}]`;
    const levelIcon = {
      info: 'ℹ️',
      warn: '⚠️',
      error: '❌',
      debug: '🔍'
    }[level];

    let formattedMessage = `${chalk.gray(prefix)} ${levelIcon} ${message}`;

    if (this.options.verbose) {
      formattedMessage = `${chalk.gray(prefix)} ${chalk.cyan(levelIcon)} ${message}`;
    }

    switch (level) {
      case 'info':
        console.log(formattedMessage);
        break;
      case 'warn':
        console.warn(chalk.yellow(formattedMessage));
        break;
      case 'error':
        console.error(chalk.red(formattedMessage));
        break;
      case 'debug':
        if (this.options.verbose) {
          console.debug(chalk.gray(formattedMessage));
        }
        break;
    }

    if (data !== undefined && data !== null && this.options.verbose) {
      console.log(chalk.gray(JSON.stringify(data, null, 2)));
    }
  }

  info(message: string, data?: unknown): void {
    this.log('info', message, data);
  }

  warn(message: string, data?: unknown): void {
    this.log('warn', message, data);
  }

  error(message: string, data?: unknown): void {
    this.log('error', message, data);
  }

  debug(message: string, data?: unknown): void {
    this.log('debug', message, data);
  }

  success(message: string): void {
    console.log(chalk.green(`✅ ${message}`));
  }

  start(message: string): void {
    console.log(chalk.blue(`🚀 ${message}`));
  }

  separator(): void {
    console.log(chalk.gray('─'.repeat(50)));
  }
}

export const logger = new Logger();