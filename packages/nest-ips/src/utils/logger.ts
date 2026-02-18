import { LoggerPort } from './logger.interface';

export class IpsLogger implements LoggerPort {
  constructor(private readonly scope = 'nest-ips') {}

  debug(message: string, meta?: Record<string, unknown>): void {
    this.print('DEBUG', message, meta);
  }

  info(message: string, meta?: Record<string, unknown>): void {
    this.print('INFO', message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.print('WARN', message, meta);
  }

  error(message: string, meta?: Record<string, unknown>): void {
    this.print('ERROR', message, meta);
  }

  private print(level: string, message: string, meta?: Record<string, unknown>): void {
    if (meta && Object.keys(meta).length > 0) {
      // eslint-disable-next-line no-console
      console.log(`[${this.scope}] [${level}] ${message}`, meta);
      return;
    }
    // eslint-disable-next-line no-console
    console.log(`[${this.scope}] [${level}] ${message}`);
  }
}
