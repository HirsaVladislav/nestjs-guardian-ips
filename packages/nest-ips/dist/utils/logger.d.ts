import { LoggerPort } from './logger.interface';
/** Default console logger used when custom `logger` option is not provided. */
export declare class IpsLogger implements LoggerPort {
    private readonly scope;
    constructor(scope?: string);
    debug(message: string, meta?: Record<string, unknown>): void;
    info(message: string, meta?: Record<string, unknown>): void;
    warn(message: string, meta?: Record<string, unknown>): void;
    error(message: string, meta?: Record<string, unknown>): void;
    private print;
}
