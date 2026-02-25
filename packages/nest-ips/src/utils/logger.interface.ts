/** Minimal logger interface accepted by `IpsModule` config. */
export interface LoggerPort {
  /** Debug-level structured log. */
  debug(message: string, meta?: Record<string, unknown>): void;
  /** Info-level structured log. */
  info(message: string, meta?: Record<string, unknown>): void;
  /** Warn-level structured log. */
  warn(message: string, meta?: Record<string, unknown>): void;
  /** Error-level structured log. */
  error(message: string, meta?: Record<string, unknown>): void;
}
