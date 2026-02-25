/**
 * Creates HTTP middleware that performs early IPS checks before Nest guards/controllers.
 * Applies baseline rate-limit headers and may short-circuit with `403`/`429`.
 */
export declare function createIpsMiddleware(): (req: Record<string, unknown>, res: Record<string, unknown>, next: (err?: unknown) => void) => Promise<void>;
