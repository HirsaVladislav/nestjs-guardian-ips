import { getIpsRuntime } from '../module/runtime.registry';
import { applyHeaders } from './headers';

/**
 * Creates HTTP middleware that performs early IPS checks before Nest guards/controllers.
 * Applies baseline rate-limit headers and may short-circuit with `403`/`429`.
 */
export function createIpsMiddleware() {
  return async (req: Record<string, unknown>, res: Record<string, unknown>, next: (err?: unknown) => void) => {
    const runtime = getIpsRuntime();
    if (!runtime) {
      next();
      return;
    }

    try {
      const decision = await runtime.middlewareCheck(req);
      const baselineHeaders = runtime.getRateLimitHeaders(req);
      if (baselineHeaders) {
        applyHeaders(res, baselineHeaders);
      }

      if (decision?.blocked) {
        writeErrorResponse(res, decision.status, decision.message, decision.headers);
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

function writeErrorResponse(
  res: Record<string, unknown>,
  status: number,
  message: string,
  headers?: Record<string, string>,
): void {
  const response = {
    statusCode: status,
    message,
  };

  if (headers) {
    applyHeaders(res, headers);
  }

  if (typeof (res as { status?: (code: number) => unknown }).status === 'function') {
    const chain = (res as { status: (code: number) => { json?: (body: unknown) => void } }).status(status);
    if (chain && typeof chain.json === 'function') {
      chain.json(response);
      return;
    }
  }

  if (typeof (res as { writeHead?: (code: number, headers: Record<string, string>) => void }).writeHead === 'function') {
    (res as { writeHead: (code: number, headers: Record<string, string>) => void }).writeHead(status, {
      'content-type': 'application/json',
    });
  }

  if (typeof (res as { end?: (chunk?: string) => void }).end === 'function') {
    (res as { end: (chunk?: string) => void }).end(JSON.stringify(response));
  }
}
