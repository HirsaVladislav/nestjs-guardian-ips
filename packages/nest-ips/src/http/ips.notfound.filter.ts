import { ArgumentsHost, Catch, ExceptionFilter, NotFoundException, Optional } from '@nestjs/common';
import { IpsRuntime } from '../module/runtime';
import { getIpsRuntime } from '../module/runtime.registry';
import { applyHeaders } from './headers';

@Catch(NotFoundException)
/** Optional filter that reports route-not-found spikes to IPS behavior detectors. */
export class IpsNotFoundFilter implements ExceptionFilter {
  constructor(@Optional() private readonly runtime?: IpsRuntime) {}

  /** For HTTP 404s without a matched route, records behavior signal and preserves JSON response semantics. */
  catch(exception: NotFoundException, host: ArgumentsHost): void {
    if (host.getType() !== 'http') {
      throw exception;
    }

    const http = host.switchToHttp();
    const req = http.getRequest<Record<string, unknown>>();
    const res = http.getResponse<Record<string, unknown>>();
    const runtime = this.runtime ?? getIpsRuntime();

    const route = (req as { route?: unknown }).route;
    if (!route && runtime) {
      void runtime.onRouteNotFound(req);
    }

    const payload = exception.getResponse();
    const body =
      typeof payload === 'string'
        ? {
            statusCode: 404,
            message: payload,
          }
        : payload;

    const headers = runtime?.getRateLimitHeaders(req);
    if (headers) {
      applyHeaders(res, headers);
    }

    if (typeof (res as { status?: (code: number) => unknown }).status === 'function') {
      const chain = (res as { status: (code: number) => { json?: (value: unknown) => void } }).status(404);
      if (chain && typeof chain.json === 'function') {
        chain.json(body);
        return;
      }
    }

    if (typeof (res as { writeHead?: (code: number, headers: Record<string, string>) => void }).writeHead === 'function') {
      (res as { writeHead: (code: number, headers: Record<string, string>) => void }).writeHead(404, {
        'content-type': 'application/json',
      });
    }

    if (typeof (res as { end?: (chunk?: string) => void }).end === 'function') {
      (res as { end: (chunk?: string) => void }).end(JSON.stringify(body));
    }
  }
}
