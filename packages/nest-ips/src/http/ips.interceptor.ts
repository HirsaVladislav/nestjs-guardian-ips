import { CallHandler, ExecutionContext, Injectable, NestInterceptor, Optional } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { IPS_BYPASS_KEY } from '../module/decorators';
import { IpsRuntime } from '../module/runtime';
import { getIpsRuntime } from '../module/runtime.registry';

@Injectable()
export class IpsInterceptor implements NestInterceptor {
  constructor(
    @Optional() private readonly runtime?: IpsRuntime,
    @Optional() private readonly reflector?: Reflector,
  ) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>> {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const bypass =
      this.reflector?.getAllAndOverride<boolean>(IPS_BYPASS_KEY, [context.getHandler(), context.getClass()]) ?? false;
    if (bypass) {
      return next.handle();
    }

    const req = context.switchToHttp().getRequest<Record<string, unknown>>();
    const runtime = this.runtime ?? getIpsRuntime();

    if (runtime) {
      await runtime.onBeforeHandler(req);
    }

    return next.handle().pipe(
      catchError((error: unknown) => {
        if (runtime) {
          const status = extractStatus(error);
          void runtime.onError(req, status);
        }
        return throwError(() => error);
      }),
    );
  }
}

function extractStatus(error: unknown): number {
  if (!error || typeof error !== 'object') {
    return 500;
  }

  const status = (error as { status?: number; statusCode?: number; getStatus?: () => number }).status;
  if (typeof status === 'number') {
    return status;
  }

  const statusCode = (error as { statusCode?: number }).statusCode;
  if (typeof statusCode === 'number') {
    return statusCode;
  }

  const getStatus = (error as { getStatus?: () => number }).getStatus;
  if (typeof getStatus === 'function') {
    return getStatus();
  }

  return 500;
}
