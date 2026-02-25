import { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { IpsRuntime } from '../module/runtime';
export declare class IpsInterceptor implements NestInterceptor {
    private readonly runtime?;
    private readonly reflector?;
    constructor(runtime?: IpsRuntime | undefined, reflector?: Reflector | undefined);
    /** Tracks request start and error status for HTTP requests unless route is marked with `@IpsBypass()`. */
    intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>>;
}
