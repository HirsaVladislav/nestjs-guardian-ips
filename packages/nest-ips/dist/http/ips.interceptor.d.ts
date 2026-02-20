import { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { IpsRuntime } from '../module/runtime';
export declare class IpsInterceptor implements NestInterceptor {
    private readonly runtime?;
    private readonly reflector?;
    constructor(runtime?: IpsRuntime | undefined, reflector?: Reflector | undefined);
    intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>>;
}
