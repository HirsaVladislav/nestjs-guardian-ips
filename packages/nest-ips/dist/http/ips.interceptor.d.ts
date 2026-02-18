import { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { IpsRuntime } from '../module/runtime';
export declare class IpsInterceptor implements NestInterceptor {
    private readonly runtime?;
    constructor(runtime?: IpsRuntime | undefined);
    intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>>;
}
