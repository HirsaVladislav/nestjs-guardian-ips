import { CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IpsRuntime } from '../module/runtime';
export declare class IpsGuard implements CanActivate {
    private readonly reflector;
    private readonly runtime?;
    constructor(reflector: Reflector, runtime?: IpsRuntime | undefined);
    /** Runs guard-level IPS checks for HTTP requests and throws Nest HTTP exceptions on block decisions. */
    canActivate(context: ExecutionContext): Promise<boolean>;
}
