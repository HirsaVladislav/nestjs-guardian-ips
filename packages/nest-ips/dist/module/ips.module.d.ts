import { DynamicModule, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { IpsModuleOptions } from './options';
import { IpsRuntime } from './runtime';
export declare class IpsModule implements OnModuleInit, OnModuleDestroy {
    private readonly runtime;
    constructor(runtime: IpsRuntime);
    /** Creates a globally-available IPS module with provided configuration. */
    static forRoot(options?: IpsModuleOptions): DynamicModule;
    /** Initializes runtime store/alerts and exposes runtime through registry for middleware/filters. */
    onModuleInit(): Promise<void>;
    /** Flushes pending report state and closes store connections. */
    onModuleDestroy(): Promise<void>;
}
