import { DynamicModule, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { IpsModuleOptions } from './options';
import { IpsRuntime } from './runtime';
export declare class IpsModule implements OnModuleInit, OnModuleDestroy {
    private readonly runtime;
    constructor(runtime: IpsRuntime);
    static forRoot(options?: IpsModuleOptions): DynamicModule;
    onModuleInit(): Promise<void>;
    onModuleDestroy(): Promise<void>;
}
