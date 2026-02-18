import { DynamicModule, Global, Module, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { IPS_OPTIONS } from './ips.tokens';
import { IpsModuleOptions } from './options';
import { clearIpsRuntime, setIpsRuntime } from './runtime.registry';
import { IpsRuntime } from './runtime';

@Global()
@Module({})
export class IpsModule implements OnModuleInit, OnModuleDestroy {
  constructor(private readonly runtime: IpsRuntime) {}

  static forRoot(options: IpsModuleOptions = {}): DynamicModule {
    return {
      module: IpsModule,
      providers: [
        {
          provide: IPS_OPTIONS,
          useValue: options,
        },
        {
          provide: IpsRuntime,
          useFactory: (input: IpsModuleOptions) => new IpsRuntime(input),
          inject: [IPS_OPTIONS],
        },
      ],
      exports: [IpsRuntime],
      global: true,
    };
  }

  async onModuleInit(): Promise<void> {
    await this.runtime.startup();
    setIpsRuntime(this.runtime);
  }

  async onModuleDestroy(): Promise<void> {
    await this.runtime.shutdown();
    clearIpsRuntime();
  }
}
