import { DynamicModule, Global, Module, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { IPS_OPTIONS } from './ips.tokens';
import { IpsModuleOptions } from './options';
import { clearIpsRuntime, setIpsRuntime } from './runtime.registry';
import { IpsRuntime } from './runtime';

@Global()
@Module({})
/** Global Nest module that creates and registers a shared `IpsRuntime`. */
export class IpsModule implements OnModuleInit, OnModuleDestroy {
  constructor(private readonly runtime: IpsRuntime) {}

  /** Creates a globally-available IPS module with provided configuration. */
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

  /** Initializes runtime store/alerts and exposes runtime through registry for middleware/filters. */
  async onModuleInit(): Promise<void> {
    await this.runtime.startup();
    setIpsRuntime(this.runtime);
  }

  /** Flushes pending report state and closes store connections. */
  async onModuleDestroy(): Promise<void> {
    await this.runtime.shutdown();
    clearIpsRuntime();
  }
}
