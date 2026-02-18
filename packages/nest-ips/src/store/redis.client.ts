export interface RedisMultiPort {
  incr(key: string): RedisMultiPort;
  expire(key: string, seconds: number): RedisMultiPort;
  sAdd(key: string, value: string): RedisMultiPort;
  sCard(key: string): RedisMultiPort;
  exec(): Promise<unknown[]>;
}

export interface RedisClientPort {
  readonly isOpen: boolean;
  readonly isReady: boolean;

  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    options?: {
      EX?: number;
    },
  ): Promise<unknown>;
  del(key: string): Promise<number>;
  multi(): RedisMultiPort;
  connect(): Promise<void>;
  ping(): Promise<string>;
  quit(): Promise<void>;
  disconnect(): void;
  on(event: 'error', listener: (error: unknown) => void): void;
}

interface NodeRedisModule {
  createClient(input: {
    url: string;
    disableOfflineQueue: boolean;
    socket: {
      connectTimeout: number;
      reconnectStrategy: false;
    };
  }): RedisClientPort;
}

export function createNodeRedisClient(url: string, connectTimeoutMs: number): RedisClientPort {
  const redisLib = require('redis') as NodeRedisModule;
  return redisLib.createClient({
    url,
    disableOfflineQueue: true,
    socket: {
      connectTimeout: connectTimeoutMs,
      reconnectStrategy: false,
    },
  });
}

