/** Minimal Redis MULTI pipeline contract used by `RedisStore`. */
export interface RedisMultiPort {
    incr(key: string): RedisMultiPort;
    expire(key: string, seconds: number): RedisMultiPort;
    sAdd(key: string, value: string): RedisMultiPort;
    sCard(key: string): RedisMultiPort;
    exec(): Promise<unknown[]>;
}
/** Minimal Redis client contract (compatible with the `redis` package client). */
export interface RedisClientPort {
    readonly isOpen: boolean;
    readonly isReady: boolean;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, options?: {
        EX?: number;
    }): Promise<unknown>;
    del(key: string): Promise<number>;
    multi(): RedisMultiPort;
    connect(): Promise<void>;
    ping(): Promise<string>;
    quit(): Promise<void>;
    disconnect(): void;
    on(event: 'error', listener: (error: unknown) => void): void;
}
/** Creates a Node Redis client with conservative IPS-friendly connection options. */
export declare function createNodeRedisClient(url: string, connectTimeoutMs: number): RedisClientPort;
