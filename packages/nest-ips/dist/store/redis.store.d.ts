import { Store } from './store.interface';
export interface RedisStoreOptions {
    url: string;
    keyPrefix?: string;
    connectTimeoutMs?: number;
    connectionRetries?: number;
    retryDelayMs?: number;
    strict: boolean;
    fallbackMaxBytes: number;
}
export declare class RedisStore implements Store {
    private readonly redis;
    private readonly fallback;
    private readonly strict;
    private readonly keyPrefix;
    private readonly connectionRetries;
    private readonly retryDelayMs;
    private lastConnectionErrorLogAt;
    private lastConnectionErrorMessage;
    private fallbackLogged;
    private closed;
    private connectInFlight;
    constructor(options: RedisStoreOptions);
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttlSec?: number): Promise<void>;
    del(key: string): Promise<void>;
    incr(key: string, windowSec: number): Promise<number>;
    sadd(key: string, value: string, ttlSec: number): Promise<number>;
    close(): Promise<void>;
    ready(): Promise<void>;
    private k;
    private runRedis;
    private ensureConnected;
    private connectWithRetries;
    private sleep;
    private logConnectionError;
    private safeDisconnect;
    private logFallback;
    private fallbackGet;
    private fallbackSet;
    private fallbackDel;
    private fallbackIncr;
    private fallbackSadd;
}
