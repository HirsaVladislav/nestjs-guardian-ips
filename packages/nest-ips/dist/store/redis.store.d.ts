import { Store } from './store.interface';
/** Configuration for the built-in Redis-backed store wrapper. */
export interface RedisStoreOptions {
    url: string;
    keyPrefix?: string;
    connectTimeoutMs?: number;
    connectionRetries?: number;
    retryDelayMs?: number;
    strict: boolean;
    fallbackMaxBytes: number;
}
/** Redis store with optional fallback to `MemoryStore` when configured in `auto` mode. */
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
    /** Creates Redis-backed store and optional memory fallback. */
    constructor(options: RedisStoreOptions);
    /** Reads key from Redis or fallback store. */
    get(key: string): Promise<string | null>;
    /** Writes key to Redis or fallback store. */
    set(key: string, value: string, ttlSec?: number): Promise<void>;
    /** Deletes key from Redis or fallback store. */
    del(key: string): Promise<void>;
    /** Increments counter in Redis pipeline or fallback store. */
    incr(key: string, windowSec: number): Promise<number>;
    /** Adds member to Redis set and returns cardinality (or fallback equivalent). */
    sadd(key: string, value: string, ttlSec: number): Promise<number>;
    /** Closes Redis connection and prevents further operations. */
    close(): Promise<void>;
    /** Validates store readiness (used by `IpsRuntime.startup()`). */
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
