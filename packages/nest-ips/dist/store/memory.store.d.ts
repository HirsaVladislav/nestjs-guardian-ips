import { Store } from './store.interface';
/** Configuration for built-in in-memory store. */
export interface MemoryStoreOptions {
    maxBytes?: number;
    overheadBytes?: number;
}
/** In-memory store with TTL support and hard memory cap using priority-aware eviction. */
export declare class MemoryStore implements Store {
    private readonly maxBytes;
    private readonly overheadBytes;
    private readonly data;
    private readonly lru;
    private currentBytes;
    /** Creates a memory store with bounded memory usage. */
    constructor(options?: MemoryStoreOptions);
    /** Reads string/counter/set-cardinality value by key. */
    get(key: string): Promise<string | null>;
    /** Stores string value with optional TTL. */
    set(key: string, value: string, ttlSec?: number): Promise<void>;
    /** Deletes a key from memory store. */
    del(key: string): Promise<void>;
    /** Increments a counter key within a fixed TTL window. */
    incr(key: string, windowSec: number): Promise<number>;
    /** Adds set member and returns unique set size within TTL window. */
    sadd(key: string, value: string, ttlSec: number): Promise<number>;
    private readEntry;
    private writeEntry;
    private deleteEntry;
    private ensureCapacity;
    private evictByPriority;
    private applyPressureMode;
    private trimSet;
    private purgeExpired;
    private estimateStringEntrySize;
    private estimateSetEntrySize;
    private priorityForKey;
}
