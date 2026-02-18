import { Store } from './store.interface';
export interface MemoryStoreOptions {
    maxBytes?: number;
    overheadBytes?: number;
}
export declare class MemoryStore implements Store {
    private readonly maxBytes;
    private readonly overheadBytes;
    private readonly data;
    private readonly lru;
    private currentBytes;
    constructor(options?: MemoryStoreOptions);
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttlSec?: number): Promise<void>;
    del(key: string): Promise<void>;
    incr(key: string, windowSec: number): Promise<number>;
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
