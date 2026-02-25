/** Lightweight LRU helper used by `MemoryStore` for eviction ordering. */
export declare class MemoryLru {
    private readonly access;
    /** Marks key as recently accessed. */
    touch(key: string, timestamp?: number): void;
    /** Removes key from access index. */
    remove(key: string): void;
    /** Returns keys sorted from oldest to newest access time. */
    ordered(keys: Iterable<string>): string[];
}
