export declare class MemoryLru {
    private readonly access;
    touch(key: string, timestamp?: number): void;
    remove(key: string): void;
    ordered(keys: Iterable<string>): string[];
}
