/** Lightweight LRU helper used by `MemoryStore` for eviction ordering. */
export class MemoryLru {
  private readonly access = new Map<string, number>();

  /** Marks key as recently accessed. */
  touch(key: string, timestamp = Date.now()): void {
    this.access.set(key, timestamp);
  }

  /** Removes key from access index. */
  remove(key: string): void {
    this.access.delete(key);
  }

  /** Returns keys sorted from oldest to newest access time. */
  ordered(keys: Iterable<string>): string[] {
    const list: Array<{ key: string; ts: number }> = [];
    for (const key of keys) {
      list.push({ key, ts: this.access.get(key) ?? 0 });
    }
    list.sort((a, b) => a.ts - b.ts);
    return list.map((item) => item.key);
  }
}
