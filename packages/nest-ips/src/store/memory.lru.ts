export class MemoryLru {
  private readonly access = new Map<string, number>();

  touch(key: string, timestamp = Date.now()): void {
    this.access.set(key, timestamp);
  }

  remove(key: string): void {
    this.access.delete(key);
  }

  ordered(keys: Iterable<string>): string[] {
    const list: Array<{ key: string; ts: number }> = [];
    for (const key of keys) {
      list.push({ key, ts: this.access.get(key) ?? 0 });
    }
    list.sort((a, b) => a.ts - b.ts);
    return list.map((item) => item.key);
  }
}
