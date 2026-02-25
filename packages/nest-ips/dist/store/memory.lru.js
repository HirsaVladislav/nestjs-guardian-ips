"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryLru = void 0;
/** Lightweight LRU helper used by `MemoryStore` for eviction ordering. */
class MemoryLru {
    constructor() {
        this.access = new Map();
    }
    /** Marks key as recently accessed. */
    touch(key, timestamp = Date.now()) {
        this.access.set(key, timestamp);
    }
    /** Removes key from access index. */
    remove(key) {
        this.access.delete(key);
    }
    /** Returns keys sorted from oldest to newest access time. */
    ordered(keys) {
        const list = [];
        for (const key of keys) {
            list.push({ key, ts: this.access.get(key) ?? 0 });
        }
        list.sort((a, b) => a.ts - b.ts);
        return list.map((item) => item.key);
    }
}
exports.MemoryLru = MemoryLru;
