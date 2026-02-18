"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryLru = void 0;
class MemoryLru {
    constructor() {
        this.access = new Map();
    }
    touch(key, timestamp = Date.now()) {
        this.access.set(key, timestamp);
    }
    remove(key) {
        this.access.delete(key);
    }
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
