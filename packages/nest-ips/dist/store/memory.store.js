"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryStore = void 0;
const memory_lru_1 = require("./memory.lru");
/** In-memory store with TTL support and hard memory cap using priority-aware eviction. */
class MemoryStore {
    /** Creates a memory store with bounded memory usage. */
    constructor(options = {}) {
        this.data = new Map();
        this.lru = new memory_lru_1.MemoryLru();
        this.currentBytes = 0;
        this.maxBytes = options.maxBytes ?? 500 * 1024 * 1024;
        this.overheadBytes = options.overheadBytes ?? 96;
    }
    /** Reads string/counter/set-cardinality value by key. */
    async get(key) {
        const entry = this.readEntry(key);
        if (!entry) {
            return null;
        }
        this.lru.touch(key);
        if (entry.type === 'set') {
            return String(entry.value.size);
        }
        return String(entry.value);
    }
    /** Stores string value with optional TTL. */
    async set(key, value, ttlSec) {
        const expiresAt = ttlSec ? Date.now() + ttlSec * 1000 : Number.POSITIVE_INFINITY;
        const priority = this.priorityForKey(key);
        const next = {
            type: 'string',
            value,
            expiresAt,
            priority,
            sizeBytes: this.estimateStringEntrySize(key, value),
        };
        if (next.sizeBytes > this.maxBytes) {
            return;
        }
        this.writeEntry(key, next);
        this.ensureCapacity(key, priority);
    }
    /** Deletes a key from memory store. */
    async del(key) {
        this.deleteEntry(key);
    }
    /** Increments a counter key within a fixed TTL window. */
    async incr(key, windowSec) {
        const now = Date.now();
        const existing = this.readEntry(key);
        let nextValue = 1;
        if (existing && existing.type === 'counter' && existing.expiresAt > now) {
            nextValue = existing.value + 1;
        }
        const expiresAt = now + windowSec * 1000;
        const priority = this.priorityForKey(key);
        const next = {
            type: 'counter',
            value: nextValue,
            expiresAt,
            priority,
            sizeBytes: this.estimateStringEntrySize(key, String(nextValue)),
        };
        if (next.sizeBytes > this.maxBytes) {
            return nextValue;
        }
        this.writeEntry(key, next);
        this.ensureCapacity(key, priority);
        return nextValue;
    }
    /** Adds set member and returns unique set size within TTL window. */
    async sadd(key, value, ttlSec) {
        const now = Date.now();
        const expiresAt = now + ttlSec * 1000;
        const existing = this.readEntry(key);
        const priority = this.priorityForKey(key);
        let setMap;
        if (existing && existing.type === 'set' && existing.expiresAt > now) {
            setMap = existing.value;
        }
        else {
            setMap = new Map();
        }
        if (setMap.has(value)) {
            setMap.delete(value);
        }
        setMap.set(value, now);
        const next = {
            type: 'set',
            value: setMap,
            expiresAt,
            priority,
            sizeBytes: this.estimateSetEntrySize(key, setMap),
        };
        if (next.sizeBytes > this.maxBytes) {
            // Trim aggressively for very large sets before giving up.
            this.trimSet(next.value, Math.max(1, Math.floor(next.value.size / 4)));
            next.sizeBytes = this.estimateSetEntrySize(key, next.value);
            if (next.sizeBytes > this.maxBytes) {
                return next.value.size;
            }
        }
        this.writeEntry(key, next);
        this.ensureCapacity(key, priority);
        return next.value.size;
    }
    readEntry(key) {
        const entry = this.data.get(key);
        if (!entry) {
            return null;
        }
        if (entry.expiresAt <= Date.now()) {
            this.deleteEntry(key);
            return null;
        }
        return entry;
    }
    writeEntry(key, entry) {
        const prev = this.data.get(key);
        if (prev) {
            this.currentBytes -= prev.sizeBytes;
        }
        this.data.set(key, entry);
        this.currentBytes += entry.sizeBytes;
        this.lru.touch(key);
    }
    deleteEntry(key) {
        const prev = this.data.get(key);
        if (!prev) {
            return;
        }
        this.currentBytes -= prev.sizeBytes;
        this.data.delete(key);
        this.lru.remove(key);
    }
    ensureCapacity(protectedKey, protectedPriority = 'normal') {
        this.purgeExpired();
        if (this.currentBytes <= this.maxBytes) {
            return;
        }
        // First pass: evict low then normal keys, preserving protected key.
        this.evictByPriority('low', protectedKey);
        this.evictByPriority('normal', protectedKey);
        if (this.currentBytes <= this.maxBytes) {
            return;
        }
        // Pressure mode: shorten TTL and trim low-priority sets.
        this.applyPressureMode();
        this.purgeExpired();
        if (this.currentBytes <= this.maxBytes) {
            return;
        }
        // Second pass: allow eviction of everything except high-priority protected key.
        this.evictByPriority('low');
        this.evictByPriority('normal');
        if (protectedPriority !== 'high') {
            this.evictByPriority('high', protectedKey);
        }
        if (this.currentBytes <= this.maxBytes) {
            return;
        }
        // Last resort: even high-priority keys may be evicted to preserve hard memory cap.
        this.evictByPriority('high');
        if (this.currentBytes > this.maxBytes && protectedKey) {
            this.deleteEntry(protectedKey);
        }
    }
    evictByPriority(priority, protectedKey) {
        if (this.currentBytes <= this.maxBytes) {
            return;
        }
        const keys = [];
        for (const [key, entry] of this.data.entries()) {
            if (entry.priority === priority && key !== protectedKey) {
                keys.push(key);
            }
        }
        const ordered = this.lru.ordered(keys);
        for (const key of ordered) {
            this.deleteEntry(key);
            if (this.currentBytes <= this.maxBytes) {
                return;
            }
        }
    }
    applyPressureMode() {
        const now = Date.now();
        for (const [key, entry] of this.data.entries()) {
            if (entry.priority === 'high') {
                continue;
            }
            if (entry.expiresAt !== Number.POSITIVE_INFINITY) {
                entry.expiresAt = Math.min(entry.expiresAt, now + 10_000);
            }
            if (entry.type === 'set') {
                const targetSize = Math.max(1, Math.floor(entry.value.size / 2));
                this.trimSet(entry.value, targetSize);
                this.currentBytes -= entry.sizeBytes;
                entry.sizeBytes = this.estimateSetEntrySize(key, entry.value);
                this.currentBytes += entry.sizeBytes;
            }
        }
    }
    trimSet(values, targetSize) {
        if (values.size <= targetSize) {
            return;
        }
        const ordered = Array.from(values.entries()).sort((a, b) => a[1] - b[1]);
        const toDelete = ordered.slice(0, Math.max(0, values.size - targetSize));
        for (const [value] of toDelete) {
            values.delete(value);
        }
    }
    purgeExpired() {
        const now = Date.now();
        for (const [key, entry] of this.data.entries()) {
            if (entry.expiresAt <= now) {
                this.deleteEntry(key);
            }
        }
    }
    estimateStringEntrySize(key, value) {
        return Buffer.byteLength(key) + Buffer.byteLength(value) + this.overheadBytes;
    }
    estimateSetEntrySize(key, values) {
        let bytes = Buffer.byteLength(key) + this.overheadBytes;
        for (const item of values.keys()) {
            bytes += Buffer.byteLength(item) + 32;
        }
        return bytes;
    }
    priorityForKey(key) {
        if (key.startsWith('ban:')) {
            return 'high';
        }
        if (key.startsWith('counter:') || key.startsWith('behavior:') || key.startsWith('alert:')) {
            return 'low';
        }
        return 'normal';
    }
}
exports.MemoryStore = MemoryStore;
