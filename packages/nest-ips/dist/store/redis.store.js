"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisStore = void 0;
const memory_store_1 = require("./memory.store");
const redis_client_1 = require("./redis.client");
class RedisStore {
    constructor(options) {
        this.lastConnectionErrorLogAt = 0;
        this.lastConnectionErrorMessage = '';
        this.fallbackLogged = false;
        this.closed = false;
        this.connectInFlight = null;
        this.strict = options.strict;
        this.keyPrefix = options.keyPrefix ?? 'ips:';
        this.connectionRetries = Math.max(1, options.connectionRetries ?? 10);
        this.retryDelayMs = Math.max(50, options.retryDelayMs ?? 300);
        this.redis = (0, redis_client_1.createNodeRedisClient)(options.url, options.connectTimeoutMs ?? 5000);
        this.fallback = this.strict ? null : new memory_store_1.MemoryStore({ maxBytes: options.fallbackMaxBytes });
        this.redis.on('error', (error) => {
            const message = error instanceof Error ? error.message : String(error);
            this.logConnectionError(message);
        });
    }
    async get(key) {
        return this.runRedis(() => this.redis.get(this.k(key)), () => this.fallbackGet(key));
    }
    async set(key, value, ttlSec) {
        await this.runRedis(async () => {
            const redisKey = this.k(key);
            if (ttlSec && ttlSec > 0) {
                await this.redis.set(redisKey, value, { EX: ttlSec });
                return;
            }
            await this.redis.set(redisKey, value);
        }, () => this.fallbackSet(key, value, ttlSec));
    }
    async del(key) {
        await this.runRedis(async () => {
            await this.redis.del(this.k(key));
        }, () => this.fallbackDel(key));
    }
    async incr(key, windowSec) {
        return this.runRedis(async () => {
            const redisKey = this.k(key);
            const result = (await this.redis.multi().incr(redisKey).expire(redisKey, windowSec).exec());
            const count = Array.isArray(result) ? result[0] : 0;
            return Number(count ?? 0);
        }, () => this.fallbackIncr(key, windowSec));
    }
    async sadd(key, value, ttlSec) {
        return this.runRedis(async () => {
            const redisKey = this.k(key);
            const result = (await this.redis.multi().sAdd(redisKey, value).expire(redisKey, ttlSec).sCard(redisKey).exec());
            const count = Array.isArray(result) ? result[2] : 0;
            return Number(count ?? 0);
        }, () => this.fallbackSadd(key, value, ttlSec));
    }
    async close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        try {
            if (this.redis.isOpen) {
                await this.redis.quit();
            }
        }
        catch {
            try {
                this.redis.disconnect();
            }
            catch {
                // no-op
            }
        }
    }
    async ready() {
        try {
            await this.ensureConnected();
            await this.redis.ping();
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logConnectionError(message);
            if (this.strict) {
                throw new Error(`[nest-ips] Redis connection failed: ${message}`);
            }
            this.logFallback();
        }
    }
    k(key) {
        return `${this.keyPrefix}${key}`;
    }
    async runRedis(operation, fallback) {
        if (this.closed) {
            if (this.strict) {
                throw new Error('[nest-ips] Redis store is closed');
            }
            return fallback();
        }
        try {
            await this.ensureConnected();
            return await operation();
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logConnectionError(message);
            if (this.strict) {
                throw new Error(`[nest-ips] Redis connection failed: ${message}`);
            }
            this.logFallback();
            return fallback();
        }
    }
    async ensureConnected() {
        if (this.redis.isReady) {
            return;
        }
        if (this.connectInFlight) {
            await this.connectInFlight;
            return;
        }
        this.connectInFlight = this.connectWithRetries();
        try {
            await this.connectInFlight;
        }
        finally {
            this.connectInFlight = null;
        }
    }
    async connectWithRetries() {
        let lastError;
        for (let attempt = 1; attempt <= this.connectionRetries; attempt += 1) {
            if (this.closed) {
                throw new Error('[nest-ips] Redis store is closed');
            }
            try {
                if (!this.redis.isOpen) {
                    await this.redis.connect();
                }
                if (!this.redis.isReady) {
                    await this.redis.ping();
                }
                return;
            }
            catch (error) {
                lastError = error;
                const message = error instanceof Error ? error.message : String(error);
                this.logConnectionError(`${message} (attempt ${attempt}/${this.connectionRetries})`);
                this.safeDisconnect();
                if (attempt < this.connectionRetries) {
                    await this.sleep(this.retryDelayMs);
                }
            }
        }
        if (lastError instanceof Error) {
            throw lastError;
        }
        throw new Error('[nest-ips] Redis connection failed');
    }
    async sleep(ms) {
        await new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    }
    logConnectionError(message) {
        const now = Date.now();
        const isSameMessage = message === this.lastConnectionErrorMessage;
        if (isSameMessage && now - this.lastConnectionErrorLogAt < 30_000) {
            return;
        }
        this.lastConnectionErrorMessage = message;
        this.lastConnectionErrorLogAt = now;
        // eslint-disable-next-line no-console
        console.error(`\x1b[31m[nest-ips] Redis connection failed: ${message}\x1b[0m`);
    }
    safeDisconnect() {
        try {
            if (this.redis.isOpen) {
                this.redis.disconnect();
            }
        }
        catch {
            // no-op
        }
    }
    logFallback() {
        if (this.fallbackLogged) {
            return;
        }
        this.fallbackLogged = true;
        // eslint-disable-next-line no-console
        console.error('\x1b[31m[nest-ips] Falling back to MemoryStore (store.type=auto)\x1b[0m');
    }
    async fallbackGet(key) {
        if (!this.fallback) {
            return null;
        }
        return this.fallback.get(key);
    }
    async fallbackSet(key, value, ttlSec) {
        if (!this.fallback) {
            return;
        }
        await this.fallback.set(key, value, ttlSec);
    }
    async fallbackDel(key) {
        if (!this.fallback) {
            return;
        }
        await this.fallback.del(key);
    }
    async fallbackIncr(key, windowSec) {
        if (!this.fallback) {
            return 0;
        }
        return this.fallback.incr(key, windowSec);
    }
    async fallbackSadd(key, value, ttlSec) {
        if (!this.fallback) {
            return 0;
        }
        return this.fallback.sadd(key, value, ttlSec);
    }
}
exports.RedisStore = RedisStore;
