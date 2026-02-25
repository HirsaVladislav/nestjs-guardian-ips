import { MemoryStore } from './memory.store';
import { createNodeRedisClient, RedisClientPort } from './redis.client';
import { Store } from './store.interface';

/** Configuration for the built-in Redis-backed store wrapper. */
export interface RedisStoreOptions {
  url: string;
  keyPrefix?: string;
  connectTimeoutMs?: number;
  connectionRetries?: number;
  retryDelayMs?: number;
  strict: boolean;
  fallbackMaxBytes: number;
}

/** Redis store with optional fallback to `MemoryStore` when configured in `auto` mode. */
export class RedisStore implements Store {
  private readonly redis: RedisClientPort;
  private readonly fallback: MemoryStore | null;
  private readonly strict: boolean;
  private readonly keyPrefix: string;
  private readonly connectionRetries: number;
  private readonly retryDelayMs: number;

  private lastConnectionErrorLogAt = 0;
  private lastConnectionErrorMessage = '';
  private fallbackLogged = false;
  private closed = false;
  private connectInFlight: Promise<void> | null = null;

  /** Creates Redis-backed store and optional memory fallback. */
  constructor(options: RedisStoreOptions) {
    this.strict = options.strict;
    this.keyPrefix = options.keyPrefix ?? 'ips:';
    this.connectionRetries = Math.max(1, options.connectionRetries ?? 10);
    this.retryDelayMs = Math.max(50, options.retryDelayMs ?? 300);
    this.redis = createNodeRedisClient(options.url, options.connectTimeoutMs ?? 5000);
    this.fallback = this.strict ? null : new MemoryStore({ maxBytes: options.fallbackMaxBytes });

    this.redis.on('error', (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      this.logConnectionError(message);
    });
  }

  /** Reads key from Redis or fallback store. */
  async get(key: string): Promise<string | null> {
    return this.runRedis(() => this.redis.get(this.k(key)), () => this.fallbackGet(key));
  }

  /** Writes key to Redis or fallback store. */
  async set(key: string, value: string, ttlSec?: number): Promise<void> {
    await this.runRedis(
      async () => {
        const redisKey = this.k(key);
        if (ttlSec && ttlSec > 0) {
          await this.redis.set(redisKey, value, { EX: ttlSec });
          return;
        }
        await this.redis.set(redisKey, value);
      },
      () => this.fallbackSet(key, value, ttlSec),
    );
  }

  /** Deletes key from Redis or fallback store. */
  async del(key: string): Promise<void> {
    await this.runRedis(
      async () => {
        await this.redis.del(this.k(key));
      },
      () => this.fallbackDel(key),
    );
  }

  /** Increments counter in Redis pipeline or fallback store. */
  async incr(key: string, windowSec: number): Promise<number> {
    return this.runRedis(
      async () => {
        const redisKey = this.k(key);
        const result = (await this.redis.multi().incr(redisKey).expire(redisKey, windowSec).exec()) as unknown[];
        const count = Array.isArray(result) ? result[0] : 0;
        return Number(count ?? 0);
      },
      () => this.fallbackIncr(key, windowSec),
    );
  }

  /** Adds member to Redis set and returns cardinality (or fallback equivalent). */
  async sadd(key: string, value: string, ttlSec: number): Promise<number> {
    return this.runRedis(
      async () => {
        const redisKey = this.k(key);
        const result = (await this.redis.multi().sAdd(redisKey, value).expire(redisKey, ttlSec).sCard(redisKey).exec()) as unknown[];
        const count = Array.isArray(result) ? result[2] : 0;
        return Number(count ?? 0);
      },
      () => this.fallbackSadd(key, value, ttlSec),
    );
  }

  /** Closes Redis connection and prevents further operations. */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }

    this.closed = true;
    try {
      if (this.redis.isOpen) {
        await this.redis.quit();
      }
    } catch {
      try {
        this.redis.disconnect();
      } catch {
        // no-op
      }
    }
  }

  /** Validates store readiness (used by `IpsRuntime.startup()`). */
  async ready(): Promise<void> {
    try {
      await this.ensureConnected();
      await this.redis.ping();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logConnectionError(message);
      if (this.strict) {
        throw new Error(`[nest-ips] Redis connection failed: ${message}`);
      }
      this.logFallback();
    }
  }

  private k(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  private async runRedis<T>(operation: () => Promise<T>, fallback: () => Promise<T>): Promise<T> {
    if (this.closed) {
      if (this.strict) {
        throw new Error('[nest-ips] Redis store is closed');
      }
      return fallback();
    }

    try {
      await this.ensureConnected();
      return await operation();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logConnectionError(message);

      if (this.strict) {
        throw new Error(`[nest-ips] Redis connection failed: ${message}`);
      }

      this.logFallback();
      return fallback();
    }
  }

  private async ensureConnected(): Promise<void> {
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
    } finally {
      this.connectInFlight = null;
    }
  }

  private async connectWithRetries(): Promise<void> {
    let lastError: unknown;

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
      } catch (error) {
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

  private async sleep(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  private logConnectionError(message: string): void {
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

  private safeDisconnect(): void {
    try {
      if (this.redis.isOpen) {
        this.redis.disconnect();
      }
    } catch {
      // no-op
    }
  }

  private logFallback(): void {
    if (this.fallbackLogged) {
      return;
    }

    this.fallbackLogged = true;
    // eslint-disable-next-line no-console
    console.error('\x1b[31m[nest-ips] Falling back to MemoryStore (store.type=auto)\x1b[0m');
  }

  private async fallbackGet(key: string): Promise<string | null> {
    if (!this.fallback) {
      return null;
    }
    return this.fallback.get(key);
  }

  private async fallbackSet(key: string, value: string, ttlSec?: number): Promise<void> {
    if (!this.fallback) {
      return;
    }
    await this.fallback.set(key, value, ttlSec);
  }

  private async fallbackDel(key: string): Promise<void> {
    if (!this.fallback) {
      return;
    }
    await this.fallback.del(key);
  }

  private async fallbackIncr(key: string, windowSec: number): Promise<number> {
    if (!this.fallback) {
      return 0;
    }
    return this.fallback.incr(key, windowSec);
  }

  private async fallbackSadd(key: string, value: string, ttlSec: number): Promise<number> {
    if (!this.fallback) {
      return 0;
    }
    return this.fallback.sadd(key, value, ttlSec);
  }
}
