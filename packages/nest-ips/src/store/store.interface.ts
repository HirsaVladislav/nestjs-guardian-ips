/** Storage abstraction used for counters, bans, throttling and behavior tracking. */
export interface Store {
  /** Gets string value by key or `null` when missing/expired. */
  get(key: string): Promise<string | null>;
  /** Sets string value with optional TTL (seconds). */
  set(key: string, value: string, ttlSec?: number): Promise<void>;
  /** Deletes key if it exists. */
  del(key: string): Promise<void>;
  /** Increments a counter and ensures it expires after `windowSec`. */
  incr(key: string, windowSec: number): Promise<number>;
  /** Adds member to a set and returns resulting cardinality (with TTL refresh). */
  sadd(key: string, value: string, ttlSec: number): Promise<number>;
  /** Optional readiness hook called on module startup. */
  ready?(): Promise<void>;
  /** Optional cleanup hook called on module shutdown. */
  close?(): Promise<void>;
}
