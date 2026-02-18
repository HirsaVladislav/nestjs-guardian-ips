export interface Store {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSec?: number): Promise<void>;
  del(key: string): Promise<void>;
  incr(key: string, windowSec: number): Promise<number>;
  sadd(key: string, value: string, ttlSec: number): Promise<number>;
  ready?(): Promise<void>;
  close?(): Promise<void>;
}
