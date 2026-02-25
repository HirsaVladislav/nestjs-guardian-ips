import { Store } from '../store/store.interface';

/** Per-rule/IP alert throttle backed by the configured store. */
export class AlertThrottle {
  constructor(private readonly store: Store) {}

  /** Returns `true` when alert should be sent and stores throttle marker. */
  async shouldSend(ruleId: string, ip: string, throttleSec: number): Promise<boolean> {
    const key = `alert:${ruleId}:${ip}`;
    const hit = await this.store.get(key);
    if (hit) {
      return false;
    }

    await this.store.set(key, '1', throttleSec);
    return true;
  }
}
