import { Store } from '../store/store.interface';
/** Per-rule/IP alert throttle backed by the configured store. */
export declare class AlertThrottle {
    private readonly store;
    constructor(store: Store);
    /** Returns `true` when alert should be sent and stores throttle marker. */
    shouldSend(ruleId: string, ip: string, throttleSec: number): Promise<boolean>;
}
