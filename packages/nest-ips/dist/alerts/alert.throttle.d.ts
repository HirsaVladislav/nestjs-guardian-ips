import { Store } from '../store/store.interface';
export declare class AlertThrottle {
    private readonly store;
    constructor(store: Store);
    shouldSend(ruleId: string, ip: string, throttleSec: number): Promise<boolean>;
}
