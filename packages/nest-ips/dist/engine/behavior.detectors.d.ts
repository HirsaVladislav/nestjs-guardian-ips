import { ProfilePolicy } from '../module/options';
import { Store } from '../store/store.interface';
export interface BehaviorSignal {
    id: 'spike.404' | 'spike.401' | 'spike.429' | 'stuffing' | 'burst' | 'route-not-found';
    message: string;
    counts: Record<string, number>;
    severity: 'medium' | 'high' | 'critical';
}
export declare class BehaviorDetectors {
    private readonly store;
    constructor(store: Store);
    recordRequest(ip: string, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    recordStatus(ip: string, status: number, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    recordStuffing(ip: string, username: string | undefined, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    recordRouteNotFound(ip: string, windowSec: number, max: number): Promise<BehaviorSignal[]>;
    private normalizeBehavior;
}
