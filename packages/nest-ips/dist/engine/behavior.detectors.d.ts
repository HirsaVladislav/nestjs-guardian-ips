import { ProfilePolicy } from '../module/options';
import { Store } from '../store/store.interface';
/** Secondary behavior detection signal emitted from counters (burst/spikes/stuffing). */
export interface BehaviorSignal {
    id: 'spike.404' | 'spike.401' | 'spike.429' | 'stuffing' | 'burst' | 'route-not-found';
    message: string;
    counts: Record<string, number>;
    severity: 'medium' | 'high' | 'critical';
}
/** Tracks behavior counters and emits signals when profile thresholds are exceeded. */
export declare class BehaviorDetectors {
    private readonly store;
    constructor(store: Store);
    /** Records a request for burst detection. */
    recordRequest(ip: string, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    /** Records response status for auth/404/429 spike detection. */
    recordStatus(ip: string, status: number, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    /** Tracks unique usernames per IP to detect credential stuffing. */
    recordStuffing(ip: string, username: string | undefined, profile: ProfilePolicy): Promise<BehaviorSignal[]>;
    /** Tracks route-not-found bursts separately from application 404 responses. */
    recordRouteNotFound(ip: string, windowSec: number, max: number): Promise<BehaviorSignal[]>;
    private normalizeBehavior;
}
