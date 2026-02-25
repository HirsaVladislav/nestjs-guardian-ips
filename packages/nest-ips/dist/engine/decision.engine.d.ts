import { AlertEvent, AlertIncludeField } from '../alerts/alerter.interface';
import { IpsProfileName, IpsResolvedOptions, ProfilePolicy, RateLimitKey, Rule } from '../module/options';
/** Result of evaluating a rule/profile decision before response translation. */
export interface DecisionResult {
    blocked: boolean;
    status?: number;
    message?: string;
    action?: 'alert' | 'block' | 'rateLimit' | 'ban';
    banTtlSec?: number;
    counts?: Record<string, number>;
    ruleId?: string;
    severity?: string;
}
/** Minimal request context used for profile/rate-limit/rule decisions. */
export interface DecisionContext {
    ip: string;
    method: string;
    path: string;
    ua: string;
    profile: IpsProfileName;
    userId?: string;
    email?: string;
    username?: string;
}
/** Builds decisions, alert payloads and profile-specific derived values. */
export declare class DecisionEngine {
    private readonly options;
    constructor(options: IpsResolvedOptions);
    /** Resolves profile by explicit decorator override or path heuristics. */
    getProfile(path: string, explicit?: IpsProfileName): IpsProfileName;
    /** Builds storage key suffix for a configured rate-limit strategy. */
    getRateLimitKey(type: RateLimitKey, ctx: DecisionContext): string;
    /** Returns profile policy with fallback to `default`. */
    profilePolicy(profile: IpsProfileName): ProfilePolicy;
    /** Returns default ban TTL for profile with fallback chain. */
    defaultBanTtl(profile: IpsProfileName): number;
    /** Converts a matched rule action into a runtime decision template. */
    fromRule(rule: Rule): DecisionResult;
    /** Creates alert event payload from current decision context. */
    alertEvent(ctx: DecisionContext, action: 'alert' | 'block' | 'rateLimit' | 'ban', message: string, details?: Partial<AlertEvent>): AlertEvent;
    /** Removes fields from alert event according to privacy/include rules. */
    sanitizeAlert(event: AlertEvent, include?: AlertIncludeField[]): AlertEvent;
}
