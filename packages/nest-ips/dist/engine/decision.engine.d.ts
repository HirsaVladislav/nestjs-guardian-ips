import { AlertEvent, AlertIncludeField } from '../alerts/alerter.interface';
import { IpsProfileName, IpsResolvedOptions, ProfilePolicy, RateLimitKey, Rule } from '../module/options';
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
export declare class DecisionEngine {
    private readonly options;
    constructor(options: IpsResolvedOptions);
    getProfile(path: string, explicit?: IpsProfileName): IpsProfileName;
    getRateLimitKey(type: RateLimitKey, ctx: DecisionContext): string;
    profilePolicy(profile: IpsProfileName): ProfilePolicy;
    defaultBanTtl(profile: IpsProfileName): number;
    fromRule(rule: Rule): DecisionResult;
    alertEvent(ctx: DecisionContext, action: 'alert' | 'block' | 'rateLimit' | 'ban', message: string, details?: Partial<AlertEvent>): AlertEvent;
    sanitizeAlert(event: AlertEvent, include?: AlertIncludeField[]): AlertEvent;
}
