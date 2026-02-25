import { IpsModuleOptions, IpsProfileName, IpsResolvedOptions } from './options';
import { IpsHttpContext } from '../http/context';
/** Normalized middleware/guard response decision returned by runtime checks. */
export interface RuntimeDecision {
    blocked: boolean;
    status: number;
    message: string;
    headers?: Record<string, string>;
}
/** Core IPS/IDS runtime orchestrating stores, rules, behavior detectors and alert channels. */
export declare class IpsRuntime {
    private readonly logger;
    private readonly options;
    private readonly store;
    private readonly ruleEngine;
    private readonly decisionEngine;
    private readonly behavior;
    private readonly throttle;
    private readonly alerter;
    private readonly rateLimitReportRows;
    private rateLimitReportWindowStartedAtMs;
    private rateLimitReportTotal;
    private rateLimitReportTimer;
    private rateLimitReportFlushing;
    private rateLimitReportEvictedGroups;
    private rateLimitReportEvictedEvents;
    /** Creates runtime and resolves normalized options, store, rules and alert transports. */
    constructor(input?: IpsModuleOptions);
    /** Returns normalized runtime options (useful for diagnostics and tests). */
    getOptions(): IpsResolvedOptions;
    /** Initializes store connectivity and starts periodic rate-limit summary timer if enabled. */
    startup(): Promise<void>;
    /** Stops timers, flushes pending summaries and closes the configured store. */
    shutdown(): Promise<void>;
    /** Returns rate-limit headers for current request context, if a rate-limit snapshot exists. */
    getRateLimitHeaders(req: Record<string, unknown>): Record<string, string> | null;
    /** Builds or updates per-request IPS context (IP, path, profile, identity fields, request id). */
    contextFor(req: Record<string, unknown>, profileOverride?: IpsProfileName): IpsHttpContext;
    /** Runs early middleware checks (ban status, global middleware rate-limit, cheap signatures). */
    middlewareCheck(req: Record<string, unknown>): Promise<RuntimeDecision | null>;
    /** Runs guard-stage checks (CIDR policy, profile rate-limit, stuffing, rules). */
    guardCheck(req: Record<string, unknown>, profileOverride: IpsProfileName | undefined, bypass: boolean, tags?: string[]): Promise<RuntimeDecision | null>;
    /** Records request-start behavior counters (burst detection) before controller handler execution. */
    onBeforeHandler(req: Record<string, unknown>): Promise<void>;
    /** Records handler error/response status for behavior detectors (401/403/404/429 spikes). */
    onError(req: Record<string, unknown>, status: number): Promise<void>;
    /** Records unmatched-route events for route-not-found spike detection. */
    onRouteNotFound(req: Record<string, unknown>): Promise<void>;
    private applyRules;
    private evaluateRule;
    private reactToSignals;
    private react;
    private sendAlert;
    private enforceRateLimit;
    private buildRateLimitHeaders;
    private checkCidrs;
    private ipInCidr;
    private isBanned;
    private banIp;
    private banKey;
    private defaultAlertThrottleSec;
    private startRateLimitReportTimer;
    private collectAlertReport;
    private flushRateLimitReport;
    private resetRateLimitReportWindow;
    private rateLimitReportConfig;
    private resolveStore;
    private resolveAlerter;
    private isStore;
    private printRedError;
    private logDetection;
    private extractEmail;
    private extractUserId;
    private extractUsername;
    private toRecord;
    private normalizeString;
}
