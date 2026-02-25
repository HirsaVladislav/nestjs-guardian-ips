import { Store } from '../store/store.interface';
import { AlertEvent, AlertIncludeField, AlertTemplateField } from '../alerts/alerter.interface';
import { LoggerPort } from '../utils/logger.interface';
/** Detection-only (`IDS`) or blocking (`IPS`) operating mode. */
export type IpsMode = 'IDS' | 'IPS';
/** Built-in profile names supported by the module. */
export type IpsProfileName = 'default' | 'public' | 'login' | 'admin';
/** Bucket key strategies used by profile/rule rate limits. */
export type RateLimitKey = 'ip' | 'ip+path' | 'ip+username' | 'ip+email' | 'ip+id';
/** Actions available in JSON rules. */
export type RuleAction = 'log' | 'alert' | 'block' | 'rateLimit' | 'ban';
/** Client IP extraction mode. */
export type ClientIpMode = 'strict' | 'hops';
/** Path matching condition for `rule.when.path`. */
export interface PathCondition {
    equals?: string;
    prefix?: string;
    regex?: string;
}
/** JSON rule definition used by the rule engine. */
export interface Rule {
    id: string;
    rev?: number;
    enabled?: boolean;
    tags?: string[];
    severity?: 'low' | 'medium' | 'high' | 'critical';
    when?: {
        methods?: string[];
        profile?: IpsProfileName;
        path?: PathCondition;
    };
    normalize?: Array<'lowercase' | 'urlDecode' | 'normalizePath'>;
    match: Array<{
        field: 'path' | 'ua';
        contains: string;
    } | {
        field: 'path' | 'ua';
        regex: string;
    } | {
        field: 'ip';
        cidr: string;
    } | {
        field: 'headers';
        header: string;
        contains?: string;
        regex?: string;
    } | {
        field: 'query';
        key: string;
        contains?: string;
        regex?: string;
    } | {
        field: 'body';
        contains?: string;
        regex?: string;
        maxBytes?: number;
    }>;
    score?: number;
    action: RuleAction;
    rateLimit?: {
        key: RateLimitKey;
        windowSec: number;
        max: number;
    };
    ban?: {
        ttlSec: number;
    };
    block?: {
        status: 403 | 429;
        message?: string;
    };
    alert?: {
        throttleSec?: number;
        include?: AlertIncludeField[];
    };
}
/** Rate-limit policy shared by profiles and rule actions. */
export interface RateLimitPolicy {
    key: RateLimitKey;
    windowSec: number;
    max: number;
}
/** Behavior spike thresholds used for secondary detections (burst, stuffing, 404/401/429 spikes). */
export interface BehaviorPolicy {
    windowSec?: number;
    max404?: number;
    max401?: number;
    max429?: number;
    maxReq?: number;
    maxUniqueUsernames?: number;
}
/** Per-profile IPS/IDS policy. */
export interface ProfilePolicy {
    rateLimit?: RateLimitPolicy;
    allowCidrs?: string[];
    denyCidrs?: string[];
    banTtlSec?: number;
    behavior?: BehaviorPolicy;
}
/** Full set of profile policies. */
export interface IpsProfiles {
    default: ProfilePolicy;
    public: ProfilePolicy;
    login: ProfilePolicy;
    admin: ProfilePolicy;
}
/** Slack webhook alert channel configuration. */
export interface SlackAlertOptions {
    enabled?: boolean;
    webhookUrl?: string;
    throttleSec?: number;
    template?: string;
    fields?: AlertTemplateField[];
    payloadTemplate?: Record<string, unknown>;
    payloadIncludeText?: boolean;
}
/** SMTP email alert channel configuration. */
export interface EmailAlertOptions {
    enabled?: boolean;
    smtp: {
        host: string;
        port: number;
        user: string;
        pass: string;
        from: string;
        to: string[];
        secure?: boolean;
    };
    throttleSec?: number;
    subjectTemplate?: string;
    textTemplate?: string;
    fields?: AlertTemplateField[];
}
/** Periodic rate-limit summary report configuration. */
export interface IpsRateLimitReportOptions {
    /**
     * Enables periodic rate-limit summary collection and sending.
     * If omitted, defaults to `true` when `rateLimitReport` object is provided.
     */
    enabled?: boolean;
    /**
     * Report period. Supports seconds (`30`), or duration strings like `30m`, `1h`, `1d`.
     * Invalid values fall back to 30 minutes.
     */
    period?: number | string;
    /**
     * If `true`, suppresses immediate `rateLimit` alerts and sends only periodic summaries.
     * Does not affect `ban`, `block`, or behavior spike alerts.
     */
    suppressImmediate?: boolean;
    /**
     * Maximum number of grouped items included in one summary message (top by count).
     */
    maxItems?: number;
    /**
     * Maximum number of unique rate-limit groups stored in memory for the current window.
     * When full, the oldest groups are evicted first (FIFO).
     */
    maxGroups?: number;
}
/** Normalized internal rate-limit report configuration. */
export interface IpsResolvedRateLimitReportOptions {
    enabled: boolean;
    periodSec: number;
    suppressImmediate: boolean;
    maxItems: number;
    maxGroups: number;
}
/** Alert channels and alert-related features. */
export interface IpsAlertsOptions {
    slack?: SlackAlertOptions;
    email?: EmailAlertOptions;
    rateLimitReport?: IpsRateLimitReportOptions;
}
/** Normalized alert configuration used by runtime. */
export interface IpsResolvedAlertsOptions {
    slack?: SlackAlertOptions;
    email?: EmailAlertOptions;
    rateLimitReport?: IpsResolvedRateLimitReportOptions;
}
/** Controls which fields are included in alert payloads. */
export interface IpsPrivacyOptions {
    include?: Array<keyof AlertEvent>;
}
/** Redis connection tuning for built-in Redis store. */
export interface IpsRedisOptions {
    url?: string;
    keyPrefix?: string;
    connectTimeoutMs?: number;
    connectionRetries?: number;
    retryDelayMs?: number;
}
/** Store configuration (memory, redis, auto, or custom instance). */
export interface IpsStoreOptions {
    type?: 'memory' | 'redis' | 'auto';
    maxBytes?: number;
    instance?: Store;
    redis?: IpsRedisOptions;
}
/** Rule sources (file path and/or inline items). */
export interface IpsRulesOptions {
    loadFrom?: string;
    items?: Rule[];
}
/** Client IP extraction and proxy trust configuration. */
export interface IpsClientIpOptions {
    mode?: ClientIpMode;
    trustedProxyCidrs?: string | string[];
    isTrustedProxy?: (remoteIp: string) => boolean;
    hops?: number;
    headersPriority?: string[];
    denyPrivateIpsFromHeaders?: boolean;
}
/** Normalized client IP extraction configuration used by runtime. */
export interface IpsResolvedClientIpOptions {
    mode: ClientIpMode;
    trustedProxyCidrs: string[];
    isTrustedProxy?: (remoteIp: string) => boolean;
    hops: number;
    headersPriority: string[];
    denyPrivateIpsFromHeaders: boolean;
}
/** Top-level Nest IPS module configuration. */
export interface IpsModuleOptions {
    mode?: IpsMode;
    clientIp?: IpsClientIpOptions;
    logging?: boolean;
    logger?: LoggerPort;
    store?: IpsStoreOptions | Store;
    memoryCapBytes?: number;
    rules?: Rule[] | IpsRulesOptions;
    profiles?: Partial<IpsProfiles>;
    alerts?: IpsAlertsOptions;
    privacy?: IpsPrivacyOptions;
    scoreThreshold?: number;
    cheapSignatures?: {
        enabled?: boolean;
        patterns?: string[];
    };
    notFound?: {
        windowSec?: number;
        max?: number;
    };
}
/** Fully normalized runtime options resolved from `IpsModuleOptions`. */
export interface IpsResolvedOptions {
    mode: IpsMode;
    clientIp: IpsResolvedClientIpOptions;
    logging: boolean;
    logger?: LoggerPort;
    store: IpsStoreOptions | Store;
    memoryCapBytes: number;
    rules?: Rule[] | IpsRulesOptions;
    profiles: IpsProfiles;
    alerts: IpsResolvedAlertsOptions;
    privacy: Required<IpsPrivacyOptions>;
    scoreThreshold: number;
    cheapSignatures: Required<NonNullable<IpsModuleOptions['cheapSignatures']>>;
    notFound: Required<NonNullable<IpsModuleOptions['notFound']>>;
}
/** Default memory cap for built-in `MemoryStore` (500 MB). */
export declare const DEFAULT_MEMORY_CAP_BYTES: number;
/** Default header priority order used for client IP extraction. */
export declare const DEFAULT_CLIENT_IP_HEADERS: string[];
/** Default cheap-signature path fragments used by middleware prefilter. */
export declare const DEFAULT_CHEAP_SIGNATURE_PATTERNS: string[];
/** Default profile policies applied when user config omits profile overrides. */
export declare const DEFAULT_PROFILES: IpsProfiles;
/** Validates and normalizes user config into runtime-ready options. */
export declare function resolveIpsOptions(input?: IpsModuleOptions): IpsResolvedOptions;
