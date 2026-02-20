import { Store } from '../store/store.interface';
import { AlertEvent, AlertIncludeField, AlertTemplateField } from '../alerts/alerter.interface';
import { LoggerPort } from '../utils/logger.interface';
export type IpsMode = 'IDS' | 'IPS';
export type IpsProfileName = 'default' | 'public' | 'login' | 'admin';
export type RateLimitKey = 'ip' | 'ip+path' | 'ip+username' | 'ip+email' | 'ip+id';
export type RuleAction = 'log' | 'alert' | 'block' | 'rateLimit' | 'ban';
export type ClientIpMode = 'strict' | 'hops';
export interface PathCondition {
    equals?: string;
    prefix?: string;
    regex?: string;
}
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
export interface RateLimitPolicy {
    key: RateLimitKey;
    windowSec: number;
    max: number;
}
export interface BehaviorPolicy {
    windowSec?: number;
    max404?: number;
    max401?: number;
    max429?: number;
    maxReq?: number;
    maxUniqueUsernames?: number;
}
export interface ProfilePolicy {
    rateLimit?: RateLimitPolicy;
    allowCidrs?: string[];
    denyCidrs?: string[];
    banTtlSec?: number;
    behavior?: BehaviorPolicy;
}
export interface IpsProfiles {
    default: ProfilePolicy;
    public: ProfilePolicy;
    login: ProfilePolicy;
    admin: ProfilePolicy;
}
export interface SlackAlertOptions {
    enabled?: boolean;
    webhookUrl?: string;
    throttleSec?: number;
    template?: string;
    fields?: AlertTemplateField[];
    payloadTemplate?: Record<string, unknown>;
    payloadIncludeText?: boolean;
}
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
export interface IpsAlertsOptions {
    slack?: SlackAlertOptions;
    email?: EmailAlertOptions;
}
export interface IpsPrivacyOptions {
    include?: Array<keyof AlertEvent>;
}
export interface IpsRedisOptions {
    url?: string;
    keyPrefix?: string;
    connectTimeoutMs?: number;
    connectionRetries?: number;
    retryDelayMs?: number;
}
export interface IpsStoreOptions {
    type?: 'memory' | 'redis' | 'auto';
    maxBytes?: number;
    instance?: Store;
    redis?: IpsRedisOptions;
}
export interface IpsRulesOptions {
    loadFrom?: string;
    items?: Rule[];
}
export interface IpsClientIpOptions {
    mode?: ClientIpMode;
    trustedProxyCidrs?: string | string[];
    isTrustedProxy?: (remoteIp: string) => boolean;
    hops?: number;
    headersPriority?: string[];
    denyPrivateIpsFromHeaders?: boolean;
}
export interface IpsResolvedClientIpOptions {
    mode: ClientIpMode;
    trustedProxyCidrs: string[];
    isTrustedProxy?: (remoteIp: string) => boolean;
    hops: number;
    headersPriority: string[];
    denyPrivateIpsFromHeaders: boolean;
}
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
export interface IpsResolvedOptions {
    mode: IpsMode;
    clientIp: IpsResolvedClientIpOptions;
    logging: boolean;
    logger?: LoggerPort;
    store: IpsStoreOptions | Store;
    memoryCapBytes: number;
    rules?: Rule[] | IpsRulesOptions;
    profiles: IpsProfiles;
    alerts: IpsAlertsOptions;
    privacy: Required<IpsPrivacyOptions>;
    scoreThreshold: number;
    cheapSignatures: Required<NonNullable<IpsModuleOptions['cheapSignatures']>>;
    notFound: Required<NonNullable<IpsModuleOptions['notFound']>>;
}
export declare const DEFAULT_MEMORY_CAP_BYTES: number;
export declare const DEFAULT_CLIENT_IP_HEADERS: string[];
export declare const DEFAULT_CHEAP_SIGNATURE_PATTERNS: string[];
export declare const DEFAULT_PROFILES: IpsProfiles;
export declare function resolveIpsOptions(input?: IpsModuleOptions): IpsResolvedOptions;
