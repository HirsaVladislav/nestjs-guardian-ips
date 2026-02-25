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
  match: Array<
    | { field: 'path' | 'ua'; contains: string }
    | { field: 'path' | 'ua'; regex: string }
    | { field: 'ip'; cidr: string }
    | { field: 'headers'; header: string; contains?: string; regex?: string }
    | { field: 'query'; key: string; contains?: string; regex?: string }
    | { field: 'body'; contains?: string; regex?: string; maxBytes?: number }
  >;
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
   * Enables periodic rate-limit summary reports.
   * Alias of `collect` for readability.
   */
  enabled?: boolean;
  /**
   * Enables periodic rate-limit summary collection and sending.
   * If omitted, defaults to `false`.
   */
  collect?: boolean;
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
export const DEFAULT_MEMORY_CAP_BYTES = 500 * 1024 * 1024;
/** Default header priority order used for client IP extraction. */
export const DEFAULT_CLIENT_IP_HEADERS = [
  'cf-connecting-ip',
  'true-client-ip',
  'fastly-client-ip',
  'x-forwarded-for',
  'forwarded',
  'x-real-ip',
];
/** Default cheap-signature path fragments used by middleware prefilter. */
export const DEFAULT_CHEAP_SIGNATURE_PATTERNS = [
  '/.env',
  '/.git',
  '/.svn',
  '/.hg',
  '/.ds_store',
  '/wp-admin',
  '/wp-login.php',
  '/phpmyadmin',
  '/server-status',
  '..%2f',
  '../',
  '..\\',
  '%2e%2e%2f',
  '%2e%2e\\',
];

/** Default profile policies applied when user config omits profile overrides. */
export const DEFAULT_PROFILES: IpsProfiles = {
  default: {
    rateLimit: { key: 'ip', windowSec: 60, max: 120 },
    banTtlSec: 600,
    behavior: { windowSec: 60, max404: 30, max401: 20, max429: 20, maxReq: 300, maxUniqueUsernames: 20 },
  },
  public: {
    rateLimit: { key: 'ip', windowSec: 60, max: 300 },
    banTtlSec: 300,
    behavior: { windowSec: 60, max404: 40, max401: 30, max429: 30, maxReq: 400, maxUniqueUsernames: 40 },
  },
  login: {
    rateLimit: { key: 'ip+id', windowSec: 120, max: 8 },
    banTtlSec: 900,
    behavior: { windowSec: 120, max404: 20, max401: 10, max429: 10, maxReq: 120, maxUniqueUsernames: 10 },
  },
  admin: {
    rateLimit: { key: 'ip', windowSec: 60, max: 30 },
    banTtlSec: 1800,
    behavior: { windowSec: 60, max404: 10, max401: 8, max429: 8, maxReq: 80, maxUniqueUsernames: 5 },
  },
};

/** Validates and normalizes user config into runtime-ready options. */
export function resolveIpsOptions(input: IpsModuleOptions = {}): IpsResolvedOptions {
  const slack = input.alerts?.slack;
  const slackConfigured = Boolean(slack);
  const slackEnabled = resolveEnabled(
    slack?.enabled,
    slackConfigured,
  );
  if (slackConfigured && slackEnabled && !slack?.webhookUrl?.trim()) {
    throw new Error('[nest-ips] alerts.slack.webhookUrl is required when alerts.slack is configured');
  }

  const email = input.alerts?.email;
  const emailConfigured = Boolean(email);
  const emailHasSmtp = hasValidEmailSmtp(email?.smtp);
  const emailEnabled = resolveEnabled(
    email?.enabled,
    emailConfigured,
  );
  if (emailConfigured && emailEnabled && !emailHasSmtp) {
    throw new Error(
      '[nest-ips] alerts.email.smtp.{host,port,user,pass,from,to[]} is required when alerts.email is configured',
    );
  }
  const rateLimitReport = resolveRateLimitReportOptions(input.alerts?.rateLimitReport);

  const cheapPatterns = input.cheapSignatures?.patterns ?? DEFAULT_CHEAP_SIGNATURE_PATTERNS;
  const cheapSignaturesEnabled = input.cheapSignatures?.enabled ?? true;
  const clientIp = resolveClientIpOptions(input);

  return {
    mode: input.mode ?? 'IPS',
    clientIp,
    logging: input.logging ?? true,
    logger: input.logger,
    store: input.store ?? { type: 'memory', maxBytes: input.memoryCapBytes ?? DEFAULT_MEMORY_CAP_BYTES },
    memoryCapBytes: input.memoryCapBytes ?? DEFAULT_MEMORY_CAP_BYTES,
    rules: input.rules,
    profiles: {
      default: { ...DEFAULT_PROFILES.default, ...input.profiles?.default },
      public: { ...DEFAULT_PROFILES.public, ...input.profiles?.public },
      login: { ...DEFAULT_PROFILES.login, ...input.profiles?.login },
      admin: { ...DEFAULT_PROFILES.admin, ...input.profiles?.admin },
    },
    alerts: {
      slack: slack ? { ...slack, enabled: slackEnabled } : undefined,
      email: email ? { ...email, enabled: emailEnabled } : undefined,
      rateLimitReport,
    },
    privacy: {
      include: input.privacy?.include ?? [
        'ts',
        'mode',
        'action',
        'ip',
        'method',
        'path',
        'ua',
        'profile',
        'ruleId',
        'severity',
        'counts',
        'message',
      ],
    },
    scoreThreshold: input.scoreThreshold ?? 100,
    cheapSignatures: {
      enabled: cheapSignaturesEnabled,
      patterns: cheapPatterns,
    },
    notFound: {
      windowSec: input.notFound?.windowSec ?? 60,
      max: input.notFound?.max ?? 30,
    },
  };
}

function resolveEnabled(explicit: boolean | undefined, hasParams: boolean): boolean {
  if (typeof explicit === 'boolean') {
    return explicit;
  }
  return hasParams;
}

function resolveRateLimitReportOptions(
  input: IpsRateLimitReportOptions | undefined,
): IpsResolvedRateLimitReportOptions | undefined {
  if (!input) {
    return undefined;
  }

  const enabled = input.collect ?? input.enabled ?? false;
  const periodSec = normalizeDurationSec(input.period, 1800);
  const maxItems = normalizePositiveInt(input.maxItems, 50);
  const maxGroups = normalizePositiveInt(input.maxGroups, 2000);

  return {
    enabled,
    suppressImmediate: input.suppressImmediate ?? true,
    maxItems,
    maxGroups,
    periodSec,
  };
}

function resolveClientIpOptions(input: IpsModuleOptions): IpsResolvedClientIpOptions {
  const next = input.clientIp;
  if (!next) {
    return {
      mode: 'strict',
      trustedProxyCidrs: [],
      isTrustedProxy: undefined,
      hops: 1,
      headersPriority: DEFAULT_CLIENT_IP_HEADERS,
      denyPrivateIpsFromHeaders: true,
    };
  }

  return {
    mode: next.mode ?? 'strict',
    trustedProxyCidrs: normalizeCidrs(next.trustedProxyCidrs),
    isTrustedProxy: next.isTrustedProxy,
    hops: normalizeHops(next.hops),
    headersPriority: normalizeHeaderList(next.headersPriority),
    denyPrivateIpsFromHeaders: next.denyPrivateIpsFromHeaders ?? true,
  };
}

function normalizeHeaderList(headers: string[] | undefined): string[] {
  const source = headers && headers.length > 0 ? headers : DEFAULT_CLIENT_IP_HEADERS;
  const unique = new Set<string>();
  for (const header of source) {
    const normalized = header.trim().toLowerCase();
    if (normalized) {
      unique.add(normalized);
    }
  }
  return Array.from(unique);
}

function normalizeCidrs(cidrs: string | string[] | undefined): string[] {
  if (!cidrs) {
    return [];
  }

  const values = Array.isArray(cidrs) ? cidrs : [cidrs];
  return values
    .flatMap((value) => value.split(','))
    .map((cidr) => cidr.trim())
    .filter((cidr) => Boolean(cidr));
}

function normalizeHops(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 1;
  }

  return Math.max(0, Math.floor(value));
}

function normalizeDurationSec(value: number | string | undefined, fallbackSec: number): number {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.max(1, Math.floor(value));
  }

  if (typeof value !== 'string') {
    return fallbackSec;
  }

  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    return fallbackSec;
  }

  const numeric = Number(trimmed);
  if (Number.isFinite(numeric) && numeric > 0) {
    return Math.max(1, Math.floor(numeric));
  }

  const match = trimmed.match(/^(\d+)\s*(s|m|h|d)$/);
  if (!match) {
    return fallbackSec;
  }

  const amount = Number(match[1]);
  const unit = match[2];
  const factor =
    unit === 's' ? 1 :
    unit === 'm' ? 60 :
    unit === 'h' ? 3600 :
    86400;

  return Math.max(1, amount * factor);
}

function normalizePositiveInt(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback;
  }

  return Math.max(1, Math.floor(value));
}

function hasValidEmailSmtp(
  smtp: EmailAlertOptions['smtp'] | undefined,
): smtp is NonNullable<EmailAlertOptions['smtp']> {
  if (!smtp) {
    return false;
  }

  if (
    !smtp.host ||
    !smtp.port ||
    !smtp.user ||
    !smtp.pass ||
    !smtp.from ||
    !Array.isArray(smtp.to) ||
    smtp.to.length === 0
  ) {
    return false;
  }

  return smtp.to.some((item) => Boolean(String(item).trim()));
}
