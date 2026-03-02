import { request } from 'node:https';
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
   * Enables periodic rate-limit summary collection and sending.
   * If omitted, defaults to `true` when `rateLimitReport` object is provided.
   */
  enabled?: boolean;
  /**
   * Aggregation scope:
   * - `rateLimit` (default): aggregate only `rateLimit` decisions
   * - `all`: aggregate all alert-producing IPS events (rate-limit, behavior signals, block/ban/alert decisions)
   */
  scope?: 'rateLimit' | 'all';
  /**
   * Report period. Supports seconds (`30`), or duration strings like `30m`, `1h`, `1d`.
   * Invalid values fall back to 30 minutes.
   */
  period?: number | string;
  /**
   * If `true`, suppresses immediate alerts for events included by `scope` and sends only periodic summaries.
   * Events not included by `scope` are unaffected.
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
  /**
   * Optional IP intelligence enrichment for summary rows.
   * Adds context such as VPN/proxy/TOR/hosting/risk/geo/ASN to grouped IP entries.
   * This helps distinguish likely bot/infrastructure traffic from regular user traffic.
   */
  ipIntel?: IpsRateLimitReportIpIntelOptions;
}

/**
 * Normalized IP intelligence result returned by `ipIntel.resolver`.
 * Keep only fields you need; missing fields are simply not shown in reports.
 */
export interface IpsIpIntelResult {
  provider?: string;
  isVpn?: boolean;
  isProxy?: boolean;
  isTor?: boolean;
  isHosting?: boolean;
  riskScore?: number;
  countryCode?: string;
  countryName?: string;
  region?: string;
  city?: string;
  asn?: string;
  org?: string;
  isp?: string;
  connectionType?: string;
}

/**
 * IP intelligence settings for periodic summary reports.
 * Use this when you need additional signal about offending IPs (VPN/proxy/data-center/risk).
 */
export interface IpsRateLimitReportIpIntelOptions {
  /**
   * Enables IP enrichment for summary rows.
   * If omitted, defaults to `true` when `ipIntel` object is provided.
   */
  enabled?: boolean;
  /**
   * Custom async resolver that returns VPN/proxy/hosting intelligence for an IP.
   * Required when `enabled` is `true`, unless built-in default resolver is used via `IP_INTEL_TOKEN`.
   * Optional `context.signal` is provided so resolvers can cancel outgoing requests on timeout.
   */
  resolver?: (
    ip: string,
    context?: { signal?: AbortSignal },
  ) => Promise<IpsIpIntelResult | null> | IpsIpIntelResult | null;
  /**
   * Maximum time (ms) allowed for one resolver call before timeout.
   * Default: `1500`.
   */
  timeoutMs?: number;
  /**
   * Cache TTL for resolved IP intelligence records.
   * Default: `3600`.
   */
  cacheTtlSec?: number;
  /**
   * Maximum number of cached IP intelligence entries in memory.
   * When full, the oldest cache entries are evicted first (FIFO).
   * Default: `5000`.
   */
  maxCacheSize?: number;
}

/** Normalized internal IP enrichment settings for report rows. */
export interface IpsResolvedRateLimitReportIpIntelOptions {
  enabled: boolean;
  resolver?: (
    ip: string,
    context?: { signal?: AbortSignal },
  ) => Promise<IpsIpIntelResult | null> | IpsIpIntelResult | null;
  timeoutMs: number;
  cacheTtlSec: number;
  maxCacheSize: number;
}

/** Normalized internal rate-limit report configuration. */
export interface IpsResolvedRateLimitReportOptions {
  enabled: boolean;
  scope: 'rateLimit' | 'all';
  periodSec: number;
  suppressImmediate: boolean;
  maxItems: number;
  maxGroups: number;
  ipIntel?: IpsResolvedRateLimitReportIpIntelOptions;
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

  const enabled = input.enabled ?? true;
  const scope = input.scope === 'all' ? 'all' : 'rateLimit';
  const periodSec = normalizeDurationSec(input.period, 1800);
  const maxItems = normalizePositiveInt(input.maxItems, 50);
  const maxGroups = normalizePositiveInt(input.maxGroups, 2000);
  const ipIntel = resolveRateLimitReportIpIntelOptions(input.ipIntel);

  return {
    enabled,
    scope,
    suppressImmediate: input.suppressImmediate ?? true,
    maxItems,
    maxGroups,
    periodSec,
    ipIntel,
  };
}

function resolveRateLimitReportIpIntelOptions(
  input: IpsRateLimitReportIpIntelOptions | undefined,
): IpsResolvedRateLimitReportIpIntelOptions | undefined {
  if (!input) {
    return undefined;
  }

  const enabled = input.enabled ?? true;
  const resolver = input.resolver ?? resolveDefaultIpIntelResolver();
  if (enabled && typeof resolver !== 'function') {
    throw new Error(
      '[nest-ips] alerts.rateLimitReport.ipIntel.resolver is required when ipIntel is enabled (or set IP_INTEL_TOKEN for default resolver)',
    );
  }

  return {
    enabled,
    resolver: typeof resolver === 'function' ? resolver : undefined,
    timeoutMs: normalizePositiveInt(input.timeoutMs, 1500),
    cacheTtlSec: normalizePositiveInt(input.cacheTtlSec, 3600),
    maxCacheSize: normalizePositiveInt(input.maxCacheSize, 5000),
  };
}

function resolveDefaultIpIntelResolver():
  ((ip: string, context?: { signal?: AbortSignal }) => Promise<IpsIpIntelResult | null>) | undefined {
  const token = String(process.env.IP_INTEL_TOKEN ?? '').trim();
  if (token) {
    return (ip: string, context?: { signal?: AbortSignal }) => defaultIpInfoResolver(ip, token, context?.signal);
  }

  return undefined;
}

async function defaultIpInfoResolver(ip: string, token: string, signal?: AbortSignal): Promise<IpsIpIntelResult | null> {
  const url = `https://api.ipinfo.io/lookup/${encodeURIComponent(ip)}?token=${encodeURIComponent(token)}`;
  const payload = await fetchJson(url, signal);
  if (!payload) {
    return null;
  }

  const anonymous = asRecord(payload.anonymous) ?? asRecord(payload.privacy);
  const asnMeta = asRecord(payload.as);
  const result: IpsIpIntelResult = {
    provider: 'ipinfo',
    isVpn: toBoolean(anonymous?.is_vpn ?? anonymous?.vpn),
    isProxy: toBoolean(anonymous?.is_proxy ?? anonymous?.proxy),
    isTor: toBoolean(anonymous?.is_tor ?? anonymous?.tor),
    isHosting: toBoolean(payload.is_hosting ?? anonymous?.is_hosting ?? anonymous?.hosting),
    riskScore: toNumber(payload.risk_score ?? payload.fraud_score),
    countryCode: toText(payload.country_code ?? payload.country),
    countryName: toText(payload.country_name),
    region: toText(payload.region),
    city: toText(payload.city),
    asn: toText(asnMeta?.asn ?? payload.asn),
    org: toText(asnMeta?.name ?? payload.org),
    isp: toText(payload.isp),
    connectionType: toText(payload.connection_type),
  };

  return hasAnyIntelValue(result) ? result : null;
}

const MAX_IP_INTEL_RESPONSE_BYTES = 512 * 1024;

function fetchJson(urlValue: string, signal?: AbortSignal): Promise<Record<string, unknown> | null> {
  return new Promise<Record<string, unknown> | null>((resolve) => {
    let settled = false;
    const finish = (value: Record<string, unknown> | null): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(value);
    };

    const url = new URL(urlValue);
    const req = request(
      {
        method: 'GET',
        hostname: url.hostname,
        path: `${url.pathname}${url.search}`,
        port: url.port || 443,
      },
      (res) => {
        const status = res.statusCode ?? 500;
        let body = '';
        let bytes = 0;
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          bytes += Buffer.byteLength(chunk, 'utf8');
          if (bytes > MAX_IP_INTEL_RESPONSE_BYTES) {
            req.destroy(new Error(`[nest-ips] ipIntel response exceeds ${MAX_IP_INTEL_RESPONSE_BYTES} bytes`));
            finish(null);
            return;
          }
          body += chunk;
        });
        res.on('end', () => {
          if (status < 200 || status >= 300) {
            finish(null);
            return;
          }
          try {
            const parsed = JSON.parse(body);
            finish(asRecord(parsed));
          } catch {
            finish(null);
          }
        });
      },
    );

    if (signal) {
      if (signal.aborted) {
        req.destroy();
        finish(null);
        return;
      }

      const onAbort = (): void => {
        req.destroy();
        finish(null);
      };
      signal.addEventListener('abort', onAbort, { once: true });
      req.on('close', () => signal.removeEventListener('abort', onAbort));
    }

    req.on('error', () => finish(null));
    req.end();
  });
}

function asRecord(input: unknown): Record<string, unknown> | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return null;
  }

  return input as Record<string, unknown>;
}

function toText(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  const next = value.trim();
  return next ? next : undefined;
}

function toBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value !== 0;
  }
  if (typeof value !== 'string') {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') {
    return true;
  }
  if (normalized === 'false' || normalized === '0' || normalized === 'no') {
    return false;
  }
  return undefined;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== 'string') {
    return undefined;
  }

  const parsed = Number(value.trim());
  return Number.isFinite(parsed) ? parsed : undefined;
}

function hasAnyIntelValue(input: IpsIpIntelResult): boolean {
  return Boolean(
    input.provider ||
    typeof input.isVpn === 'boolean' ||
    typeof input.isProxy === 'boolean' ||
    typeof input.isTor === 'boolean' ||
    typeof input.isHosting === 'boolean' ||
    typeof input.riskScore === 'number' ||
    input.countryCode ||
    input.countryName ||
    input.region ||
    input.city ||
    input.asn ||
    input.org ||
    input.isp ||
    input.connectionType,
  );
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
