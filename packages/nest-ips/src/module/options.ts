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
  trustedProxyCidrs?: string[];
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

export const DEFAULT_MEMORY_CAP_BYTES = 500 * 1024 * 1024;
export const DEFAULT_CLIENT_IP_HEADERS = [
  'cf-connecting-ip',
  'true-client-ip',
  'fastly-client-ip',
  'x-forwarded-for',
  'forwarded',
  'x-real-ip',
];
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

function normalizeCidrs(cidrs: string[] | undefined): string[] {
  if (!cidrs || cidrs.length === 0) {
    return [];
  }

  return cidrs.map((cidr) => cidr.trim()).filter((cidr) => Boolean(cidr));
}

function normalizeHops(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 1;
  }

  return Math.max(0, Math.floor(value));
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
