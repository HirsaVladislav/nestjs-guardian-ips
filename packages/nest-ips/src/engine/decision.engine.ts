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

export class DecisionEngine {
  constructor(private readonly options: IpsResolvedOptions) {}

  getProfile(path: string, explicit?: IpsProfileName): IpsProfileName {
    if (explicit) {
      return explicit;
    }
    if (path.startsWith('/auth/login') || path.startsWith('/login') || path.startsWith('/auth')) {
      return 'login';
    }
    if (path.startsWith('/admin')) {
      return 'admin';
    }
    if (path.startsWith('/public')) {
      return 'public';
    }
    return 'default';
  }

  getRateLimitKey(type: RateLimitKey, ctx: DecisionContext): string {
    if (type === 'ip') {
      return ctx.ip;
    }
    if (type === 'ip+path') {
      return `${ctx.ip}:${ctx.path}`;
    }
    if (type === 'ip+email') {
      return `${ctx.ip}:${ctx.email ?? ctx.username ?? '-'}`;
    }
    if (type === 'ip+id') {
      return `${ctx.ip}:${ctx.userId ?? '-'}`;
    }
    return `${ctx.ip}:${ctx.username ?? '-'}`;
  }

  profilePolicy(profile: IpsProfileName): ProfilePolicy {
    return this.options.profiles[profile] ?? this.options.profiles.default;
  }

  defaultBanTtl(profile: IpsProfileName): number {
    return this.profilePolicy(profile).banTtlSec ?? this.options.profiles.default.banTtlSec ?? 600;
  }

  fromRule(rule: Rule): DecisionResult {
    if (rule.action === 'block') {
      return {
        blocked: true,
        status: rule.block?.status ?? 403,
        message: rule.block?.message ?? 'Blocked by IPS rule',
        action: 'block',
        ruleId: rule.id,
        severity: rule.severity,
      };
    }

    if (rule.action === 'ban') {
      return {
        blocked: true,
        status: 403,
        message: 'Banned by IPS rule',
        action: 'ban',
        banTtlSec: rule.ban?.ttlSec,
        ruleId: rule.id,
        severity: rule.severity,
      };
    }

    if (rule.action === 'rateLimit') {
      return {
        blocked: true,
        status: 429,
        message: 'Rate limit exceeded by IPS rule',
        action: 'rateLimit',
        ruleId: rule.id,
        severity: rule.severity,
      };
    }

    if (rule.action === 'alert') {
      return {
        blocked: false,
        action: 'alert',
        ruleId: rule.id,
        severity: rule.severity,
      };
    }

    return { blocked: false };
  }

  alertEvent(
    ctx: DecisionContext,
    action: 'alert' | 'block' | 'rateLimit' | 'ban',
    message: string,
    details?: Partial<AlertEvent>,
  ): AlertEvent {
    return {
      ts: Date.now(),
      mode: this.options.mode,
      action,
      ip: ctx.ip,
      method: ctx.method,
      path: ctx.path,
      ua: ctx.ua,
      profile: ctx.profile,
      ruleId: details?.ruleId,
      severity: details?.severity,
      counts: details?.counts,
      message,
    };
  }

  sanitizeAlert(
    event: AlertEvent,
    include?: AlertIncludeField[],
  ): AlertEvent {
    const mandatory: Array<keyof AlertEvent> = ['ts', 'mode', 'action', 'ip', 'message'];
    const allowed = new Set<keyof AlertEvent>([...(include ?? this.options.privacy.include), ...mandatory]);
    const output: Partial<Record<keyof AlertEvent, AlertEvent[keyof AlertEvent]>> = {};
    for (const [k, v] of Object.entries(event) as Array<[keyof AlertEvent, AlertEvent[keyof AlertEvent]]>) {
      if (allowed.has(k)) {
        output[k] = v;
      }
    }

    return {
      ts: (output.ts as number) ?? event.ts,
      mode: (output.mode as AlertEvent['mode']) ?? event.mode,
      action: (output.action as AlertEvent['action']) ?? event.action,
      ip: (output.ip as string) ?? event.ip,
      message: (output.message as string) ?? event.message,
      method: output.method as string | undefined,
      path: output.path as string | undefined,
      ua: output.ua as string | undefined,
      profile: output.profile as string | undefined,
      ruleId: output.ruleId as string | undefined,
      severity: output.severity as string | undefined,
      counts: output.counts as Record<string, number> | undefined,
    };
  }
}
