"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DecisionEngine = void 0;
/** Builds decisions, alert payloads and profile-specific derived values. */
class DecisionEngine {
    constructor(options) {
        this.options = options;
    }
    /** Resolves profile by explicit decorator override or path heuristics. */
    getProfile(path, explicit) {
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
    /** Builds storage key suffix for a configured rate-limit strategy. */
    getRateLimitKey(type, ctx) {
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
    /** Returns profile policy with fallback to `default`. */
    profilePolicy(profile) {
        return this.options.profiles[profile] ?? this.options.profiles.default;
    }
    /** Returns default ban TTL for profile with fallback chain. */
    defaultBanTtl(profile) {
        return this.profilePolicy(profile).banTtlSec ?? this.options.profiles.default.banTtlSec ?? 600;
    }
    /** Converts a matched rule action into a runtime decision template. */
    fromRule(rule) {
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
    /** Creates alert event payload from current decision context. */
    alertEvent(ctx, action, message, details) {
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
    /** Removes fields from alert event according to privacy/include rules. */
    sanitizeAlert(event, include) {
        const mandatory = ['ts', 'mode', 'action', 'ip', 'message'];
        const allowed = new Set([...(include ?? this.options.privacy.include), ...mandatory]);
        const output = {};
        for (const [k, v] of Object.entries(event)) {
            if (allowed.has(k)) {
                output[k] = v;
            }
        }
        return {
            ts: output.ts ?? event.ts,
            mode: output.mode ?? event.mode,
            action: output.action ?? event.action,
            ip: output.ip ?? event.ip,
            message: output.message ?? event.message,
            method: output.method,
            path: output.path,
            ua: output.ua,
            profile: output.profile,
            ruleId: output.ruleId,
            severity: output.severity,
            counts: output.counts,
        };
    }
}
exports.DecisionEngine = DecisionEngine;
