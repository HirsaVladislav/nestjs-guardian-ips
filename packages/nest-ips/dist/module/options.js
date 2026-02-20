"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_PROFILES = exports.DEFAULT_CHEAP_SIGNATURE_PATTERNS = exports.DEFAULT_CLIENT_IP_HEADERS = exports.DEFAULT_MEMORY_CAP_BYTES = void 0;
exports.resolveIpsOptions = resolveIpsOptions;
exports.DEFAULT_MEMORY_CAP_BYTES = 500 * 1024 * 1024;
exports.DEFAULT_CLIENT_IP_HEADERS = [
    'cf-connecting-ip',
    'true-client-ip',
    'fastly-client-ip',
    'x-forwarded-for',
    'forwarded',
    'x-real-ip',
];
exports.DEFAULT_CHEAP_SIGNATURE_PATTERNS = [
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
exports.DEFAULT_PROFILES = {
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
function resolveIpsOptions(input = {}) {
    const slack = input.alerts?.slack;
    const slackConfigured = Boolean(slack);
    const slackEnabled = resolveEnabled(slack?.enabled, slackConfigured);
    if (slackConfigured && slackEnabled && !slack?.webhookUrl?.trim()) {
        throw new Error('[nest-ips] alerts.slack.webhookUrl is required when alerts.slack is configured');
    }
    const email = input.alerts?.email;
    const emailConfigured = Boolean(email);
    const emailHasSmtp = hasValidEmailSmtp(email?.smtp);
    const emailEnabled = resolveEnabled(email?.enabled, emailConfigured);
    if (emailConfigured && emailEnabled && !emailHasSmtp) {
        throw new Error('[nest-ips] alerts.email.smtp.{host,port,user,pass,from,to[]} is required when alerts.email is configured');
    }
    const cheapPatterns = input.cheapSignatures?.patterns ?? exports.DEFAULT_CHEAP_SIGNATURE_PATTERNS;
    const cheapSignaturesEnabled = input.cheapSignatures?.enabled ?? true;
    const clientIp = resolveClientIpOptions(input);
    return {
        mode: input.mode ?? 'IPS',
        clientIp,
        logging: input.logging ?? true,
        logger: input.logger,
        store: input.store ?? { type: 'memory', maxBytes: input.memoryCapBytes ?? exports.DEFAULT_MEMORY_CAP_BYTES },
        memoryCapBytes: input.memoryCapBytes ?? exports.DEFAULT_MEMORY_CAP_BYTES,
        rules: input.rules,
        profiles: {
            default: { ...exports.DEFAULT_PROFILES.default, ...input.profiles?.default },
            public: { ...exports.DEFAULT_PROFILES.public, ...input.profiles?.public },
            login: { ...exports.DEFAULT_PROFILES.login, ...input.profiles?.login },
            admin: { ...exports.DEFAULT_PROFILES.admin, ...input.profiles?.admin },
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
function resolveEnabled(explicit, hasParams) {
    if (typeof explicit === 'boolean') {
        return explicit;
    }
    return hasParams;
}
function resolveClientIpOptions(input) {
    const next = input.clientIp;
    if (!next) {
        return {
            mode: 'strict',
            trustedProxyCidrs: [],
            isTrustedProxy: undefined,
            hops: 1,
            headersPriority: exports.DEFAULT_CLIENT_IP_HEADERS,
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
function normalizeHeaderList(headers) {
    const source = headers && headers.length > 0 ? headers : exports.DEFAULT_CLIENT_IP_HEADERS;
    const unique = new Set();
    for (const header of source) {
        const normalized = header.trim().toLowerCase();
        if (normalized) {
            unique.add(normalized);
        }
    }
    return Array.from(unique);
}
function normalizeCidrs(cidrs) {
    if (!cidrs) {
        return [];
    }
    const values = Array.isArray(cidrs) ? cidrs : [cidrs];
    return values
        .flatMap((value) => value.split(','))
        .map((cidr) => cidr.trim())
        .filter((cidr) => Boolean(cidr));
}
function normalizeHops(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return 1;
    }
    return Math.max(0, Math.floor(value));
}
function hasValidEmailSmtp(smtp) {
    if (!smtp) {
        return false;
    }
    if (!smtp.host ||
        !smtp.port ||
        !smtp.user ||
        !smtp.pass ||
        !smtp.from ||
        !Array.isArray(smtp.to) ||
        smtp.to.length === 0) {
        return false;
    }
    return smtp.to.some((item) => Boolean(String(item).trim()));
}
