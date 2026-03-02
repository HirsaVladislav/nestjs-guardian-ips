"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_PROFILES = exports.DEFAULT_CHEAP_SIGNATURE_PATTERNS = exports.DEFAULT_CLIENT_IP_HEADERS = exports.DEFAULT_MEMORY_CAP_BYTES = void 0;
exports.resolveIpsOptions = resolveIpsOptions;
const node_https_1 = require("node:https");
/** Default memory cap for built-in `MemoryStore` (500 MB). */
exports.DEFAULT_MEMORY_CAP_BYTES = 500 * 1024 * 1024;
/** Default header priority order used for client IP extraction. */
exports.DEFAULT_CLIENT_IP_HEADERS = [
    'cf-connecting-ip',
    'true-client-ip',
    'fastly-client-ip',
    'x-forwarded-for',
    'forwarded',
    'x-real-ip',
];
/** Default cheap-signature path fragments used by middleware prefilter. */
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
/** Default profile policies applied when user config omits profile overrides. */
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
/** Validates and normalizes user config into runtime-ready options. */
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
    const rateLimitReport = resolveRateLimitReportOptions(input.alerts?.rateLimitReport);
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
function resolveEnabled(explicit, hasParams) {
    if (typeof explicit === 'boolean') {
        return explicit;
    }
    return hasParams;
}
function resolveRateLimitReportOptions(input) {
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
function resolveRateLimitReportIpIntelOptions(input) {
    if (!input) {
        return undefined;
    }
    const enabled = input.enabled ?? true;
    const resolver = input.resolver ?? resolveDefaultIpIntelResolver();
    if (enabled && typeof resolver !== 'function') {
        throw new Error('[nest-ips] alerts.rateLimitReport.ipIntel.resolver is required when ipIntel is enabled (or set IP_INTEL_TOKEN for default resolver)');
    }
    return {
        enabled,
        resolver: typeof resolver === 'function' ? resolver : undefined,
        timeoutMs: normalizePositiveInt(input.timeoutMs, 1500),
        cacheTtlSec: normalizePositiveInt(input.cacheTtlSec, 3600),
        maxCacheSize: normalizePositiveInt(input.maxCacheSize, 5000),
    };
}
function resolveDefaultIpIntelResolver() {
    const token = String(process.env.IP_INTEL_TOKEN ?? '').trim();
    if (token) {
        return (ip, context) => defaultIpInfoResolver(ip, token, context?.signal);
    }
    return undefined;
}
async function defaultIpInfoResolver(ip, token, signal) {
    const url = `https://api.ipinfo.io/lookup/${encodeURIComponent(ip)}?token=${encodeURIComponent(token)}`;
    const payload = await fetchJson(url, signal);
    if (!payload) {
        return null;
    }
    const anonymous = asRecord(payload.anonymous) ?? asRecord(payload.privacy);
    const asnMeta = asRecord(payload.as);
    const result = {
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
function fetchJson(urlValue, signal) {
    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) {
                return;
            }
            settled = true;
            resolve(value);
        };
        const url = new URL(urlValue);
        const req = (0, node_https_1.request)({
            method: 'GET',
            hostname: url.hostname,
            path: `${url.pathname}${url.search}`,
            port: url.port || 443,
        }, (res) => {
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
                }
                catch {
                    finish(null);
                }
            });
        });
        if (signal) {
            if (signal.aborted) {
                req.destroy();
                finish(null);
                return;
            }
            const onAbort = () => {
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
function asRecord(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return null;
    }
    return input;
}
function toText(value) {
    if (typeof value !== 'string') {
        return undefined;
    }
    const next = value.trim();
    return next ? next : undefined;
}
function toBoolean(value) {
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
function toNumber(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }
    if (typeof value !== 'string') {
        return undefined;
    }
    const parsed = Number(value.trim());
    return Number.isFinite(parsed) ? parsed : undefined;
}
function hasAnyIntelValue(input) {
    return Boolean(input.provider ||
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
        input.connectionType);
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
function normalizeDurationSec(value, fallbackSec) {
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
    const factor = unit === 's' ? 1 :
        unit === 'm' ? 60 :
            unit === 'h' ? 3600 :
                86400;
    return Math.max(1, amount * factor);
}
function normalizePositiveInt(value, fallback) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return fallback;
    }
    return Math.max(1, Math.floor(value));
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
