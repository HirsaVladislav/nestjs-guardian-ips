"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpsRuntime = void 0;
const node_crypto_1 = require("node:crypto");
const alerter_interface_1 = require("../alerts/alerter.interface");
const alert_throttle_1 = require("../alerts/alert.throttle");
const email_smtp_1 = require("../alerts/email.smtp");
const slack_webhook_1 = require("../alerts/slack.webhook");
const behavior_detectors_1 = require("../engine/behavior.detectors");
const decision_engine_1 = require("../engine/decision.engine");
const rule_engine_1 = require("../engine/rule.engine");
const options_1 = require("./options");
const memory_store_1 = require("../store/memory.store");
const redis_store_1 = require("../store/redis.store");
const ip_1 = require("../utils/ip");
const logger_1 = require("../utils/logger");
const context_1 = require("../http/context");
/** Core IPS/IDS runtime orchestrating stores, rules, behavior detectors and alert channels. */
class IpsRuntime {
    /** Creates runtime and resolves normalized options, store, rules and alert transports. */
    constructor(input = {}) {
        this.rateLimitReportRows = new Map();
        this.rateLimitReportWindowStartedAtMs = Date.now();
        this.rateLimitReportTotal = 0;
        this.rateLimitReportTimer = null;
        this.rateLimitReportFlushing = false;
        this.rateLimitReportEvictedGroups = 0;
        this.rateLimitReportEvictedEvents = 0;
        this.options = (0, options_1.resolveIpsOptions)(input);
        this.logger = this.options.logger ?? new logger_1.IpsLogger();
        this.store = this.resolveStore(this.options);
        this.ruleEngine = new rule_engine_1.RuleEngine(this.options, this.logger);
        this.decisionEngine = new decision_engine_1.DecisionEngine(this.options);
        this.behavior = new behavior_detectors_1.BehaviorDetectors(this.store);
        this.throttle = new alert_throttle_1.AlertThrottle(this.store);
        this.alerter = this.resolveAlerter();
    }
    /** Returns normalized runtime options (useful for diagnostics and tests). */
    getOptions() {
        return this.options;
    }
    /** Initializes store connectivity and starts periodic rate-limit summary timer if enabled. */
    async startup() {
        if (typeof this.store.ready === 'function') {
            await this.store.ready();
        }
        this.startRateLimitReportTimer();
    }
    /** Stops timers, flushes pending summaries and closes the configured store. */
    async shutdown() {
        if (this.rateLimitReportTimer) {
            clearInterval(this.rateLimitReportTimer);
            this.rateLimitReportTimer = null;
        }
        await this.flushRateLimitReport('shutdown');
        if (typeof this.store.close === 'function') {
            await this.store.close();
        }
    }
    /** Returns rate-limit headers for current request context, if a rate-limit snapshot exists. */
    getRateLimitHeaders(req) {
        const rateLimit = (0, context_1.getIpsContext)(req)?.rateLimit;
        if (!rateLimit) {
            return null;
        }
        return this.buildRateLimitHeaders(rateLimit, false);
    }
    /** Builds or updates per-request IPS context (IP, path, profile, identity fields, request id). */
    contextFor(req, profileOverride) {
        const existing = (0, context_1.ensureIpsContext)(req);
        const ip = (0, ip_1.extractClientIp)(req, this.options);
        const path = (0, ip_1.extractPath)(req);
        const method = (0, ip_1.extractMethod)(req);
        const ua = (0, ip_1.getHeader)(req, 'user-agent') ?? 'unknown';
        const requestId = (0, ip_1.getHeader)(req, 'x-request-id') ?? (0, node_crypto_1.randomUUID)();
        const userId = this.extractUserId(req);
        const email = this.extractEmail(req);
        const username = this.extractUsername(req);
        const inferredProfile = this.decisionEngine.getProfile(path);
        const profile = profileOverride ?? (existing.profile !== 'default' ? existing.profile : inferredProfile);
        const next = {
            ...existing,
            ip,
            path,
            method,
            ua,
            requestId,
            userId,
            email,
            username,
            profile,
        };
        (0, context_1.setIpsContext)(req, next);
        return next;
    }
    /** Runs early middleware checks (ban status, global middleware rate-limit, cheap signatures). */
    async middlewareCheck(req) {
        const ctx = this.contextFor(req);
        if (this.options.mode === 'IPS' && (await this.isBanned(ctx.ip))) {
            this.logDetection('banned-ip-blocked', ctx, { source: 'middleware' });
            return {
                blocked: true,
                status: 403,
                message: 'Forbidden',
            };
        }
        const defaultProfile = this.options.profiles.default;
        const defaultRateLimit = defaultProfile.rateLimit;
        if (defaultRateLimit) {
            const exceeded = await this.enforceRateLimit('counter:mw:global', defaultRateLimit, ctx);
            if (exceeded) {
                await this.react(ctx, {
                    blocked: true,
                    status: exceeded.status,
                    message: exceeded.message,
                    action: 'rateLimit',
                }, 'middleware-rate-limit');
                if (this.options.mode === 'IPS') {
                    return exceeded;
                }
            }
        }
        if (this.options.cheapSignatures.enabled) {
            const loweredPath = ctx.path.toLowerCase();
            const blocked = this.options.cheapSignatures.patterns.some((pattern) => loweredPath.includes(pattern.toLowerCase()));
            if (blocked) {
                await this.react(ctx, {
                    blocked: true,
                    status: 403,
                    message: 'Forbidden by IPS signature',
                    action: 'block',
                    severity: 'high',
                }, 'cheap-signature');
                if (this.options.mode === 'IPS') {
                    return { blocked: true, status: 403, message: 'Forbidden' };
                }
            }
        }
        return null;
    }
    /** Runs guard-stage checks (CIDR policy, profile rate-limit, stuffing, rules). */
    async guardCheck(req, profileOverride, bypass, tags = []) {
        const ctx = this.contextFor(req, profileOverride);
        ctx.tags = tags;
        if (bypass) {
            return null;
        }
        if (this.options.mode === 'IPS' && (await this.isBanned(ctx.ip))) {
            this.logDetection('banned-ip-blocked', ctx, { source: 'guard' });
            return {
                blocked: true,
                status: 403,
                message: 'Forbidden',
            };
        }
        const policy = this.decisionEngine.profilePolicy(ctx.profile);
        const cidrDecision = this.checkCidrs(ctx, policy);
        if (cidrDecision) {
            await this.react(ctx, { blocked: true, status: 403, message: cidrDecision, action: 'block' }, 'admin-cidr');
            if (this.options.mode === 'IPS') {
                return { blocked: true, status: 403, message: 'Forbidden' };
            }
        }
        if (policy.rateLimit) {
            const exceeded = await this.enforceRateLimit(`counter:guard:${ctx.profile}`, policy.rateLimit, ctx);
            if (exceeded) {
                await this.react(ctx, { blocked: true, status: exceeded.status, message: exceeded.message, action: 'rateLimit' }, 'profile-rate-limit');
                if (this.options.mode === 'IPS') {
                    return exceeded;
                }
            }
        }
        const stuffingSignals = await this.behavior.recordStuffing(ctx.ip, ctx.username, policy);
        await this.reactToSignals(ctx, stuffingSignals, policy);
        const rulesDecision = await this.applyRules(req, ctx);
        if (rulesDecision && this.options.mode === 'IPS') {
            return rulesDecision;
        }
        return null;
    }
    /** Records request-start behavior counters (burst detection) before controller handler execution. */
    async onBeforeHandler(req) {
        const ctx = this.contextFor(req);
        const policy = this.decisionEngine.profilePolicy(ctx.profile);
        const signals = await this.behavior.recordRequest(ctx.ip, policy);
        await this.reactToSignals(ctx, signals, policy);
    }
    /** Records handler error/response status for behavior detectors (401/403/404/429 spikes). */
    async onError(req, status) {
        const ctx = this.contextFor(req);
        const policy = this.decisionEngine.profilePolicy(ctx.profile);
        const signals = await this.behavior.recordStatus(ctx.ip, status, policy);
        await this.reactToSignals(ctx, signals, policy);
    }
    /** Records unmatched-route events for route-not-found spike detection. */
    async onRouteNotFound(req) {
        const ctx = this.contextFor(req);
        const policy = this.decisionEngine.profilePolicy(ctx.profile);
        const signals = await this.behavior.recordRouteNotFound(ctx.ip, this.options.notFound.windowSec, this.options.notFound.max);
        await this.reactToSignals(ctx, signals, policy);
    }
    async applyRules(req, ctx) {
        const matchCtx = {
            ip: ctx.ip,
            path: ctx.path,
            ua: ctx.ua,
            method: ctx.method,
            profile: ctx.profile,
            headers: req.headers ?? {},
            query: req.query ?? {},
            body: req.body,
        };
        const rules = this.ruleEngine.match(matchCtx);
        for (const rule of rules) {
            const decision = await this.evaluateRule(rule, ctx);
            if (decision) {
                return decision;
            }
        }
        return null;
    }
    async evaluateRule(rule, ctx) {
        const base = this.decisionEngine.fromRule(rule);
        if (rule.score && rule.score > 0) {
            const scoreKey = `counter:score:${ctx.ip}`;
            const prev = Number((await this.store.get(scoreKey)) ?? '0');
            const score = prev + rule.score;
            await this.store.set(scoreKey, String(score), 300);
            if (score >= this.options.scoreThreshold) {
                const ttl = rule.ban?.ttlSec ?? this.decisionEngine.defaultBanTtl(ctx.profile);
                await this.banIp(ctx.ip, ttl, `Score threshold reached (${score})`);
                this.logDetection('score-threshold-reached', ctx, {
                    ruleId: rule.id,
                    severity: rule.severity,
                    score,
                    threshold: this.options.scoreThreshold,
                });
                await this.sendAlert(this.decisionEngine.alertEvent(ctx, this.options.mode === 'IPS' ? 'ban' : 'alert', `Score threshold reached (${score})`, {
                    ruleId: rule.id,
                    severity: rule.severity,
                    counts: { score },
                }), rule.id, ctx.ip, rule.alert?.throttleSec, rule.alert?.include);
                if (this.options.mode === 'IPS') {
                    return { blocked: true, status: 403, message: 'Forbidden' };
                }
            }
        }
        if (rule.action === 'log') {
            this.logDetection('rule-log', ctx, { ruleId: rule.id, severity: rule.severity });
            return null;
        }
        if (rule.action === 'alert') {
            this.logDetection('rule-alert', ctx, { ruleId: rule.id, severity: rule.severity });
            await this.sendAlert(this.decisionEngine.alertEvent(ctx, 'alert', `Rule matched: ${rule.id}`, {
                ruleId: rule.id,
                severity: rule.severity,
            }), rule.id, ctx.ip, rule.alert?.throttleSec, rule.alert?.include);
            return null;
        }
        if (rule.action === 'rateLimit') {
            if (!rule.rateLimit) {
                return null;
            }
            const limit = await this.enforceRateLimit(`counter:rule:${rule.id}`, rule.rateLimit, ctx);
            if (!limit) {
                return null;
            }
            await this.react(ctx, { ...base, blocked: true, status: limit.status, message: limit.message }, rule.id, rule.alert?.throttleSec, rule.alert?.include);
            if (this.options.mode === 'IPS') {
                return limit;
            }
            return null;
        }
        if (rule.action === 'ban') {
            if (this.options.mode === 'IPS') {
                const ttl = rule.ban?.ttlSec ?? this.decisionEngine.defaultBanTtl(ctx.profile);
                await this.banIp(ctx.ip, ttl, `Rule ban: ${rule.id}`);
                await this.react(ctx, { ...base, blocked: true, status: 403, message: 'Forbidden', action: 'ban' }, rule.id, rule.alert?.throttleSec, rule.alert?.include);
                return { blocked: true, status: 403, message: 'Forbidden' };
            }
            await this.react(ctx, { ...base, blocked: false, action: 'alert', message: `IDS detected ban rule: ${rule.id}` }, rule.id, rule.alert?.throttleSec, rule.alert?.include);
            return null;
        }
        if (rule.action === 'block') {
            await this.react(ctx, { ...base, blocked: true, action: 'block' }, rule.id, rule.alert?.throttleSec, rule.alert?.include);
            if (this.options.mode === 'IPS') {
                return {
                    blocked: true,
                    status: base.status ?? 403,
                    message: base.message ?? 'Forbidden',
                };
            }
        }
        return null;
    }
    async reactToSignals(ctx, signals, policy) {
        for (const signal of signals) {
            this.logDetection('behavior-signal', ctx, {
                signalId: signal.id,
                severity: signal.severity,
                message: signal.message,
                counts: signal.counts,
            });
            if (this.options.mode === 'IPS') {
                const ttl = policy.banTtlSec ?? this.options.profiles.default.banTtlSec ?? 600;
                await this.banIp(ctx.ip, ttl, signal.message);
            }
            await this.sendAlert(this.decisionEngine.alertEvent(ctx, this.options.mode === 'IPS' ? 'ban' : 'alert', signal.message, {
                ruleId: signal.id,
                severity: signal.severity,
                counts: signal.counts,
            }), signal.id, ctx.ip, this.defaultAlertThrottleSec());
        }
    }
    async react(ctx, decision, ruleId, throttleSec, include) {
        if (!decision.action) {
            return;
        }
        this.logDetection('decision', ctx, {
            action: decision.action,
            ruleId,
            status: decision.status,
            blocked: decision.blocked,
            severity: decision.severity,
            message: decision.message,
            counts: decision.counts,
        });
        const suppressImmediate = this.collectRateLimitReport(ctx, decision, ruleId);
        if (suppressImmediate) {
            return;
        }
        await this.sendAlert(this.decisionEngine.alertEvent(ctx, this.options.mode === 'IPS' ? decision.action : 'alert', decision.message ?? 'IPS event', {
            ruleId,
            severity: decision.severity,
            counts: decision.counts,
        }), ruleId, ctx.ip, throttleSec, include);
    }
    async sendAlert(event, ruleId, ip, throttleSec, include) {
        if (!this.alerter) {
            return;
        }
        const effectiveThrottle = throttleSec ?? this.defaultAlertThrottleSec();
        const send = await this.throttle.shouldSend(ruleId, ip, effectiveThrottle);
        if (!send) {
            this.logDetection('alert-throttled', { ip }, { ruleId, throttleSec: effectiveThrottle });
            return;
        }
        try {
            await this.alerter.send(this.decisionEngine.sanitizeAlert(event, include));
            this.logDetection('alert-sent', { ip }, { ruleId, action: event.action });
        }
        catch (error) {
            this.logDetection('alert-failed', { ip }, {
                ruleId,
                action: event.action,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    async enforceRateLimit(prefix, policy, ctx) {
        const keyPart = this.decisionEngine.getRateLimitKey(policy.key, ctx);
        const key = `${prefix}:${keyPart}`;
        const count = await this.store.incr(key, policy.windowSec);
        const nowSec = Math.floor(Date.now() / 1000);
        const resetAtSec = Math.floor(nowSec / policy.windowSec) * policy.windowSec + policy.windowSec;
        const resetAfterSec = Math.max(1, resetAtSec - nowSec);
        const rateLimit = {
            limit: policy.max,
            remaining: Math.max(0, policy.max - count),
            windowSec: policy.windowSec,
            resetAtSec,
            resetAfterSec,
        };
        ctx.rateLimit = rateLimit;
        if (count <= policy.max) {
            return null;
        }
        const profilePolicy = this.decisionEngine.profilePolicy(ctx.profile);
        const signals = await this.behavior.recordStatus(ctx.ip, 429, profilePolicy);
        await this.reactToSignals(ctx, signals, profilePolicy);
        return {
            blocked: true,
            status: 429,
            message: 'Too Many Requests',
            headers: this.buildRateLimitHeaders(rateLimit, true),
        };
    }
    buildRateLimitHeaders(rateLimit, blocked) {
        const headers = {
            'RateLimit-Limit': String(rateLimit.limit),
            'RateLimit-Remaining': String(rateLimit.remaining),
            'RateLimit-Reset': String(rateLimit.resetAfterSec),
            'RateLimit-Policy': `${rateLimit.limit};w=${rateLimit.windowSec}`,
            'X-RateLimit-Limit': String(rateLimit.limit),
            'X-RateLimit-Remaining': String(rateLimit.remaining),
            'X-RateLimit-Reset': String(rateLimit.resetAtSec),
        };
        if (blocked || rateLimit.remaining === 0) {
            headers['Retry-After'] = String(rateLimit.resetAfterSec);
        }
        return headers;
    }
    checkCidrs(ctx, policy) {
        if (ctx.profile !== 'admin') {
            return null;
        }
        if (policy.denyCidrs && policy.denyCidrs.some((cidr) => this.ipInCidr(ctx.ip, cidr))) {
            return 'IP is denied';
        }
        if (policy.allowCidrs && policy.allowCidrs.length > 0) {
            const allowed = policy.allowCidrs.some((cidr) => this.ipInCidr(ctx.ip, cidr));
            if (!allowed) {
                return 'IP is not in allowlist';
            }
        }
        return null;
    }
    ipInCidr(ip, cidr) {
        return (0, ip_1.isIpInCidr)(ip, cidr);
    }
    async isBanned(ip) {
        const value = await this.store.get(this.banKey(ip));
        return Boolean(value);
    }
    async banIp(ip, ttlSec, reason) {
        await this.store.set(this.banKey(ip), reason, ttlSec);
        this.logDetection('ip-banned', { ip }, { ttlSec, reason });
    }
    banKey(ip) {
        return `ban:${ip}`;
    }
    defaultAlertThrottleSec() {
        const values = [];
        if (this.options.alerts.slack?.enabled) {
            values.push(this.options.alerts.slack.throttleSec ?? 120);
        }
        if (this.options.alerts.email?.enabled) {
            values.push(this.options.alerts.email.throttleSec ?? 300);
        }
        if (values.length === 0) {
            return 120;
        }
        return Math.min(...values);
    }
    startRateLimitReportTimer() {
        const config = this.rateLimitReportConfig();
        if (!config?.enabled || !this.alerter) {
            return;
        }
        const periodMs = Math.max(1000, (config.periodSec ?? 1800) * 1000);
        this.rateLimitReportWindowStartedAtMs = Date.now();
        this.rateLimitReportTimer = setInterval(() => {
            void this.flushRateLimitReport('interval');
        }, periodMs);
        this.rateLimitReportTimer.unref?.();
    }
    collectRateLimitReport(ctx, decision, ruleId) {
        const config = this.rateLimitReportConfig();
        if (!config?.enabled || !this.alerter || decision.action !== 'rateLimit') {
            return false;
        }
        const key = `${ruleId}|${ctx.ip}|${ctx.method}|${ctx.path}|${ctx.profile}`;
        const current = this.rateLimitReportRows.get(key);
        if (current) {
            current.count += 1;
        }
        else {
            if (this.rateLimitReportRows.size >= config.maxGroups) {
                const oldestKey = this.rateLimitReportRows.keys().next().value;
                if (typeof oldestKey === 'string') {
                    const oldest = this.rateLimitReportRows.get(oldestKey);
                    if (oldest) {
                        this.rateLimitReportEvictedGroups += 1;
                        this.rateLimitReportEvictedEvents += oldest.count;
                    }
                    this.rateLimitReportRows.delete(oldestKey);
                }
            }
            this.rateLimitReportRows.set(key, {
                ruleId,
                ip: ctx.ip,
                method: ctx.method,
                path: ctx.path,
                profile: ctx.profile,
                count: 1,
            });
        }
        this.rateLimitReportTotal += 1;
        return config.suppressImmediate;
    }
    async flushRateLimitReport(trigger) {
        if (this.rateLimitReportFlushing) {
            return;
        }
        const config = this.rateLimitReportConfig();
        if (!config?.enabled || !this.alerter) {
            this.resetRateLimitReportWindow();
            return;
        }
        if (this.rateLimitReportTotal === 0 || this.rateLimitReportRows.size === 0) {
            this.resetRateLimitReportWindow();
            return;
        }
        this.rateLimitReportFlushing = true;
        try {
            const now = Date.now();
            const rows = Array.from(this.rateLimitReportRows.values())
                .sort((a, b) => b.count - a.count)
                .slice(0, config.maxItems ?? 50);
            const omitted = Math.max(0, this.rateLimitReportRows.size - rows.length);
            const windowStartedAt = this.rateLimitReportWindowStartedAtMs;
            const periodSec = config.periodSec;
            const lines = rows.map((row, index) => `${index + 1}. count=${row.count} ip=${row.ip} ${row.method} ${row.path} rule=${row.ruleId} profile=${row.profile}`);
            if (omitted > 0) {
                lines.push(`... omitted ${omitted} more groups`);
            }
            if (this.rateLimitReportEvictedGroups > 0) {
                lines.push(`... evicted oldest groups due to maxGroups=${config.maxGroups}: groups=${this.rateLimitReportEvictedGroups}, events=${this.rateLimitReportEvictedEvents}`);
            }
            const message = [
                `Rate-limit summary (${trigger})`,
                `windowStart=${new Date(windowStartedAt).toISOString()}`,
                `windowEnd=${new Date(now).toISOString()}`,
                `periodSec=${periodSec}`,
                `totalEvents=${this.rateLimitReportTotal}`,
                `uniqueGroups=${this.rateLimitReportRows.size}`,
                ...lines,
            ].join('\n');
            const event = {
                ts: now,
                mode: this.options.mode,
                action: 'alert',
                ip: '*',
                method: 'MULTI',
                path: '*',
                profile: 'summary',
                ruleId: 'rateLimit-summary',
                severity: 'medium',
                counts: {
                    rateLimitEvents: this.rateLimitReportTotal,
                    uniqueGroups: this.rateLimitReportRows.size,
                    evictedGroups: this.rateLimitReportEvictedGroups,
                    evictedEvents: this.rateLimitReportEvictedEvents,
                    periodSec,
                },
                message,
            };
            await this.alerter.send(this.decisionEngine.sanitizeAlert(event));
            this.logDetection('rate-limit-report-sent', { ip: '*' }, {
                trigger,
                totalEvents: this.rateLimitReportTotal,
                uniqueGroups: this.rateLimitReportRows.size,
                evictedGroups: this.rateLimitReportEvictedGroups,
                evictedEvents: this.rateLimitReportEvictedEvents,
                periodSec,
                maxGroups: config.maxGroups,
            });
        }
        catch (error) {
            this.logDetection('rate-limit-report-failed', { ip: '*' }, {
                trigger,
                error: error instanceof Error ? error.message : String(error),
            });
        }
        finally {
            this.resetRateLimitReportWindow();
            this.rateLimitReportFlushing = false;
        }
    }
    resetRateLimitReportWindow() {
        this.rateLimitReportRows.clear();
        this.rateLimitReportTotal = 0;
        this.rateLimitReportEvictedGroups = 0;
        this.rateLimitReportEvictedEvents = 0;
        this.rateLimitReportWindowStartedAtMs = Date.now();
    }
    rateLimitReportConfig() {
        return this.options.alerts.rateLimitReport;
    }
    resolveStore(options) {
        if (this.isStore(options.store)) {
            return options.store;
        }
        if (options.store.instance) {
            return options.store.instance;
        }
        const type = options.store.type ?? 'memory';
        const maxBytes = options.store.maxBytes ?? options.memoryCapBytes;
        const redisOptions = options.store.redis;
        const redisUrl = redisOptions?.url ?? process.env.REDIS_URL;
        if (type === 'redis') {
            if (!redisUrl) {
                this.printRedError('store.type=redis requires redis.url or REDIS_URL');
                throw new Error('[nest-ips] store.type=redis requires redis.url or REDIS_URL');
            }
            return new redis_store_1.RedisStore({
                url: redisUrl,
                keyPrefix: redisOptions?.keyPrefix,
                connectTimeoutMs: redisOptions?.connectTimeoutMs,
                connectionRetries: redisOptions?.connectionRetries,
                retryDelayMs: redisOptions?.retryDelayMs,
                strict: true,
                fallbackMaxBytes: maxBytes,
            });
        }
        if (type === 'auto' && redisUrl) {
            return new redis_store_1.RedisStore({
                url: redisUrl,
                keyPrefix: redisOptions?.keyPrefix,
                connectTimeoutMs: redisOptions?.connectTimeoutMs,
                connectionRetries: redisOptions?.connectionRetries,
                retryDelayMs: redisOptions?.retryDelayMs,
                strict: false,
                fallbackMaxBytes: maxBytes,
            });
        }
        return new memory_store_1.MemoryStore({
            maxBytes,
        });
    }
    resolveAlerter() {
        const channels = [];
        if (this.options.alerts.slack?.enabled) {
            channels.push(new slack_webhook_1.SlackWebhookAlerter({
                webhookUrl: this.options.alerts.slack.webhookUrl,
                template: this.options.alerts.slack.template,
                fields: this.options.alerts.slack.fields,
                payloadTemplate: this.options.alerts.slack.payloadTemplate,
                payloadIncludeText: this.options.alerts.slack.payloadIncludeText,
            }));
        }
        if (this.options.alerts.email?.enabled) {
            channels.push(new email_smtp_1.EmailSmtpAlerter({
                host: this.options.alerts.email.smtp.host,
                port: this.options.alerts.email.smtp.port,
                user: this.options.alerts.email.smtp.user,
                pass: this.options.alerts.email.smtp.pass,
                from: this.options.alerts.email.smtp.from,
                to: this.options.alerts.email.smtp.to,
                secure: this.options.alerts.email.smtp.secure,
                subjectTemplate: this.options.alerts.email.subjectTemplate,
                textTemplate: this.options.alerts.email.textTemplate,
                fields: this.options.alerts.email.fields,
            }));
        }
        if (channels.length === 0) {
            return null;
        }
        return new alerter_interface_1.MultiAlerter(channels);
    }
    isStore(value) {
        if (!value || typeof value !== 'object') {
            return false;
        }
        const maybeStore = value;
        return (typeof maybeStore.get === 'function' &&
            typeof maybeStore.set === 'function' &&
            typeof maybeStore.del === 'function' &&
            typeof maybeStore.incr === 'function' &&
            typeof maybeStore.sadd === 'function');
    }
    printRedError(message) {
        // eslint-disable-next-line no-console
        console.error(`\x1b[31m[nest-ips] ${message}\x1b[0m`);
    }
    logDetection(event, ctx, meta) {
        if (!this.options.logging) {
            return;
        }
        const payload = {
            event,
        };
        if (ctx?.requestId) {
            payload.requestId = ctx.requestId;
        }
        if (ctx?.ip) {
            payload.ip = ctx.ip;
        }
        if (ctx?.method) {
            payload.method = ctx.method;
        }
        if (ctx?.path) {
            payload.path = ctx.path;
        }
        if (ctx?.profile) {
            payload.profile = ctx.profile;
        }
        if (ctx?.userId) {
            payload.userId = ctx.userId;
        }
        if (ctx?.email) {
            payload.email = ctx.email;
        }
        if (ctx?.username) {
            payload.username = ctx.username;
        }
        if (meta) {
            Object.assign(payload, meta);
        }
        this.logger.info('Detection', payload);
    }
    extractEmail(req) {
        const body = this.toRecord(req.body);
        const query = this.toRecord(req.query);
        const user = this.toRecord(req.user);
        const auth = this.toRecord(req.auth);
        const headers = this.toRecord(req.headers);
        const candidate = user?.email ??
            user?.mail ??
            auth?.email ??
            auth?.mail ??
            body?.email ??
            body?.mail ??
            query?.email ??
            query?.mail ??
            headers?.['x-user-email'];
        return this.normalizeString(candidate);
    }
    extractUserId(req) {
        const body = this.toRecord(req.body);
        const query = this.toRecord(req.query);
        const user = this.toRecord(req.user);
        const auth = this.toRecord(req.auth);
        const headers = this.toRecord(req.headers);
        const candidate = user?.id ??
            user?.userId ??
            user?.sub ??
            auth?.id ??
            auth?.userId ??
            auth?.sub ??
            body?.id ??
            body?.userId ??
            query?.id ??
            query?.userId ??
            headers?.['x-user-id'];
        return this.normalizeString(candidate);
    }
    extractUsername(req) {
        const body = this.toRecord(req.body);
        const query = this.toRecord(req.query);
        const user = this.toRecord(req.user);
        const auth = this.toRecord(req.auth);
        const candidate = user?.username ??
            user?.login ??
            auth?.username ??
            auth?.login ??
            body?.username ??
            body?.email ??
            body?.login ??
            query?.username ??
            query?.email ??
            query?.login;
        return this.normalizeString(candidate);
    }
    toRecord(value) {
        if (!value || typeof value !== 'object') {
            return undefined;
        }
        return value;
    }
    normalizeString(value) {
        if (value === undefined || value === null) {
            return undefined;
        }
        if (Array.isArray(value)) {
            for (const item of value) {
                const normalizedItem = this.normalizeString(item);
                if (normalizedItem) {
                    return normalizedItem;
                }
            }
            return undefined;
        }
        const normalized = String(value).trim();
        return normalized || undefined;
    }
}
exports.IpsRuntime = IpsRuntime;
