"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchesWhen = matchesWhen;
exports.matchesAll = matchesAll;
const ip_1 = require("../utils/ip");
const normalize_1 = require("./normalize");
function matchesWhen(rule, ctx) {
    if (!rule.when) {
        return true;
    }
    if (rule.when.methods && !rule.when.methods.map((m) => m.toUpperCase()).includes(ctx.method.toUpperCase())) {
        return false;
    }
    if (rule.when.profile && rule.when.profile !== ctx.profile) {
        return false;
    }
    if (!rule.when.path) {
        return true;
    }
    const path = ctx.path;
    if (rule.when.path.equals && rule.when.path.equals !== path) {
        return false;
    }
    if (rule.when.path.prefix && !path.startsWith(rule.when.path.prefix)) {
        return false;
    }
    if (rule.when.path.regex) {
        const regex = safeRegex(rule.when.path.regex);
        if (!regex || !regex.test(path)) {
            return false;
        }
    }
    return true;
}
function matchesAll(rule, ctx) {
    const path = (0, normalize_1.applyNormalization)(ctx.path, rule.normalize);
    const ua = (0, normalize_1.applyNormalization)(ctx.ua, rule.normalize);
    for (const clause of rule.match) {
        if (clause.field === 'path' || clause.field === 'ua') {
            const value = clause.field === 'path' ? path : ua;
            if ('contains' in clause && !value.includes(clause.contains)) {
                return false;
            }
            if ('regex' in clause) {
                const regex = safeRegex(clause.regex);
                if (!regex || !regex.test(value)) {
                    return false;
                }
            }
            continue;
        }
        if (clause.field === 'ip') {
            if (!(0, ip_1.isIpInCidr)(ctx.ip, clause.cidr)) {
                return false;
            }
            continue;
        }
        if (clause.field === 'headers') {
            const raw = findHeader(ctx.headers, clause.header);
            const value = stringify(raw);
            if (clause.contains && !value.includes(clause.contains)) {
                return false;
            }
            if (clause.regex) {
                const regex = safeRegex(clause.regex);
                if (!regex || !regex.test(value)) {
                    return false;
                }
            }
            continue;
        }
        if (clause.field === 'query') {
            const value = stringify(ctx.query[clause.key]);
            if (clause.contains && !value.includes(clause.contains)) {
                return false;
            }
            if (clause.regex) {
                const regex = safeRegex(clause.regex);
                if (!regex || !regex.test(value)) {
                    return false;
                }
            }
            continue;
        }
        if (clause.field === 'body') {
            const value = stringify(ctx.body);
            if (clause.maxBytes && Buffer.byteLength(value) > clause.maxBytes) {
                return false;
            }
            if (clause.contains && !value.includes(clause.contains)) {
                return false;
            }
            if (clause.regex) {
                const regex = safeRegex(clause.regex);
                if (!regex || !regex.test(value)) {
                    return false;
                }
            }
        }
    }
    return true;
}
function safeRegex(pattern) {
    try {
        return new RegExp(pattern, 'i');
    }
    catch {
        return null;
    }
}
function stringify(value) {
    if (typeof value === 'string') {
        return value;
    }
    if (Array.isArray(value)) {
        return value.map((x) => stringify(x)).join(',');
    }
    if (value === null || value === undefined) {
        return '';
    }
    if (typeof value === 'object') {
        try {
            return JSON.stringify(value);
        }
        catch {
            return '[object]';
        }
    }
    return String(value);
}
function findHeader(headers, name) {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
    if (!key) {
        return undefined;
    }
    return headers[key];
}
