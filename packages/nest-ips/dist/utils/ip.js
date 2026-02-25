"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getHeader = getHeader;
exports.extractClientIp = extractClientIp;
exports.extractPath = extractPath;
exports.extractMethod = extractMethod;
exports.stripIpv6Prefix = stripIpv6Prefix;
exports.isIpInCidr = isIpInCidr;
const node_net_1 = require("node:net");
/** Reads a request header by name using case-insensitive lookup. */
function getHeader(req, name) {
    const headers = req.headers ?? {};
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
    if (!key) {
        return undefined;
    }
    const value = headers[key];
    if (Array.isArray(value)) {
        return value[0];
    }
    return value;
}
/** Resolves client IP according to configured trust model (`strict` or `hops`). */
function extractClientIp(req, options) {
    const remoteIp = extractRemoteIp(req);
    const config = options.clientIp;
    if (config.mode === 'hops') {
        const byHops = extractClientIpByHops(req, remoteIp, config);
        if (byHops) {
            return byHops;
        }
    }
    else if (remoteIp && isTrustedProxyRemote(remoteIp, config)) {
        const byTrustedHeaders = extractFromHeadersPriority(req, config);
        if (byTrustedHeaders) {
            return byTrustedHeaders;
        }
    }
    if (remoteIp) {
        return remoteIp;
    }
    return '0.0.0.0';
}
/** Extracts request path without query string. */
function extractPath(req) {
    const candidate = req.originalUrl ?? req.url ?? req.path ?? '/';
    const noQuery = candidate.split('?')[0] ?? '/';
    return noQuery || '/';
}
/** Extracts uppercase HTTP method with `GET` fallback. */
function extractMethod(req) {
    return (req.method ?? 'GET').toUpperCase();
}
/** Converts IPv4-mapped IPv6 format (`::ffff:x.x.x.x`) to plain IPv4 string. */
function stripIpv6Prefix(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.slice(7);
    }
    return ip;
}
/** Checks whether an IP belongs to CIDR (or equals a plain IP string). */
function isIpInCidr(ip, cidr) {
    const normalizedIp = normalizeIpCandidate(ip);
    if (!normalizedIp) {
        return false;
    }
    const normalizedCidr = cidr.trim();
    if (!normalizedCidr.includes('/')) {
        const target = normalizeIpCandidate(normalizedCidr);
        return Boolean(target && target === normalizedIp);
    }
    const [baseIp, maskPart] = normalizedCidr.split('/');
    const normalizedBase = normalizeIpCandidate(baseIp);
    const maskBits = Number(maskPart);
    if (!normalizedBase || !Number.isInteger(maskBits)) {
        return false;
    }
    const family = (0, node_net_1.isIP)(normalizedBase);
    if (!family || (0, node_net_1.isIP)(normalizedIp) !== family) {
        return false;
    }
    try {
        const blockList = new node_net_1.BlockList();
        blockList.addSubnet(normalizedBase, maskBits, family === 6 ? 'ipv6' : 'ipv4');
        return blockList.check(normalizedIp, family === 6 ? 'ipv6' : 'ipv4');
    }
    catch {
        return false;
    }
}
function extractRemoteIp(req) {
    const candidates = [req.socket?.remoteAddress, req.connection?.remoteAddress, req.ip, ...(req.ips ?? [])];
    for (const candidate of candidates) {
        const normalized = normalizeIpCandidate(candidate);
        if (normalized) {
            return normalized;
        }
    }
    return undefined;
}
function extractClientIpByHops(req, remoteIp, config) {
    const chain = extractForwardChain(req, config.headersPriority);
    if (chain.length > 0) {
        const fullChain = remoteIp ? [...chain, remoteIp] : [...chain];
        let index = fullChain.length - 1 - config.hops;
        if (index < 0) {
            index = 0;
        }
        for (let i = index; i >= 0; i -= 1) {
            const candidate = fullChain[i];
            const fromHeaders = i < chain.length;
            if (fromHeaders && config.denyPrivateIpsFromHeaders && isPrivateOrLocalIp(candidate)) {
                continue;
            }
            return candidate;
        }
    }
    return extractFromHeadersPriority(req, config);
}
function extractForwardChain(req, headersPriority) {
    for (const header of headersPriority) {
        if (header === 'x-forwarded-for') {
            const value = getHeader(req, header);
            if (!value) {
                continue;
            }
            const parsed = parseXForwardedFor(value);
            if (parsed.length > 0) {
                return parsed;
            }
            continue;
        }
        if (header === 'forwarded') {
            const value = getHeader(req, header);
            if (!value) {
                continue;
            }
            const parsed = parseForwardedFor(value);
            if (parsed.length > 0) {
                return parsed;
            }
        }
    }
    return [];
}
function extractFromHeadersPriority(req, config) {
    for (const header of config.headersPriority) {
        const candidates = extractHeaderCandidates(req, header);
        for (const candidate of candidates) {
            if (config.denyPrivateIpsFromHeaders && isPrivateOrLocalIp(candidate)) {
                continue;
            }
            return candidate;
        }
    }
    return undefined;
}
function extractHeaderCandidates(req, header) {
    const value = getHeader(req, header);
    if (!value) {
        return [];
    }
    if (header === 'x-forwarded-for') {
        return parseXForwardedFor(value);
    }
    if (header === 'forwarded') {
        return parseForwardedFor(value);
    }
    return value
        .split(',')
        .map((candidate) => normalizeIpCandidate(candidate))
        .filter((candidate) => Boolean(candidate));
}
function parseXForwardedFor(value) {
    return value
        .split(',')
        .map((part) => normalizeIpCandidate(part))
        .filter((candidate) => Boolean(candidate));
}
function parseForwardedFor(value) {
    const out = [];
    const entries = value.split(',');
    for (const entry of entries) {
        const params = entry.split(';');
        for (const param of params) {
            const [rawKey, ...rawValueParts] = param.split('=');
            if (!rawKey || rawKey.trim().toLowerCase() !== 'for') {
                continue;
            }
            const rawValue = rawValueParts.join('=').trim();
            const candidate = normalizeIpCandidate(rawValue);
            if (candidate) {
                out.push(candidate);
            }
            break;
        }
    }
    return out;
}
function normalizeIpCandidate(value) {
    if (!value) {
        return undefined;
    }
    let candidate = value.trim();
    if (!candidate) {
        return undefined;
    }
    if (candidate.startsWith('"') && candidate.endsWith('"')) {
        candidate = candidate.slice(1, -1).trim();
    }
    if (!candidate || candidate.toLowerCase() === 'unknown' || candidate === '_hidden') {
        return undefined;
    }
    if (candidate.startsWith('[')) {
        const bracketEnd = candidate.indexOf(']');
        if (bracketEnd > 1) {
            candidate = candidate.slice(1, bracketEnd);
        }
    }
    else if (candidate.includes(':') && (0, node_net_1.isIP)(candidate) !== 6) {
        const maybePort = candidate.match(/^(.+):(\d+)$/);
        if (maybePort && (0, node_net_1.isIP)(maybePort[1]) === 4) {
            candidate = maybePort[1];
        }
    }
    candidate = stripIpv6Prefix(candidate);
    if ((0, node_net_1.isIP)(candidate) === 0) {
        return undefined;
    }
    return candidate;
}
function isTrustedProxyRemote(remoteIp, config) {
    if (typeof config.isTrustedProxy === 'function') {
        try {
            if (config.isTrustedProxy(remoteIp)) {
                return true;
            }
        }
        catch {
            // ignore user callback errors
        }
    }
    return config.trustedProxyCidrs.some((cidr) => isIpInCidr(remoteIp, cidr));
}
function isPrivateOrLocalIp(ip) {
    const family = (0, node_net_1.isIP)(ip);
    if (family === 4) {
        return (isIpInCidr(ip, '10.0.0.0/8') ||
            isIpInCidr(ip, '172.16.0.0/12') ||
            isIpInCidr(ip, '192.168.0.0/16') ||
            isIpInCidr(ip, '127.0.0.0/8') ||
            isIpInCidr(ip, '169.254.0.0/16') ||
            isIpInCidr(ip, '100.64.0.0/10') ||
            isIpInCidr(ip, '0.0.0.0/8'));
    }
    if (family === 6) {
        const normalized = ip.toLowerCase();
        return (normalized === '::1' ||
            normalized === '::' ||
            normalized.startsWith('fc') ||
            normalized.startsWith('fd') ||
            normalized.startsWith('fe8') ||
            normalized.startsWith('fe9') ||
            normalized.startsWith('fea') ||
            normalized.startsWith('feb'));
    }
    return false;
}
