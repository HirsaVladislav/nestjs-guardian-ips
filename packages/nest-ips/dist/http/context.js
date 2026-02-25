"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setIpsContext = setIpsContext;
exports.getIpsContext = getIpsContext;
exports.ensureIpsContext = ensureIpsContext;
const IPS_HTTP_CONTEXT_KEY = Symbol.for('nest-ips:http-context');
/** Stores IPS context on request object. */
function setIpsContext(req, ctx) {
    req[IPS_HTTP_CONTEXT_KEY] = ctx;
}
/** Reads IPS context from request object if already initialized. */
function getIpsContext(req) {
    return req[IPS_HTTP_CONTEXT_KEY];
}
/** Returns existing IPS context or initializes a safe fallback context. */
function ensureIpsContext(req) {
    const existing = getIpsContext(req);
    if (existing) {
        return existing;
    }
    const fallback = {
        ip: '0.0.0.0',
        ua: 'unknown',
        method: 'GET',
        path: '/',
        requestId: 'n/a',
        profile: 'default',
    };
    setIpsContext(req, fallback);
    return fallback;
}
