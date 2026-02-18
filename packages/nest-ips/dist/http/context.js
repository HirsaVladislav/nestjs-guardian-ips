"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setIpsContext = setIpsContext;
exports.getIpsContext = getIpsContext;
exports.ensureIpsContext = ensureIpsContext;
const IPS_HTTP_CONTEXT_KEY = Symbol.for('nest-ips:http-context');
function setIpsContext(req, ctx) {
    req[IPS_HTTP_CONTEXT_KEY] = ctx;
}
function getIpsContext(req) {
    return req[IPS_HTTP_CONTEXT_KEY];
}
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
