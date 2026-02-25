"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.applyHeaders = applyHeaders;
/** Applies response headers across common response adapters (`setHeader`, `header`, `set`). */
function applyHeaders(res, headers) {
    for (const [key, value] of Object.entries(headers)) {
        if (typeof res.setHeader === 'function') {
            res.setHeader(key, value);
            continue;
        }
        if (typeof res.header === 'function') {
            res.header(key, value);
            continue;
        }
        if (typeof res.set === 'function') {
            res.set(key, value);
        }
    }
}
