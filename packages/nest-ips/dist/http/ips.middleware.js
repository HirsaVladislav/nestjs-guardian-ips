"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIpsMiddleware = createIpsMiddleware;
const runtime_registry_1 = require("../module/runtime.registry");
const headers_1 = require("./headers");
/**
 * Creates HTTP middleware that performs early IPS checks before Nest guards/controllers.
 * Applies baseline rate-limit headers and may short-circuit with `403`/`429`.
 */
function createIpsMiddleware() {
    return async (req, res, next) => {
        const runtime = (0, runtime_registry_1.getIpsRuntime)();
        if (!runtime) {
            next();
            return;
        }
        try {
            const decision = await runtime.middlewareCheck(req);
            const baselineHeaders = runtime.getRateLimitHeaders(req);
            if (baselineHeaders) {
                (0, headers_1.applyHeaders)(res, baselineHeaders);
            }
            if (decision?.blocked) {
                writeErrorResponse(res, decision.status, decision.message, decision.headers);
                return;
            }
            next();
        }
        catch (error) {
            next(error);
        }
    };
}
function writeErrorResponse(res, status, message, headers) {
    const response = {
        statusCode: status,
        message,
    };
    if (headers) {
        (0, headers_1.applyHeaders)(res, headers);
    }
    if (typeof res.status === 'function') {
        const chain = res.status(status);
        if (chain && typeof chain.json === 'function') {
            chain.json(response);
            return;
        }
    }
    if (typeof res.writeHead === 'function') {
        res.writeHead(status, {
            'content-type': 'application/json',
        });
    }
    if (typeof res.end === 'function') {
        res.end(JSON.stringify(response));
    }
}
